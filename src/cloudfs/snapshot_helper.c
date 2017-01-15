#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "cloudapi.h"
#include "cloudfs.h"
#include "dedup.h"
#include "openssl/sha.h"
#include "dedup_layer.c"
#include "../snapshot/snapshot-api.h"
#include <libtar.h>
#include <sys/time.h>

/* total number of snapshots created */
int snapshot_num = 0;

/* node structure for each snapshot */
struct snapshot_node {
    unsigned int timestamp; // because the microseconds returned by gettimeofday() is always less than one million
    int installed;
    struct snapshot_node *next;
};

/* store xattr of the proxy files in the snapshot */
struct snapshot_xattr {
    char path[MAX_PATH_LEN];
    struct stat filestat;
};

struct snapshot_node *head;

/*
 * check if there are snapshots installed when
 * trying to create a new snapshot
 */
int check_installed() {
    struct snapshot_node *ptr = head->next;
    while (ptr != NULL) {
        if (ptr->installed == 1) {
            return 1;
        }
        ptr = ptr->next;
    }
    return 0;
}

/* create the .snapshot file */
void create_snapshot_file() {
    char snapshot_path[MAX_PATH_LEN];
    strcpy(snapshot_path, state_.ssd_path);
    strcat(snapshot_path, ".snapshot");
    FILE *snapshot_file = fopen(snapshot_path, "w+");
    fclose(snapshot_file);
    head = (struct snapshot_node *) malloc(sizeof(struct snapshot_node));
    head->next = NULL;
}

/* restore the snapshot list */
void restore_snapshot_list() {
    // download the snapshot list backup file
    char fpath[MAX_PATH_LEN];
    strcpy(fpath, state_.ssd_path);
    strcat(fpath, ".snapshot_list");
    outfile = fopen(fpath, "w+");
    cloud_get_object("snapshot_list", "snapshot_list", get_buffer);
    fclose(outfile);

    // restore the snapshot list
    snapshot_num = 0;
    FILE *backup_file = fopen(fpath, "r");
    struct snapshot_node *tail = head;
    unsigned int timestamp;
    while (fread(&timestamp, sizeof(unsigned int), 1, backup_file) > 0) {
        struct snapshot_node *new_entry = (struct snapshot_node *) malloc(sizeof(struct snapshot_node));
        new_entry->timestamp = timestamp;
        new_entry->next = NULL;
        new_entry->installed = 0; // because at the time the snapshot was taken, there must be no snapshots installed
        tail->next = new_entry;
        tail = new_entry;
        snapshot_num++;
    }
    fclose(backup_file);
    truncate(fpath, 0);
    unlink(fpath);
}

/* backup hashtable when creating a snapshot */
void snapshot_backup_hashtable(char *timestamp) {
    char backup_path[MAX_PATH_LEN];
    strcpy(backup_path, state_.ssd_path);
    strcat(backup_path, str_seg_backup);

    FILE *hashtable_file = fopen(backup_path, "w+");
    struct segment *seg;
    for (seg = segments; seg != NULL; seg = (struct segment *) (seg->hh.next)) {
        seg->count++;
        fwrite(seg, sizeof(struct segment), 1, hashtable_file);
    }
    fclose(hashtable_file);

    struct stat filestat;
    lstat(backup_path, &filestat);
    infile = fopen(backup_path, "r");
    cloud_put_object("hashtable", timestamp, filestat.st_size, put_buffer);
    fclose(infile);
}

/* backup the xattr of the proxy files in the snapshot */
void backup_snapshot_xattr(const char *current_dir, FILE *xattr_file, const char *timestamp) {
    DIR *dir;
    struct dirent *de;
    if ((dir = opendir(current_dir)) == NULL) {
        return;
    }
    char fpath[MAX_PATH_LEN];
    while ((de = readdir(dir)) != NULL) {
        if (strstr(de->d_name, ".") != NULL)
            continue;
        if (strstr(de->d_name, "lost+found") != NULL)
            continue;
        if (de->d_type == DT_DIR) {
            char new_dir[MAX_PATH_LEN];
            strcpy(new_dir, current_dir);
            strcat(new_dir, de->d_name);
            strcat(new_dir, "/");
            backup_snapshot_xattr(new_dir, xattr_file, timestamp);
        } else {
            strcpy(fpath, current_dir);
            strcat(fpath, de->d_name);
            if (in_cloud(fpath)) {
                struct stat fstat;
                get_proxy_xattr(fpath, &fstat);
                struct snapshot_xattr entry;
                strcpy(entry.path, fpath);
                entry.filestat.st_size = fstat.st_size;
                entry.filestat.st_mtime = fstat.st_mtime;
                fwrite(&entry, sizeof(struct snapshot_xattr), 1, xattr_file);
            }
        }
    }
    closedir(dir);
}

/* send local files to cloud */
void snapshot_small_files(char *timestamp) {
    // compress all local files to one tar file
    char tar_path[MAX_PATH_LEN];
    strcpy(tar_path, "/tmp/");
    strcat(tar_path, timestamp);
    strcat(tar_path, ".tar");
    char save_dir[MAX_PATH_LEN] = ".";
    TAR *tar;
    tar_open(&tar, tar_path, NULL, O_WRONLY | O_CREAT, 0777, TAR_GNU);
    tar_append_tree(tar, state_.ssd_path, save_dir);
    tar_append_eof(tar);
    tar_close(tar);

    // send the tar file to the cloud
    infile = fopen(tar_path, "r");
    struct stat fstat;
    lstat(tar_path, &fstat);
    cloud_put_object("smallfiles", timestamp, fstat.st_size, put_buffer);
    fclose(infile);
    truncate(tar_path, 0);
    unlink(tar_path);
}

/* add a new snapshot to the snapshot list */
void add_snapshot(char *str_ts) {
    unsigned int timestamp = atoi(str_ts);
    struct snapshot_node *new_node = (struct snapshot_node *) malloc(sizeof(struct snapshot_node));
    new_node->timestamp = timestamp;
    new_node->installed = 0;
    new_node->next = head->next;
    head->next = new_node;
}

/* backup the snapshot list */
void backup_snapshot_list() {
    char fpath[MAX_PATH_LEN];
    strcpy(fpath, state_.ssd_path);
    strcat(fpath, ".snapshot_list");
    FILE *backup_file = fopen(fpath, "w+");
    struct snapshot_node *ptr = head->next;
    while (ptr != NULL) {
        fwrite(&(ptr->timestamp), sizeof(unsigned int), 1, backup_file);
        ptr = ptr->next;
    }
    fclose(backup_file);
    infile = fopen(fpath, "r");
    struct stat filestat;
    lstat(fpath, &filestat);
    cloud_put_object("snapshot_list", "snapshot_list", filestat.st_size, put_buffer);
    fclose(infile);
}

/* create a snapshot given the timestamp */
int create_snapshot(void *data) {
    if (snapshot_num >= CLOUDFS_MAX_NUM_SNAPSHOTS) {
        fprintf(logfile, "Error in creating a snapshot: Can't create more snapshots!\n");
        return -1;
    }
    if (check_installed()) {
        fprintf(logfile, "Error in creating a snapshot: There are snapshots installed!\n");
        return -1;
    }
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    unsigned int timestamp = tv.tv_usec;
    *((uint64_t *) data) = timestamp;
    char str_ts[8]; // because timestamp value is always less than one million
    sprintf(str_ts, "%u", timestamp);

    if (state_.cache_size) {
        clear_cache();
    }

    // backup hashtable
    snapshot_backup_hashtable(str_ts);

    // backup up proxy xattr of snapshot
    char xattr_file_path[MAX_PATH_LEN];
    strcpy(xattr_file_path, "/tmp/");
    strcat(xattr_file_path, str_ts);
    strcat(xattr_file_path, "_xattr");
    FILE *xattr_file = fopen(xattr_file_path, "w+");
    backup_snapshot_xattr(state_.ssd_path, xattr_file, str_ts);
    fclose(xattr_file);
    struct stat filestat;
    lstat(xattr_file_path, &filestat);
    infile = fopen(xattr_file_path, "r");
    cloud_put_object("snapshot_xattr", str_ts, filestat.st_size, put_buffer);
    fclose(infile);
    truncate(xattr_file_path, 0);
    unlink(xattr_file_path);

    // backup all small files
    snapshot_small_files(str_ts);

    add_snapshot(str_ts);
    snapshot_num++;
    backup_snapshot_list();
    return 0;
}

/* restore the hashtable of a given timestamp */
void snapshot_restore_hashtable(char *timestamp) {
    char backup_path[MAX_PATH_LEN];
    strcpy(backup_path, state_.ssd_path);
    strcat(backup_path, str_seg_backup);

    outfile = fopen(backup_path, "w+");
    cloud_get_object("hashtable", timestamp, get_buffer);
    fclose(outfile);

    struct segment *new_segments = NULL;

    FILE *hashtable_file = fopen(backup_path, "r");
    struct segment seg;
    while (fread(&seg, sizeof(struct segment), 1, hashtable_file) > 0) {
        struct segment *new_seg = (struct segment *) malloc(sizeof(struct segment));
        strcpy(new_seg->md5, seg.md5);
        new_seg->count = seg.count;
        HASH_ADD_STR(new_segments, md5, new_seg);
    }
    fclose(hashtable_file);

    struct segment *cur, *tmp;
    struct segment *s = NULL;
    HASH_ITER(hh, segments, cur, tmp) {
        s = NULL;
        HASH_FIND_STR(new_segments, cur->md5, s);
        if (s == NULL) {
            cloud_delete_object("bigfiles", cur->md5);
        }
        HASH_DEL(segments, cur);
        free(cur);
    }
    segments = new_segments;
}

/* set the xattr of the proxy files of the restored snapshot */
void set_restored_proxy(char *str_ts) {
    char xattr_path[MAX_PATH_LEN];
    strcpy(xattr_path, "/tmp/");
    strcat(xattr_path, str_ts);
    strcat(xattr_path, "_xattr");
    outfile = fopen(xattr_path, "w+");
    cloud_get_object("snapshot_xattr", str_ts, get_buffer);
    fclose(outfile);

    FILE *xattr_file = fopen(xattr_path, "r");
    struct snapshot_xattr entry;
    int size = sizeof(struct snapshot_xattr);
    while (fread(&entry, size, 1, xattr_file) > 0) {
        struct stat tmp_fstat;
        lstat(entry.path, &tmp_fstat);
        chmod(entry.path, 0777);
        set_proxy_xattr(entry.path, entry.filestat);
        char c = 't';
        lsetxattr(entry.path, "user.incloud", &c, sizeof(char), 0);
        chmod(entry.path, tmp_fstat.st_mode);
    }
    fclose(xattr_file);
    truncate(xattr_path, 0);
    unlink(xattr_path);
}

/* delete all files under ssd folder */
void delete_ssd_dir() {
    char command[MAX_PATH_LEN];
    strcpy(command, "rm -rf ");
    strcat(command, state_.ssd_path);
    strcat(command, "*");
    system(command);
}

/* delete all the related resources of snapshot at timestamp */
void delete_snapshot_resources(unsigned int timestamp) {
    char str_ts[8];
    sprintf(str_ts, "%u", timestamp);
    char hashtable_path[MAX_PATH_LEN];
    strcpy(hashtable_path, state_.ssd_path);
    strcat(hashtable_path, str_ts);
    strcat(hashtable_path, "_tmp");
    outfile = fopen(hashtable_path, "w+");
    cloud_get_object("hashtable", str_ts, get_buffer);
    fclose(outfile);

    // scan the segments of the deleted snapshot have referenced
    // reduce their counts by one
    FILE *hashtable_file = fopen(hashtable_path, "r");
    struct segment seg;
    int size = sizeof(struct segment);
    while (fread(&seg, size, 1, hashtable_file) > 0) {
        struct segment *s = NULL;
        HASH_FIND_STR(segments, seg.md5, s);
        if (s != NULL) {
            s->count--;
            if (s->count == 0) {
                cloud_delete_object("bigfiles", s->md5);
                HASH_DEL(segments, s);
                free(s);
            }
        }
    }
    fclose(hashtable_file);
    truncate(hashtable_path, 0);
    unlink(hashtable_path);

    // delete the related backup metadata in the cloud
    backup_snapshot_list();
    cloud_delete_object("smallfiles", str_ts);
    cloud_delete_object("snapshot_xattr", str_ts);
    cloud_delete_object("hashtable", str_ts);
}

/* delete a snapshot of a given timestamp */
int delete_snapshot(void *data) {
    unsigned int timestamp = *((unsigned int *) data);
    struct snapshot_node *pre = head;
    struct snapshot_node *cur = pre->next;
    while (cur != NULL) {
        if (cur->timestamp == timestamp) {
            if (cur->installed == 1) {
                fprintf(logfile, "Error in delete_snapshot: Cannot delete a installed snapshot!\n");
                return -1;
            } else {
                delete_snapshot_resources(timestamp);
                snapshot_num--;
                pre->next = cur->next;
                free(cur);
                return 0;
            }
        }
        pre = cur;
        cur = pre->next;
    }
    return -1;
}

/* restore snapshot to a given timestamp */
int restore_snapshot(void *data) {
    unsigned int timestamp = *((unsigned int *) data);
    struct snapshot_node *cur = head->next;
    // check if the snapshot exists
    while (cur != NULL) {
        if (cur->timestamp == timestamp) {
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        fprintf(logfile, "Error in restore_snapshot: Cannot find such snapshot!\n");
        return -1;
    }

    // uninstall all snapshots and delete snapshots following the restored one
    cur = head->next;
    while (cur != NULL) {
        if (cur->installed == 1) {
            cur->installed = 0;
        }
        if (cur->timestamp == timestamp) {
            cur = cur->next;
            break;
        } else {
            head->next = cur->next;
            delete_snapshot_resources(cur->timestamp);
            snapshot_num--;
            free(cur);
            cur = head->next;
        }
    }

    while (cur != NULL) {
        if (cur->installed == 1) {
            cur->installed = 0;
        }
        cur = cur->next;
    }

    delete_ssd_dir();

    char str_ts[8];
    sprintf(str_ts, "%u", timestamp);
    backup_snapshot_list();
    snapshot_restore_hashtable(str_ts);

    // download the snapshot
    char tar_path[MAX_PATH_LEN];
    strcpy(tar_path, "/tmp/");
    strcat(tar_path, str_ts);
    strcat(tar_path, ".tar");
    outfile = fopen(tar_path, "w+");
    cloud_get_object("smallfiles", str_ts, get_buffer);
    fclose(outfile);

    // extract the snapshot
    TAR *tar;
    tar_open(&tar, tar_path, NULL, O_RDONLY, 0, TAR_GNU);
    tar_extract_all(tar, state_.ssd_path);
    tar_close(tar);

    truncate(tar_path, 0);
    unlink(tar_path);

    // set the xattr of the proxy files
    set_restored_proxy(str_ts);

    return 0;
}

/* set the xattr of the proxy files in the installed snapshot */
void set_snapshot_xattr(char *str_ts) {
    char xattr_file_path[MAX_PATH_LEN];
    strcpy(xattr_file_path, "/tmp/");
    strcat(xattr_file_path, str_ts);
    strcat(xattr_file_path, "_xattr");
    outfile = fopen(xattr_file_path, "w+");
    cloud_get_object("snapshot_xattr", str_ts, get_buffer);
    fclose(outfile);

    unsigned long timestamp = atoi(str_ts);
    FILE *xattr_file = fopen(xattr_file_path, "r");
    struct snapshot_xattr entry;
    int size = sizeof(struct snapshot_xattr);
    while (fread(&entry, size, 1, xattr_file) > 0) {
        char proxy_path[MAX_PATH_LEN];
        strcpy(proxy_path, state_.ssd_path);
        strcat(proxy_path, "snapshot_");
        strcat(proxy_path, str_ts);
        strcat(proxy_path, "/");
        int len = strlen(state_.ssd_path);
        strcat(proxy_path, entry.path + len);

        set_proxy_xattr(proxy_path, entry.filestat);
        char c = 't';
        lsetxattr(proxy_path, "user.incloud", &c, sizeof(char), 0);
        lsetxattr(proxy_path, "user.snapshot", &c, sizeof(char), 0);
        lsetxattr(proxy_path, "user.timestamp", &timestamp, sizeof(unsigned int), 0);
    }
    fclose(xattr_file);
    truncate(xattr_file_path, 0);
    unlink(xattr_file_path);
}

/* install a snapshot of a given timestamp */
int install_snapshot(void *data) {
    unsigned int timestamp = *((unsigned int *) data);
    struct snapshot_node *cur = head->next;
    while (cur != NULL) {
        if (cur->timestamp == timestamp && cur->installed == 0) {
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        fprintf(logfile, "Error in install_snapshot: Cannot find such snapshot!\n");
        return -1;
    }
    cur->installed = 1;
    char str_ts[8];
    sprintf(str_ts, "%u", timestamp);

    // download the sanpshot
    char new_tar_path[MAX_PATH_LEN];
    strcpy(new_tar_path, "/tmp/");
    strcat(new_tar_path, str_ts);
    strcat(new_tar_path, ".tar");
    outfile = fopen(new_tar_path, "w+");
    cloud_get_object("smallfiles", str_ts, get_buffer);
    fclose(outfile);

    // extract the snapshot
    TAR *tar;
    char save_dir[MAX_PATH_LEN];
    strcpy(save_dir, state_.ssd_path);
    strcat(save_dir, "snapshot_");
    strcat(save_dir, str_ts);
    strcat(save_dir, "/");
    tar_open(&tar, new_tar_path, NULL, O_RDONLY, 0, TAR_GNU);
    tar_extract_all(tar, save_dir);
    tar_close(tar);
    truncate(new_tar_path, 0);
    unlink(new_tar_path);

    // set the proxy xattr of the installed snapshot
    set_snapshot_xattr(str_ts);

    // make the installed snapshot folder read-only
    char command[MAX_PATH_LEN];
    strcpy(command, "chmod 0444 ");
    strcat(command, save_dir);
    strcat(command, "*");
    system(command);

    return 0;
}

/* uninstall the snapshot of a given timestamp */
int uninstall_snapshot(void *data) {
    unsigned int timestamp = *((unsigned int *) data);
    struct snapshot_node *cur = head->next;
    while (cur != NULL) {
        if (cur->timestamp == timestamp && cur->installed == 1) {
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        fprintf(logfile, "Error in uninstall_snapshot: Cannot find such snapshot!\n");
        return -1;
    }
    cur->installed = 0;
    char str_ts[8];
    sprintf(str_ts, "%u", timestamp);
    char dir_path[MAX_PATH_LEN];
    strcpy(dir_path, state_.ssd_path);
    strcat(dir_path, "snapshot_");
    strcat(dir_path, str_ts);

    // delete the installed snapshot folder
    chmod(dir_path, 0777);
    char command[MAX_PATH_LEN];
    strcpy(command, "rm -rf ");
    strcat(command, dir_path);
    system(command);
    return 0;
}

/* list all the snapshots */
int list_snapshot(void *data) {
    int i = 0;
    struct snapshot_node *ptr = head->next;
    while (ptr != NULL) {
        ((uint64_t *) data)[i++] = ptr->timestamp;
        ptr = ptr->next;
    }
    int tmp = i;
    for (; i < CLOUDFS_MAX_NUM_SNAPSHOTS; i++) {
        ((uint64_t *) data)[i] = 0;
    }
    return 0;
}

/* ioctl calls that handle snapshot operations */
int cloudfs_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, void *data) {
    char snapshot_path[MAX_PATH_LEN] = "/.snapshot";
    if (strstr(path, snapshot_path) == NULL) {
        return -1;
    }
    int ret = 0;

    switch (cmd) {
        case CLOUDFS_SNAPSHOT:
            ret = create_snapshot(data);
            return ret;
        case CLOUDFS_RESTORE:
            ret = restore_snapshot(data);
            return ret;
        case CLOUDFS_DELETE:
            ret = delete_snapshot(data);
            return ret;
        case CLOUDFS_INSTALL_SNAPSHOT:
            ret = install_snapshot(data);
            return ret;
        case CLOUDFS_UNINSTALL_SNAPSHOT:
            ret = uninstall_snapshot(data);
            return ret;
        case CLOUDFS_SNAPSHOT_LIST:
            ret = list_snapshot(data);
            return ret;
        default:
            fprintf(logfile, "Error: invalid ioctl parameter!\n");
            return -1;
    }
}