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
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include "cloudapi.h"
#include "cloudfs.h"
#include "dedup.h"
#include "openssl/sha.h"
#include "snapshot_helper.c"

struct cloudfs_state state_;

/* get the full path of the file */
void cloudfs_get_fullpath(const char *path, char *fpath) {
    strcpy(fpath, state_.ssd_path);
    if (strstr(path, fpath) != NULL) {
        strcpy(fpath, path);
        return;
    }
    if (*path == '/') {
        strncat(fpath, path + 1, MAX_PATH_LEN - strlen(fpath));
    } else {
        strncat(fpath, path, MAX_PATH_LEN - strlen(fpath));
    }
}

/* move the file to cloud */
void move_to_cloud(const char *fpath, struct stat filestat) {
    unsigned char *s3_path = get_S3_path(fpath);
    int size = filestat.st_size;
    infile = fopen(fpath, "r");
    cloud_put_object("bigfiles", s3_path, size, put_buffer);
    fclose(infile);
    truncate(fpath, 0);
    set_proxy_xattr(fpath, filestat);
    lsetxattr(fpath, "user.s3path", s3_path, SHA_DIGEST_LENGTH * 2 + 1, 0);
}

/*
 * Initializes the FUSE file system (cloudfs) by checking if the mount points
 * are valid, and if all is well, it mounts the file system ready for usage.
 */
void *cloudfs_init(struct fuse_conn_info *conn UNUSED) {
    cloud_init(state_.hostname);
    cloud_create_bucket("bigfiles"); // storing segments
    cloud_create_bucket("smallfiles"); // storing tar of local files
    cloud_create_bucket("hashtable");// storing snapshot segments hashtable
    cloud_create_bucket("snapshot_list");// storing snapshots list
    cloud_create_bucket("snapshot_xattr");// storing proxy files xattr
    cloud_create_bucket("cache_list");// storing cache list
    if (!state_.no_dedup) {
        initialize_rabin();
        create_meta_dir();
        restore_hash_table();
    }
    create_snapshot_file();
    restore_snapshot_list();
    if (state_.cache_size) {
        create_cache_dir();
        restore_cache_list();
    }
    return NULL;
}

void cloudfs_destroy(void *data UNUSED) {
    if (!state_.no_dedup) {
        backup_hash_table();
        backup_snapshot_list();
    }
    if (state_.cache_size) {
        backup_cache_list();
    }
    cloud_destroy();
}

/* get the information about the a file */
int cloudfs_getattr(const char *path UNUSED, struct stat *statbuf UNUSED) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);
    int ret = 0;
    ret = stat(fpath, statbuf);
    if (ret != 0) {
        ret = cloudfs_error("Error in cloudfs_getattr");
    }

    if (in_cloud(fpath)) {
        get_proxy_xattr(fpath, statbuf);
    }
    return ret;
}

/* get the extended attributes of a file */
int cloudfs_getxattr(const char *path, const char *name, char *value, size_t size) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = lgetxattr(fpath, name, value, size);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_getxattr");
    }
    return ret;
}

/* set the extended attributes of a file */
int cloudfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = lsetxattr(fpath, name, value, size, flags);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_setxattr");
    }
    return ret;
}

/* create a directory */
int cloudfs_mkdir(const char *path, mode_t mode) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = mkdir(fpath, mode);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_mkdir");
    }
    return ret;
}

/* create a system node */
int cloudfs_mknod(const char *path, mode_t mode, dev_t dev) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    if (S_ISREG(mode)) {
        ret = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (ret >= 0) {
            ret = close(ret);
        }
    } else {
        if (S_ISFIFO(mode)) {
            ret = mkfifo(fpath, mode);
        } else {
            ret = mknod(fpath, mode, dev);
        }
    }
    return ret;
}

/* open a file */
int cloudfs_open(const char *path, struct fuse_file_info *fi) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    int fd;
    fd = open(fpath, fi->flags);
    if (fd < 0) {
        ret = cloudfs_error("Error in cloudfs_open");
        return ret;
    }

    if (in_cloud(fpath) && state_.no_dedup) {
        struct stat *filestat = (struct stat *) malloc(sizeof(struct stat));
        stat(fpath, filestat);
        chmod(fpath, 0777);
        outfile = fopen(fpath, "w");
        unsigned char *s3_path = get_S3_path(fpath);
        cloud_get_object("bigfiles", s3_path, get_buffer);
        fclose(outfile);
        chmod(fpath, filestat->st_mode);
    }

    fi->fh = fd;
    return ret;
}

/* read a file */
int cloudfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    if (in_cloud(fpath)) {
        if (state_.no_dedup) {
            ret = pread(fi->fh, buf, size, offset);
        } else {
            ret = read_segs_from_cloud(fpath, buf, size, offset);
        }
    } else {
        ret = pread(fi->fh, buf, size, offset);
    }
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_read!");
    }
    return ret;
}

/* write a file */
int cloudfs_write(const char *path, const char *buf, size_t size, off_t offset,
                  struct fuse_file_info *fi) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    if (state_.no_dedup) {
        ret = pwrite(fi->fh, buf, size, offset);
        if (ret < 0) {
            ret = cloudfs_error("Error in cloudfs_write");
            return ret;
        }
        char dirty = 't';
        lsetxattr(fpath, "user.dirty", &dirty, sizeof(char), 0);
    } else {
        if (in_cloud(fpath)) {
            off_t file_size;
            lgetxattr(fpath, "user.proxysize", &file_size, sizeof(off_t));
            if (offset == file_size) {
                ret = write_to_cloud_end(fpath, buf, size, file_size);
            } else if (offset == 0) {
                ret = write_to_cloud_head(fpath, buf, size);
            } else if (offset > 0 && offset < file_size) {
                ret = write_to_cloud_mid(fpath, buf, size, offset);
            } else {
                return -1;
            }
            cloud_file_reset(fpath);
        } else {
            ret = pwrite(fi->fh, buf, size, offset);
        }
        if (ret < 0) {
            ret = cloudfs_error("Error in cloudfs_write!");
        }
    }
    return ret;
}

/* close a file */
int cloudfs_release(const char *path, struct fuse_file_info *fi) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = close(fi->fh);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_release: close");
        return ret;
    }

    struct stat *filestat = (struct stat *) malloc(sizeof(struct stat));
    ret = stat(fpath, filestat);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_release: stat");
        return ret;
    }

    int need_truncate = 1;

    int size = filestat->st_size;
    if (in_cloud(fpath)) {
        if (state_.no_dedup) {
            char dirty = 'f';
            lgetxattr(fpath, "user.dirty", &dirty, sizeof(char));
            if (dirty == 't') {
                if (size > state_.threshold) {
                    move_to_cloud(path, *filestat);
                } else {
                    unsigned char s3_path[SHA_DIGEST_LENGTH * 2 + 1];
                    lgetxattr(fpath, "user.s3path", s3_path, SHA_DIGEST_LENGTH * 2 + 1);
                    cloud_delete_object("bigfiles", s3_path);
                    char c = 'f';
                    lsetxattr(fpath, "user.incloud", &c, sizeof(char), 0);
                    need_truncate = 0;
                }
            }
        } else {
            cloud_file_reset(fpath);
        }
    } else {
        if (state_.no_dedup) {
            if (size > state_.threshold) {
                move_to_cloud(fpath, *filestat);
                char c = 't';
                lsetxattr(fpath, "user.incloud", &c, sizeof(char), 0);
            } else {
                need_truncate = 0;
            }
        } else {
            if (size > state_.threshold) {
                char meta_file_path[MAX_PATH_LEN];
                get_meta_path(fpath, meta_file_path);
                split_and_send(fpath, meta_file_path, 0);
                char c = 't';
                lsetxattr(fpath, "user.incloud", &c, sizeof(char), 0);
                set_proxy_xattr(fpath, *filestat);
            } else {
                need_truncate = 0;
            }
        }
    }

    if (need_truncate) {
        chmod(fpath, 0777);
        truncate(fpath, 0);
        chmod(fpath, filestat->st_mode);
    }
    char dirty = 'f';
    lsetxattr(fpath, "user.dirty", &dirty, sizeof(char), 0);
    free(filestat);
    return ret;
}

/* open a directory */
int cloudfs_opendir(const char *path, struct fuse_file_info *fi) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);
    DIR *dp;
    int ret = 0;
    dp = opendir(fpath);
    if (dp == NULL) {
        ret = cloudfs_error("Error in cloudfs_opendir");
    }
    fi->fh = (intptr_t) dp;
    return ret;
}

/* read a direcotry */
int cloudfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset UNUSED,
                    struct fuse_file_info *fi) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    DIR *dp;
    struct dirent *de;

    dp = (DIR *) (uintptr_t) fi->fh;
    de = readdir(dp);
    if (de == 0) {
        ret = cloudfs_error("Error in cloudfs_readdir");
        return ret;
    }

    do {
        if (strstr(de->d_name, "lost+found") != NULL) {
            continue;
        }
        if (strstr(de->d_name, ".cache") != NULL) {
            continue;
        }
        if (strstr(de->d_name, ".meta") != NULL) {
            continue;
        }
        if (filler(buf, de->d_name, NULL, 0) != 0) {
            return -ENOMEM;
        }
    } while ((de = readdir(dp)) != NULL);
    return ret;
}

/* determine whether a file can be accessed */
int cloudfs_access(const char *path, int mask) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = access(fpath, mask);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_access");
    }
    return ret;
}

/* delete a file */
int cloudfs_unlink(const char *path) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;

    if (in_cloud(fpath)) {
        if (state_.no_dedup) {
            unsigned char s3_path[SHA_DIGEST_LENGTH * 2 + 1];
            lgetxattr(fpath, "user.s3path", s3_path, SHA_DIGEST_LENGTH * 2 + 1);
            cloud_delete_object("bigfiles", s3_path);
        } else {
            delete_cloud_file(fpath);
        }
    }

    ret = unlink(fpath);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_unlink");
    }

    return ret;
}

/* update the timestamps of a file */
int cloudfs_utimens(const char *path, const struct timespec ts[2]) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);
    int ret = 0;
    ret = utimensat(0, fpath, ts, AT_SYMLINK_NOFOLLOW);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_error");
    }

    if (in_cloud(fpath)) {
        struct stat *filestat = (struct stat *) malloc(sizeof(struct stat));
        stat(fpath, filestat);
        lsetxattr(fpath, "user.mtime", &(filestat->st_mtime), sizeof(time_t), 0);
        free(filestat);
    }

    return 0;
}

/* change the permission of a file */
int cloudfs_chmod(const char *path, mode_t mode) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = chmod(fpath, mode);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_chmod");
    }

    if (in_cloud(fpath)) {
        struct stat *filestat = (struct stat *) malloc(sizeof(struct stat));
        stat(fpath, filestat);
        free(filestat);
    }
    return ret;
}

/* shrink or extend the size of a file to the specified size */
int cloudfs_truncate(const char *path, off_t size) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);
    int ret = 0;
    if (state_.no_dedup) {
        ret = truncate(fpath, size);
        if (ret < 0)
            ret = cloudfs_error("Error in cloudfs_ftruncate");

        if (in_cloud(fpath)) {
            char dirty = 't';
            lsetxattr(fpath, "user.dirty", &dirty, sizeof(char), 0);
        }
    } else {
        if (in_cloud(fpath)) {
            if (size <= state_.threshold) {
                truncate_cloud_file_to_ssd(fpath, size);
            } else {
                truncate_cloud_file_stay_cloud(fpath, size);
            }
        } else {
            struct stat *filestat = (struct stat *) malloc(sizeof(struct stat));
            ret = truncate(fpath, size);
            stat(fpath, filestat);
            if (filestat->st_size > state_.threshold) {
                char meta_file_path[PATH_MAX];
                get_meta_path(fpath, meta_file_path);
                split_and_send(fpath, meta_file_path, 0);
                int c = 't';
                lsetxattr(fpath, "user.incloud", &c, sizeof(char), 0);
                set_proxy_xattr(fpath, *filestat);
                truncate(fpath, 0);
                free(filestat);
            }
        }
    }

    return ret;
}

/* remove a directory */
int cloudfs_rmdir(const char *path) {
    char fpath[MAX_PATH_LEN];
    cloudfs_get_fullpath(path, fpath);

    int ret = 0;
    ret = rmdir(fpath);
    if (ret < 0) {
        ret = cloudfs_error("Error in cloudfs_rmdir");
    }
    return ret;
}

/*
 * Functions supported by cloudfs 
 */
static
struct fuse_operations cloudfs_operations = {
        //
        // TODO
        //
        // This is where you add the VFS functions that your implementation of
        // MelangsFS will support, i.e. replace 'NULL' with 'melange_operation'
        // --- melange_getattr() and melange_init() show you what to do ...
        //
        // Different operations take different types of parameters. This list can
        // be found at the following URL:
        // --- http://fuse.sourceforge.net/doxygen/structfuse__operations.html
        //
        //
        .getattr        = cloudfs_getattr,
        .getxattr       = cloudfs_getxattr,
        .setxattr       = cloudfs_setxattr,
        .mkdir          = cloudfs_mkdir,
        .mknod          = cloudfs_mknod,
        .open           = cloudfs_open,
        .read           = cloudfs_read,
        .write          = cloudfs_write,
        .release        = cloudfs_release,
        .opendir        = cloudfs_opendir,
        .readdir        = cloudfs_readdir,
        .init           = cloudfs_init,
        .destroy        = cloudfs_destroy,
        .access         = cloudfs_access,
        .utimens        = cloudfs_utimens,
        .chmod          = cloudfs_chmod,
        .unlink         = cloudfs_unlink,
        .truncate       = cloudfs_truncate,
        .rmdir          = cloudfs_rmdir,
        .ioctl         = cloudfs_ioctl
};

int cloudfs_start(struct cloudfs_state *state,
                  const char *fuse_runtime_name) {

    int argc = 0;
    char *argv[10];
    argv[argc] = (char *) malloc(128 * sizeof(char));
    strcpy(argv[argc++], fuse_runtime_name);
    argv[argc] = (char *) malloc(1024 * sizeof(char));
    strcpy(argv[argc++], state->fuse_path);
    argv[argc++] = "-s"; // set the fuse mode to single thread
    //argv[argc++] = "-f"; // run fuse in foreground

    logfile = fopen("/tmp/cloudfs.log", "w");
    setvbuf(logfile, NULL, _IOLBF, 0);
    state_ = *state;

    int fuse_stat = fuse_main(argc, argv, &cloudfs_operations, NULL);
    return fuse_stat;
}
