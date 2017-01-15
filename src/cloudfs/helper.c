#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "dedup.h"
#include "uthash.h"
#include "cloudfs.h"

#define UNUSED __attribute__((unused))

FILE *logfile;
FILE *infile;
FILE *outfile;

extern struct cloudfs_state state_;
static char *str_seg_backup = ".seg_backup";
int cache_size = 0;

/* store the md5 value and reference count of a segment in the cloud */
struct segment {
    char md5[MD5_DIGEST_LENGTH * 2 + 1];
    int count;
    UT_hash_handle hh;
};

/* store the md5 value and size of a segment of a certain file */
struct seg_meta {
    char segment_md5[MD5_DIGEST_LENGTH * 2 + 1];
    int segment_len;
};

/* store the segments that are in cache */
struct seg_cache {
    char md5[MD5_DIGEST_LENGTH * 2 + 1];
    int size;
    char dirty;
    struct seg_cache *next;
};

struct segment *segments = NULL;
struct seg_cache *cache_head = NULL, *cache_tail = NULL;

/* print error message */
static int UNUSED cloudfs_error(char *error_str) {
    if (state_.cache_size) {
        fprintf(logfile, "CloudFS Error: %s\n", error_str);
    }
    return -errno;
}

/* used to download file from the cloud */
int get_buffer(const char *buffer, int bufferLength) {
    return fwrite(buffer, 1, bufferLength, outfile);
}

/* used to send file to the cloud */
int put_buffer(char *buffer, int bufferLength) {
    return fread(buffer, 1, bufferLength, infile);
}

/* get the S3 path, only used in no-dedup mode */
unsigned char *get_S3_path(const char *fpath) {
    int i;
    unsigned char meta_filename[SHA_DIGEST_LENGTH];
    unsigned char s3_path[SHA_DIGEST_LENGTH * 2 + 1];
    memset(meta_filename, 0x0, SHA_DIGEST_LENGTH);
    SHA1((unsigned char *) fpath, strlen(fpath), meta_filename);
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char *) &(s3_path[i * 2]), "%02x", meta_filename[i]);
    }
    s3_path[SHA_DIGEST_LENGTH * 2] = '\0';
    return s3_path;
}

/* list the services in the cloud */
int list_service(const char *bucketName) {
    fprintf(logfile, "list_service: %s\n", bucketName);
    return 0;
}

/* list the buckets in the cloud */
int list_bucket(const char *key, time_t modified_time UNUSED, uint64_t size UNUSED) {
    fprintf(logfile, "list_bucket: %s", key);
    return 0;
}

/* get the xattr of fpath */
void get_proxy_xattr(const char *fpath, struct stat *filestat) {
    lgetxattr(fpath, "user.proxysize", &(filestat->st_size), sizeof(off_t));
    lgetxattr(fpath, "user.mtime", &(filestat->st_mtime), sizeof(time_t));
}

/* set the xattr of fpath using filestat */
void set_proxy_xattr(const char *fpath, struct stat filestat) {
    lsetxattr(fpath, "user.proxysize", &(filestat.st_size), sizeof(off_t), 0);
    lsetxattr(fpath, "user.mtime", &(filestat.st_mtime), sizeof(time_t), 0);
}

/* check whether the file is in the cloud */
int in_cloud(const char *fpath) {
    char c = 't';
    ssize_t result = lgetxattr(fpath, "user.incloud", &c, sizeof(char));
    if (result > 0 && c == 't') {
        return 1;
    } else {
        return 0;
    }
}

/* get the path of a file's meta data file */
void get_meta_path(const char *fpath, char *meta_path) {
    char c = 'f';
    lgetxattr(fpath, "user.snapshot", &c, sizeof(char));
    if (c == 't') {
        unsigned int timestamp = 0;
        lgetxattr(fpath, "user.timestamp", &timestamp, sizeof(unsigned int));
        char str_ts[8];
        sprintf(str_ts, "%u", timestamp);
        strcpy(meta_path, state_.ssd_path);
        strcat(meta_path, "snapshot_");
        strcat(meta_path, str_ts);
        strcat(meta_path, "/");
        int tmp_len = strlen(meta_path);
        strcat(meta_path, ".meta/");
        char meta_filename[MAX_PATH_LEN];
        meta_filename[0] = '.';
        strcpy(&meta_filename[1], &fpath[tmp_len]);
        int i = 1;
        while (meta_filename[i] != '\0') {
            if (meta_filename[i] == '/') {
                meta_filename[i] = '+';
            }
            i++;
        }
        strcat(meta_path, meta_filename);
        return;
    }
    int len = strlen(state_.ssd_path);
    char meta_filename[MAX_PATH_LEN];
    meta_filename[0] = '.';
    strcpy(&meta_filename[1], &fpath[len]);
    int i = 1;
    for (; meta_filename[i] != '\0'; i++) {
        if (meta_filename[i] == '/') {
            meta_filename[i] = '+';
        }
    }
    strcpy(meta_path, state_.ssd_path);
    strcat(meta_path, ".meta/");
    strcat(meta_path, meta_filename);
}

/* create metadata directory ".meta" */
void create_meta_dir() {
    char meta_dir_path[MAX_PATH_LEN];
    strcpy(meta_dir_path, state_.ssd_path);
    strcat(meta_dir_path, ".meta");
    if (access(meta_dir_path, F_OK) == -1) {
        mkdir(meta_dir_path, 0755);
    }
    return;
}

/* backup the segments hashtable to file */
void backup_hash_table() {
    char seg_backup_path[MAX_PATH_LEN];
    strcpy(seg_backup_path, state_.ssd_path);
    strcat(seg_backup_path, str_seg_backup);
    FILE *seg_file = fopen(seg_backup_path, "w+");
    struct segment *seg;
    int seg_size = sizeof(struct segment);
    for (seg = segments; seg != NULL; seg = (struct segment *) (seg->hh.next)) {
        fwrite(seg, seg_size, 1, seg_file);
    }
    fclose(seg_file);
}

/* restore the hashtable from the backup file */
void restore_hash_table() {
    char seg_backup_path[MAX_PATH_LEN];
    strcpy(seg_backup_path, state_.ssd_path);
    strcat(seg_backup_path, str_seg_backup);
    if (access(seg_backup_path, F_OK) != -1) {
        FILE *seg_file = fopen(seg_backup_path, "r");
        int seg_size = sizeof(struct segment);
        struct segment seg;
        while (fread(&seg, seg_size, 1, seg_file) > 0) {
            struct segment *s = (struct segment *) malloc(seg_size);
            strcpy(s->md5, seg.md5);
            s->count = seg.count;
            HASH_ADD_STR(segments, md5, s);
        }
        fclose(seg_file);
    }
}

/* create cache directory ".cache" */
void create_cache_dir() {
    char meta_dir_path[MAX_PATH_LEN];
    strcpy(meta_dir_path, state_.ssd_path);
    strcat(meta_dir_path, ".cache");
    if (access(meta_dir_path, F_OK) == -1) {
        mkdir(meta_dir_path, 0777);
    }
}

/* check if the segment is in the cache */
int in_cache(char *md5) {
    char cache_path[MAX_PATH_LEN];
    strcpy(cache_path, state_.ssd_path);
    strcat(cache_path, ".cache/");
    strcat(cache_path, md5);
    if (access(cache_path, F_OK) != -1) {
        return 1;
    } else {
        return 0;
    }
}

/* backup LRU list of the cache */
void backup_cache_list() {
    char list_path[MAX_PATH_LEN];
    strcpy(list_path, state_.ssd_path);
    strcat(list_path, ".cache_list");
    FILE *seg_file = fopen(list_path, "w+");
    struct seg_cache *cur = cache_head->next;
    int size = sizeof(struct seg_cache);
    while (cur != NULL) {
        fwrite(cur, size, 1, seg_file);
        cur = cur->next;
    }
    fclose(seg_file);
}

/* restore the LRU list of the cache */
void restore_cache_list() {
    int size = sizeof(struct seg_cache);
    cache_size = 0;
    if (cache_head != NULL) {
        struct seg_cache *ptr = cache_head->next;
        while (ptr != NULL) {
            cache_head->next = ptr->next;
            free(ptr);
            ptr = cache_head->next;
        }
    } else {
        cache_head = (struct seg_cache *) malloc(size);
    }
    cache_head->next = NULL;
    cache_tail = cache_head;
    char list_path[MAX_PATH_LEN];
    strcpy(list_path, state_.ssd_path);
    strcat(list_path, ".cache_list");
    if (access(list_path, F_OK) != -1) {
        FILE *seg_file = fopen(list_path, "r");
        struct seg_cache entry;
        while (fread(&entry, size, 1, seg_file) > 0) {
            struct seg_cache *new_cache = (struct seg_cache *) malloc(size);
            new_cache->next = NULL;
            strcpy(new_cache->md5, entry.md5);
            new_cache->size = entry.size;
            new_cache->dirty = entry.dirty;

            cache_tail->next = new_cache;
            cache_tail = new_cache;
            cache_size += entry.size;
        }
        fclose(seg_file);
    }
}