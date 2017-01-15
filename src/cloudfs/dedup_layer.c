#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include "dedup.h"
#include "uthash.h"
#include "helper.c"
#include "cloudfs.h"

extern struct cloudfs_state state_;

static rabinpoly_t *rp;
static int window_size = 48;
static int avg_seg_size = 4096;
static int min_seg_size = 2048;
static int max_seg_size = 8192;

off_t get_segs_for_read(const char *tmp_file, const char *fpath, size_t size, off_t offset);

void get_segs_for_write(const char *tmp_file, const char *meta_path, size_t size, off_t offset, off_t start);

/* initialzation */
void initialize_rabin() {
    window_size = state_.rabin_window_size;
    avg_seg_size = state_.avg_seg_size;
    if (state_.max_seg_size > avg_seg_size) {
        max_seg_size = state_.max_seg_size;
    } else {
        max_seg_size = avg_seg_size << 1;
    }
    if (state_.min_seg_size < avg_seg_size) {
        min_seg_size = state_.min_seg_size;
    } else {
        min_seg_size = avg_seg_size >> 1;
    }
    rp = rabin_init(window_size, avg_seg_size,
                    min_seg_size, max_seg_size);
    if (!rp) {
        fprintf(stderr, "Failed to init rabinhash algorithm\n");
        exit(1);
    }
}

/* cache hit, update the LRU list */
void cache_hit(char *md5) {
    struct seg_cache *cur = cache_head->next;
    struct seg_cache *pre = cache_head;
    while (cur != NULL) {
        if (strcmp(cur->md5, md5) == 0) {
            if (cur == cache_tail) {
                return;
            }
            pre->next = cur->next;
            cur->next = NULL;
            cache_tail->next = cur;
            cache_tail = cur;
            return;
        }
        pre = cur;
        cur = cur->next;
    }
}

/* add cache to list */
void add_cache(char *md5, int len, int dirty) {
    if (len + cache_size > state_.cache_size) {
        // need eviction
        evict_and_add(md5, len, dirty);
    } else {
        struct seg_cache *new_cache = (struct seg_cache *) malloc(sizeof(struct seg_cache));
        strcpy(new_cache->md5, md5);
        new_cache->next = NULL;
        new_cache->size = len;
        if (dirty) {
            new_cache->dirty = 't';
        } else {
            new_cache->dirty = 'f';
        }
        cache_tail->next = new_cache;
        cache_tail = new_cache;
        cache_size += len;
    }
}

/* evict segments cache from the head of LRU list */
void evict_and_add(char *md5, int len, int dirty) {
    struct seg_cache *cur;
    while (len + cache_size > state_.cache_size) {
        cur = cache_head->next;
        if (cur == NULL) {
            fprintf(logfile, "Error in evicting cache!\n");
            return;
        }
        cache_head->next = cur->next;
        if (cur == cache_tail) {
            cache_tail = cache_head;
        }
        char cache_path[MAX_PATH_LEN];
        strcpy(cache_path, state_.ssd_path);
        strcat(cache_path, ".cache/");
        strcat(cache_path, cur->md5);
        if (cur->dirty == 't') {// if the cache it's dirty
            infile = fopen(cache_path, "r");
            cloud_delete_object("bigfiles", cur->md5);
            cloud_put_object("bigfiles", cur->md5, cur->size, put_buffer);
            fclose(infile);
        }
        truncate(cache_path, 0);
        unlink(cache_path);
        cache_size -= cur->size;
        free(cur);
    }
    add_cache(md5, len, dirty);
}

/* delete a cache given the md5 */
void remove_cache(char *md5) {
    struct seg_cache *cur = cache_head->next;
    struct seg_cache *pre = cache_head;
    while (cur != NULL) {
        if (strcmp(cur->md5, md5) == 0) {
            char cache_path[MAX_PATH_LEN];
            strcpy(cache_path, state_.ssd_path);
            strcat(cache_path, ".cache/");
            strcat(cache_path, md5);
            truncate(cache_path, 0);
            unlink(cache_path);
            pre->next = cur->next;
            cache_size -= cur->size;
            if (cur == cache_tail) {
                cache_tail = pre;
            }
            free(cur);
            return;
        }
        pre = cur;
        cur = cur->next;
    }
}

/* write all dirty segments to the cloud */
void clear_cache() {
    struct seg_cache *cur = cache_head->next;
    while (cur != NULL) {
        cache_head->next = cur->next;
        if (cur == cache_tail) {
            cache_tail = cache_head;
        }
        char cache_path[MAX_PATH_LEN];
        strcpy(cache_path, state_.ssd_path);
        strcat(cache_path, ".cache/");
        strcat(cache_path, cur->md5);
        if (cur->dirty == 't') {// if the cache it's dirty
            infile = fopen(cache_path, "r");
            cloud_delete_object("bigfiles", cur->md5);
            cloud_put_object("bigfiles", cur->md5, cur->size, put_buffer);
            fclose(infile);
        }
        truncate(cache_path, 0);
        unlink(cache_path);
        free(cur);
        cur = cache_head->next;
    }
    cache_size = 0;
}

/* get the current size of a file given its meta file path */
off_t dedup_get_cur_file_size(char *meta_path) {
    FILE *meta_file = fopen(meta_path, "r");
    struct seg_meta metadata;
    int size = sizeof(struct seg_meta);
    off_t total_size = 0;
    while (fread(&metadata, size, 1, meta_file) > 0) {
        total_size += metadata.segment_len;
    }
    fclose(meta_file);
    return total_size;
}

/* reset the xattr of the proxy file */
void cloud_file_reset(const char *fpath) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    int cur_size = dedup_get_cur_file_size(meta_path);
    struct stat *filestat = (struct stat *) malloc(sizeof(struct stat));
    get_proxy_xattr(fpath, filestat);
    filestat->st_size = cur_size;
    set_proxy_xattr(fpath, *filestat);
    free(filestat);
}

/* send a given segment to the cloud or add the reference count by one */
void send_segs_to_cloud(char *md5, int segment_len, FILE *meta_file, char *fpath) {
    if (segment_len == 0) {
        return;
    }
    struct segment *s = NULL;
    HASH_FIND_STR(segments, md5, s);
    if (s == NULL) {
        s = (struct segment *) malloc(sizeof(struct segment));
        strcpy(s->md5, md5);
        s->count = 1;
        HASH_ADD_STR(segments, md5, s);
        if (state_.cache_size) {
            // add new cache
            char cache_path[MAX_PATH_LEN];
            strcpy(cache_path, state_.ssd_path);
            strcat(cache_path, ".cache/");
            strcat(cache_path, md5);
            char buf[segment_len + 1];
            FILE *cache_file = fopen(cache_path, "w+");
            fclose(cache_file);
            off_t p = ftello(infile);
            int fd = open(fpath, O_RDONLY);
            pread(fd, buf, segment_len, p);
            close(fd);
            fd = open(cache_path, O_WRONLY);
            int w = pwrite(fd, buf, segment_len, 0);
            close(fd);
            fseek(infile, segment_len, SEEK_CUR);
            p = ftello(infile);
            fclose(infile);
            add_cache(md5, segment_len, 1);
            infile = fopen(fpath, "r");
            fseek(infile, p, SEEK_SET);
        } else {
            cloud_put_object("bigfiles", md5, segment_len, put_buffer);
        }
    } else {
        s->count++;
        if (state_.cache_size) {
            if (in_cache(md5)) {
                // cache hit
                cache_hit(md5);
                fseek(infile, segment_len, SEEK_CUR);
                off_t p = ftello(infile);
            } else {
                // add new cache
                char cache_path[MAX_PATH_LEN];
                strcpy(cache_path, state_.ssd_path);
                strcat(cache_path, ".cache/");
                strcat(cache_path, md5);
                char buf[segment_len + 1];
                FILE *cache_file = fopen(cache_path, "w+");
                fclose(cache_file);
                off_t p = ftello(infile);
                int fd = open(fpath, O_RDONLY);
                pread(fd, buf, segment_len, p);
                close(fd);
                fd = open(cache_path, O_WRONLY);
                int w = pwrite(fd, buf, segment_len, 0);
                close(fd);
                fseek(infile, segment_len, SEEK_CUR);
                p = ftello(infile);
                fclose(infile);
                add_cache(md5, segment_len, 1);
                infile = fopen(fpath, "r");
                fseek(infile, p, SEEK_SET);
            }
        } else {
            cloud_put_object("bigfiles", md5, segment_len, put_buffer);
        }
    }
    struct seg_meta new_meta;
    strcpy(new_meta.segment_md5, md5);
    new_meta.segment_len = segment_len;
    fwrite(&new_meta, sizeof(struct seg_meta), 1, meta_file);
}

/* split the file using Rabin algorithm and send to the cloud */
void split_and_send(const char *fpath, const char *meta_path, int mode) {
    rabin_reset(rp);
    int fd;
    if (fpath) {
        fd = open(fpath, O_RDONLY);
        if (fd == -1) {
            fprintf(logfile, "open failed\n");
            exit(2);
        }
    } else {
        fd = STDIN_FILENO;
    }
    infile = fopen(fpath, "r");
    FILE *meta_file;
    if (mode == 1) {
        meta_file = fopen(meta_path, "a");
    } else {
        meta_file = fopen(meta_path, "w+");
    }
    MD5_CTX ctx;
    unsigned char md5[MD5_DIGEST_LENGTH];
    int new_segment = 0;
    int len, segment_len = 0, b;
    char buf[1024];
    int bytes;
    char md5_key[2 * MD5_DIGEST_LENGTH];
    MD5_Init(&ctx);
    while ((bytes = read(fd, buf, sizeof buf)) > 0) {
        char *buftoread = &buf[0];
        while ((len = rabin_segment_next(rp, buftoread, bytes,
                                         &new_segment)) > 0) {
            MD5_Update(&ctx, buftoread, len);
            segment_len += len;

            if (new_segment) {
                MD5_Final(md5, &ctx);

                for (b = 0; b < MD5_DIGEST_LENGTH; b++)
                    sprintf(&md5_key[b * 2], "%02x", md5[b]);
                send_segs_to_cloud(md5_key, segment_len, meta_file, fpath);
                MD5_Init(&ctx);
                segment_len = 0;
            }

            buftoread += len;
            bytes -= len;

            if (!bytes) {
                break;
            }
        }
        if (len == -1) {
            fprintf(logfile, "Failed to process the segment\n");
            exit(2);
        }
    }
    MD5_Final(md5, &ctx);

    for (b = 0; b < MD5_DIGEST_LENGTH; b++) {
        sprintf(&md5_key[b * 2], "%02x", md5[b]);
    }
    send_segs_to_cloud(md5_key, segment_len, meta_file, fpath);
    fclose(meta_file);
    close(fd);
    fclose(infile);
}

/* delete a file in the cloud given the path */
void delete_cloud_file(const char *fpath) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    FILE *meta_file = fopen(meta_path, "r");
    if (meta_file == NULL) {
        cloudfs_error("Error in opening meta file!  delete_cloud_file!\n");
        exit(1);
    }
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        struct segment *s = NULL;
        HASH_FIND_STR(segments, meta.segment_md5, s);
        if (s == NULL) {
            cloudfs_error("Error in looking up hash table!\n");
            exit(1);
        }
        s->count--;
        if (s->count <= 0) {
            cloud_delete_object("bigfiles", s->md5);
            HASH_DEL(segments, s);
            free(s);
        }
    }
    fclose(meta_file);
    truncate(meta_path, 0);
    unlink(meta_path);
}

/* download related segments from the cloud for read */
off_t get_segs_for_read(const char *tmp_file, const char *fpath, size_t size, off_t offset) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    FILE *meta_file = fopen(meta_path, "r");
    if (meta_file == NULL) {
        cloudfs_error("Error in opening meta file!  get_segs_for_read!\n");
        exit(1);
    }
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    int cur_ptr = 0;
    off_t new_offset = 0;
    if (state_.cache_size) {
        FILE *read_tmp = fopen(tmp_file, "w+");
        while (offset != 0 && fread(&meta, seg_meta_size, 1, meta_file) > 0) {
            cur_ptr += meta.segment_len;
            if (cur_ptr > offset) {
                new_offset = offset - cur_ptr + meta.segment_len;

                char cache_path[MAX_PATH_LEN];
                strcpy(cache_path, state_.ssd_path);
                strcat(cache_path, ".cache/");
                strcat(cache_path, meta.segment_md5);

                if (in_cache(meta.segment_md5)) {
                    cache_hit(meta.segment_md5);
                } else {
                    outfile = fopen(cache_path, "w+");
                    cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
                    fclose(outfile);
                    add_cache(meta.segment_md5, meta.segment_len, 0);
                }
                outfile = fopen(cache_path, "r");
                char c;
                c = fgetc(outfile);
                while (c != EOF) {
                    fputc(c, read_tmp);
                    c = fgetc(outfile);
                }
                fclose(outfile);
                break;
            }
        }

        while (cur_ptr - offset < size) {
            if (fread(&meta, seg_meta_size, 1, meta_file) <= 0) {
                break;
            }
            cur_ptr += meta.segment_len;
            char cache_path[MAX_PATH_LEN];
            strcpy(cache_path, state_.ssd_path);
            strcat(cache_path, ".cache/");
            strcat(cache_path, meta.segment_md5);
            if (in_cache(meta.segment_md5)) {
                cache_hit(meta.segment_md5);
            } else {
                outfile = fopen(cache_path, "w+");
                cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
                fclose(outfile);
                add_cache(meta.segment_md5, meta.segment_len, 0);
            }
            outfile = fopen(cache_path, "r");
            char c;
            c = fgetc(outfile);
            while (c != EOF) {
                fputc(c, read_tmp);
                c = fgetc(outfile);
            }
            fclose(outfile);
        }

        fclose(read_tmp);

    } else {
        outfile = fopen(tmp_file, "w+");

        while (offset != 0 && fread(&meta, seg_meta_size, 1, meta_file) > 0) {
            cur_ptr += meta.segment_len;
            if (cur_ptr > offset) {
                new_offset = offset - cur_ptr + meta.segment_len;
                cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
                break;
            }
        }

        while (cur_ptr - offset < size) {
            if (fread(&meta, seg_meta_size, 1, meta_file) <= 0) {
                break;
            }
            cur_ptr += meta.segment_len;
            cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
        }
        fclose(outfile);
    }
    fclose(meta_file);
    return new_offset;
}

/* read cloud file */
int read_segs_from_cloud(const char *fpath, char *buf, size_t size, off_t offset) {
    char tmp_file[MAX_PATH_LEN];
    strcpy(tmp_file, fpath);
    strcat(tmp_file, "_tmp");
    off_t new_offset = get_segs_for_read(tmp_file, fpath, size, offset);
    int fd = open(tmp_file, O_RDONLY);
    int ret = pread(fd, buf, size, new_offset);
    close(fd);
    truncate(tmp_file, 0);
    unlink(tmp_file);
    return ret;
}

/* download related segments from the cloud for write */
void get_segs_for_write(const char *tmp_file, const char *meta_path, size_t size, off_t offset, off_t start) {
    FILE *meta_file = fopen(meta_path, "r");
    if (meta_file == NULL) {
        cloudfs_error("Error in opening meta file! get_segs_for_write!\n");
        exit(1);
    }
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    int cur_ptr = 0;
    int find_end = 0;

    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (cur_ptr <= start) {
            continue;
        }
        if (state_.cache_size) {
            if (in_cache(meta.segment_md5)) {
                // cache hit
                char cache_path[MAX_PATH_LEN];
                strcpy(cache_path, state_.ssd_path);
                strcat(cache_path, ".cache/");
                strcat(cache_path, meta.segment_md5);
                FILE *cache_file = fopen(cache_path, "r");
                char buf[meta.segment_len + 1];
                fread(buf, meta.segment_len, 1, cache_file);
                outfile = fopen(tmp_file, "a");
                fwrite(buf, meta.segment_len, 1, outfile);
                fclose(outfile);
                fclose(cache_file);
                remove_cache(meta.segment_md5);
            } else {
                // cache miss, download from the cloud
                outfile = fopen(tmp_file, "a");
                cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
                fclose(outfile);
            }
        } else {
            outfile = fopen(tmp_file, "a");
            cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
            fclose(outfile);
        }
        struct segment *s = NULL;
        HASH_FIND_STR(segments, meta.segment_md5, s);
        if (s == NULL) {
            cloudfs_error("Error in looking up hash table!\n");
            exit(1);
        }
        s->count--;
        if (s->count == 0) {
            cloud_delete_object("bigfiles", s->md5);
            HASH_DEL(segments, s);
            free(s);
        }
        if (find_end == 1) {
            break;
        }
        if (cur_ptr >= (offset + size)) {
            find_end = 1;
        }
    }

    fclose(meta_file);
}

/* write to the end of the cloud file */
ssize_t write_to_cloud_end(const char *fpath, char *buf, size_t size, off_t offset) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    char meta_path_new[MAX_PATH_LEN];
    strcpy(meta_path_new, meta_path);
    strcat(meta_path_new, "_new");
    FILE *meta_file = fopen(meta_path, "r");
    FILE *meta_file_new = fopen(meta_path_new, "w+");
    char tmp_file[MAX_PATH_LEN];
    strcpy(tmp_file, fpath);
    strcat(tmp_file, "_tmp");
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    int cur_ptr = 0;
    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (cur_ptr >= offset) {
            struct segment *seg = NULL;
            HASH_FIND_STR(segments, meta.segment_md5, seg);
            if (seg == NULL) {
                cloudfs_error("Error in looking up hash table!\n");
                exit(1);
            }

            if (state_.cache_size) {
                if (in_cache(meta.segment_md5)) {
                    // cache hit
                    char cache_path[MAX_PATH_LEN];
                    strcpy(cache_path, state_.ssd_path);
                    strcat(cache_path, ".cache/");
                    strcat(cache_path, meta.segment_md5);
                    FILE *cache_file = fopen(cache_path, "r");
                    char buf[meta.segment_len + 1];
                    fread(buf, meta.segment_len, 1, cache_file);
                    outfile = fopen(tmp_file, "w+");
                    fwrite(buf, meta.segment_len, 1, outfile);
                    fclose(outfile);
                    fclose(cache_file);
                    remove_cache(meta.segment_md5);
                } else {
                    // cache miss, download from the cloud
                    outfile = fopen(tmp_file, "w+");
                    cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
                    fclose(outfile);
                }
            } else {
                outfile = fopen(tmp_file, "w+");
                cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
                fclose(outfile);
            }

            seg->count--;
            if (seg->count <= 0) {
                HASH_DEL(segments, seg);
                cloud_delete_object("bigfiles", meta.segment_md5);
                free(seg);
            }
            break;
        }
        fwrite(&meta, seg_meta_size, 1, meta_file_new);
    }
    fclose(meta_file);
    fclose(meta_file_new);

    int fd = open(tmp_file, O_WRONLY);
    int ret = pwrite(fd, buf, size, meta.segment_len);
    close(fd);

    split_and_send(tmp_file, meta_path_new, 1);
    truncate(meta_path, 0);
    truncate(tmp_file, 0);
    unlink(meta_path);
    unlink(tmp_file);
    rename(meta_path_new, meta_path);
    return ret;
}

/* write to the head of the cloud file */
ssize_t write_to_cloud_head(const char *fpath, char *buf, size_t size) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    char meta_path_new[MAX_PATH_LEN];
    strcpy(meta_path_new, meta_path);
    strcat(meta_path_new, "_new");
    char tmp_file[MAX_PATH_LEN];
    strcpy(tmp_file, fpath);
    strcat(tmp_file, "_tmp");
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    int cur_ptr = 0;
    FILE *meta_file = fopen(meta_path, "r");
    int find_end = 0;
    while (fread((&meta), seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (find_end == 1) {
            break;
        }
        if (cur_ptr >= size) {
            find_end = 1;
        }
    }
    get_segs_for_write(tmp_file, meta_path, size, 0, 0);

    int fd = open(tmp_file, O_WRONLY);
    int ret = pwrite(fd, buf, size, 0);
    close(fd);

    split_and_send(tmp_file, meta_path_new, 0);
    FILE *meta_file_new = fopen(meta_path_new, "a");
    while (fread((&meta), seg_meta_size, 1, meta_file) > 0) {
        fwrite(&meta, seg_meta_size, 1, meta_file_new);
    }

    fclose(meta_file_new);
    fclose(meta_file);
    truncate(meta_path, 0);
    truncate(tmp_file, 0);
    unlink(meta_path);
    unlink(tmp_file);
    rename(meta_path_new, meta_path);
    return ret;
}

/* write to the middle of the cloud file */
ssize_t write_to_cloud_mid(const char *fpath, char *buf, size_t size, off_t offset) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    char meta_path_tail[MAX_PATH_LEN];
    strcpy(meta_path_tail, meta_path);
    strcat(meta_path_tail, "_tail");
    char meta_path_head[MAX_PATH_LEN];
    strcpy(meta_path_head, meta_path);
    strcat(meta_path_head, "_head");
    char tmp_file[MAX_PATH_LEN];
    strcpy(tmp_file, fpath);
    strcat(tmp_file, "_tmp");
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    int cur_ptr = 0, start = 0, pre_len = 0, find_end = 0;
    FILE *meta_file = fopen(meta_path, "r");
    FILE *meta_file_tail = fopen(meta_path_tail, "w+");
    FILE *meta_file_head = fopen(meta_path_head, "w+");
    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (cur_ptr > offset) {
            if (pre_len == 0) {
                start = 0;
            } else {
                start -= pre_len;
            }
            break;
        }
        pre_len = meta.segment_len;
        start = cur_ptr;
    }

    off_t new_offset = offset - start;

    if (cur_ptr >= (offset + size)) {
        find_end = 1;
    }

    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (find_end) {
            break;
        }
        if (cur_ptr >= (offset + size)) {
            find_end = 1;
        }
    }

    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        fwrite(&meta, seg_meta_size, 1, meta_file_tail);
    }

    fseek(meta_file, 0, SEEK_SET);
    cur_ptr = 0;
    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (cur_ptr > start) {
            break;
        }
        fwrite(&meta, seg_meta_size, 1, meta_file_head);
    }
    fclose(meta_file_head);
    fclose(meta_file_tail);
    fclose(meta_file);


    get_segs_for_write(tmp_file, meta_path, size, offset, start);

    int fd = open(tmp_file, O_WRONLY);
    int ret = pwrite(fd, buf, size, new_offset);
    close(fd);

    meta_file = fopen(meta_path, "w");
    meta_file_head = fopen(meta_path_head, "r");
    while (fread(&meta, seg_meta_size, 1, meta_file_head) > 0) {
        fwrite(&meta, seg_meta_size, 1, meta_file);
    }
    fclose(meta_file);
    fclose(meta_file_head);

    split_and_send(tmp_file, meta_path, 1);

    meta_file = fopen(meta_path, "a");
    meta_file_tail = fopen(meta_path_tail, "r");
    while (fread(&meta, seg_meta_size, 1, meta_file_tail) > 0) {
        fwrite(&meta, seg_meta_size, 1, meta_file);
    }
    fclose(meta_file);
    fclose(meta_file_tail);

    truncate(tmp_file, 0);
    truncate(meta_path_head, 0);
    truncate(meta_path_tail, 0);
    unlink(tmp_file);
    unlink(meta_path_tail);
    unlink(meta_path_head);
    return ret;
}

/* truncate a cloud file and move it to local */
void truncate_cloud_file_to_ssd(const char *fpath, off_t size) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    FILE *meta_file = fopen(meta_path, "r");
    outfile = fopen(fpath, "w");
    struct seg_meta meta;
    off_t seg_meta_size = sizeof(struct seg_meta);
    off_t cur_ptr = 0;
    while (cur_ptr < size) {
        if (fread(&meta, seg_meta_size, 1, meta_file) <= 0) {
            break;
        }
        cur_ptr += meta.segment_len;
        cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
        struct segment *s = NULL;
        HASH_FIND_STR(segments, meta.segment_md5, s);
        if (s == NULL) {
            cloudfs_error("Error in looking up hash table!\n");
            exit(1);
        }
        s->count--;
        if (s->count == 0) {
            cloud_delete_object("bigfiles", s->md5);
            HASH_DEL(segments, s);
            free(s);
        }
    }

    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        struct segment *s = NULL;
        HASH_FIND_STR(segments, meta.segment_md5, s);
        if (s == NULL) {
            cloudfs_error("Error in looking up hash table!\n");
            exit(1);
        }
        s->count--;
        if (s->count == 0) {
            cloud_delete_object("bigfiles", s->md5);
            HASH_DEL(segments, s);
            free(s);
        }
    }
    fclose(outfile);
    fclose(meta_file);
    truncate(fpath, size);
    unlink(meta_path);
    char c = 'f';
    lsetxattr(fpath, "user.incloud", &c, sizeof(char), 0);
}

/* truncate a cloud file which still stays in the cloud */
void truncate_cloud_file_stay_cloud(const char *fpath, off_t size) {
    char meta_path[MAX_PATH_LEN];
    get_meta_path(fpath, meta_path);
    char meta_path_new[MAX_PATH_LEN];
    strcpy(meta_path_new, meta_path);
    strcat(meta_path_new, "_new");
    FILE *meta_file = fopen(meta_path, "r");
    FILE *meta_file_new = fopen(meta_path_new, "w+");
    char tmp_file[MAX_PATH_LEN];
    strcpy(tmp_file, fpath);
    strcat(tmp_file, "_tmp");
    int seg_meta_size = sizeof(struct seg_meta);
    struct seg_meta meta;
    int cur_ptr = 0, tmp_size = 0;
    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        cur_ptr += meta.segment_len;
        if (cur_ptr >= size) {
            tmp_size = size - cur_ptr + meta.segment_len;
            struct segment *seg = NULL;
            HASH_FIND_STR(segments, meta.segment_md5, seg);
            if (seg == NULL) {
                cloudfs_error("Error in looking up hash table!\n");
                exit(1);
            }
            outfile = fopen(tmp_file, "w");
            cloud_get_object("bigfiles", meta.segment_md5, get_buffer);
            fclose(outfile);
            seg->count--;
            if (seg->count <= 0) {
                HASH_DEL(segments, seg);
                cloud_delete_object("bigfiles", meta.segment_md5);
                free(seg);
            }
            break;
        }
        fwrite(&meta, seg_meta_size, 1, meta_file_new);
    }

    while (fread(&meta, seg_meta_size, 1, meta_file) > 0) {
        struct segment *s = NULL;
        HASH_FIND_STR(segments, meta.segment_md5, s);
        if (s == NULL) {
            cloudfs_error("Error in looking up hash table!\n");
            exit(1);
        }
        s->count--;
        if (s->count == 0) {
            cloud_delete_object("bigfiles", s->md5);
            HASH_DEL(segments, s);
            free(s);
        }
    }

    fclose(meta_file);
    fclose(meta_file_new);
    truncate(tmp_file, tmp_size);

    split_and_send(tmp_file, meta_path_new, 1);
    truncate(meta_path, 0);
    truncate(tmp_file, 0);
    unlink(meta_path);
    unlink(tmp_file);
    rename(meta_path_new, meta_path);
}
