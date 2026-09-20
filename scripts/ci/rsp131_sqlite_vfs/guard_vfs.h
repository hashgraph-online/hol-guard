/* Opt-in SQLite VFS observation. No payload, SQL, or event retention.
 * One private owned database path is retained only for scope admission. */
#ifndef GUARD_SQLITE_VFS_H
#define GUARD_SQLITE_VFS_H

#if defined(_WIN32)
#error "This diagnostic currently requires a POSIX pthread host."
#endif
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT3

enum { GUARD_OTHER, GUARD_WRITER, GUARD_READBACK, GUARD_SCOPES };
enum { GUARD_AUX, GUARD_MAIN, GUARD_WAL, GUARD_JOURNAL, GUARD_ROLES };
enum {
    G_OPEN, G_OPEN_ERROR, G_CLOSE, G_CLOSE_ERROR,
    G_READ, G_READ_ERROR, G_READ_REQUESTED, G_READ_OK_BYTES,
    G_WRITE, G_WRITE_ERROR, G_WRITE_REQUESTED, G_WRITE_OK_BYTES,
    G_WRITE_ERROR_REQUESTED, G_SYNC, G_SYNC_ERROR, G_SYNC_NORMAL,
    G_SYNC_FULL, G_SYNC_DATAONLY, G_TRUNCATE, G_TRUNCATE_ERROR,
    G_FETCH, G_FETCH_MAPPED, G_CROSS_THREAD, GUARD_METRICS
};
typedef struct GuardVfs GuardVfs;
typedef struct GuardFile {
    sqlite3_file base;
    sqlite3_io_methods methods;
    GuardVfs *owner;
    pthread_t opening_thread;
    int scope;
    int role;
    /* The real sqlite3_file starts at the next aligned byte after this object. */
} GuardFile;
struct GuardVfs {
    sqlite3_vfs base;
    sqlite3_vfs *original;
    sqlite3_mutex *mutex;
    sqlite3_int64 values[GUARD_SCOPES][GUARD_ROLES][GUARD_METRICS];
    sqlite3_int64 active;
    sqlite3_int64 opening;
    sqlite3_int64 unsupported;
    sqlite3_int64 outside_owned;
    char *database;
    sqlite3_int64 saturated;
    int registered;
    int abandoned;
    int permanent;
    char name[80];
};
#define GUARD_FILE_OFFSET ((sizeof(GuardFile) + 7u) & ~(size_t)7u)

sqlite3_file *guard_real(sqlite3_file *file);
void guard_add(GuardVfs *owner, sqlite3_int64 *field, sqlite3_int64 amount);
void guard_measure(GuardFile *file, int metric, sqlite3_int64 amount);
void guard_touch(GuardFile *file);
int guard_methods(GuardFile *file);
int guard_open(sqlite3_vfs *, const char *, sqlite3_file *, int, int *);
void guard_vfs_methods(GuardVfs *);
void guard_control(sqlite3_context *, int, sqlite3_value **);
void guard_destroy(void *);

#endif
