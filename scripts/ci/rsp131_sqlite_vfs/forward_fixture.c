/* Portable callback controls only. These stubs are not a SQLite engine. */
#define SQLITE_CORE 1
#include "guard_vfs.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "check failed line %d\n", __LINE__); exit(91); } } while (0)
static int seen;
static int closes;
static int version = 3;
static int open_result;
static int open_has_methods = 1;
static int optional_methods = 1;
static sqlite3_vfs parent;
static sqlite3_io_methods original;
static const char *expected_name;
static const void *expected_buffer;
static unsigned char effects[8];
static unsigned char shared[16];
static int token;

void sqlite3_mutex_enter(sqlite3_mutex *mutex) { (void)mutex; }
void sqlite3_mutex_leave(sqlite3_mutex *mutex) { (void)mutex; }
const char *sqlite3_uri_parameter(const char *name, const char *key) {
    CHECK(name == expected_name);
    CHECK(strcmp(key, "guard_scope") == 0);
    return "writer";
}
const char *sqlite3_filename_database(const char *name) {
    CHECK(name == expected_name);
    return "/owned.db";
}
static int closed(sqlite3_file *file) {
    CHECK(file->pMethods == &original);
    closes++;
    errno = ENOSPC;
    return SQLITE_IOERR_CLOSE;
}
static int read_file(sqlite3_file *file, void *buffer, int amount, sqlite3_int64 offset) {
    CHECK(file->pMethods == &original && buffer == expected_buffer && amount == 8 && offset == 17);
    memcpy(buffer, "abcd", 4);
    memset((char *)buffer + 4, 0, 4);
    errno = EIO;
    return SQLITE_IOERR_SHORT_READ;
}
static int write_file(sqlite3_file *file, const void *buffer, int amount, sqlite3_int64 offset) {
    CHECK(file->pMethods == &original && buffer == expected_buffer && amount == 8 && offset == 17);
    memcpy(effects, buffer, 4); /* A real prefix effect followed by a failing SQLite status. */
    errno = ENOSPC;
    return SQLITE_IOERR_WRITE;
}
static int sync_file(sqlite3_file *file, int flags) {
    CHECK(file->pMethods == &original && flags == (SQLITE_SYNC_FULL | SQLITE_SYNC_DATAONLY));
    errno = EIO;
    return SQLITE_IOERR_FSYNC;
}
static int truncate_file(sqlite3_file *file, sqlite3_int64 size) {
    CHECK(file->pMethods == &original && size == 17);
    errno = EFBIG;
    return SQLITE_FULL;
}
static int file_size(sqlite3_file *file, sqlite3_int64 *out) {
    CHECK(file->pMethods == &original);
    *out = 73;
    errno = EIO;
    return SQLITE_IOERR_FSTAT;
}
static int lock_file(sqlite3_file *file, int level) {
    CHECK(file->pMethods == &original && level == 3);
    seen |= 1;
    return SQLITE_BUSY;
}
static int unlock_file(sqlite3_file *file, int level) {
    CHECK(file->pMethods == &original && level == 1);
    seen |= 2;
    return SQLITE_IOERR_UNLOCK;
}
static int reserved(sqlite3_file *file, int *out) {
    CHECK(file->pMethods == &original);
    *out = 1;
    seen |= 4;
    return SQLITE_OK;
}
static int file_control(sqlite3_file *file, int operation, void *out) {
    CHECK(file->pMethods == &original && operation == 1234 && out == &token);
    token = 29;
    seen |= 8;
    return SQLITE_NOTFOUND;
}
static int sector(sqlite3_file *file) { CHECK(file->pMethods == &original); return 4096; }
static int characteristics(sqlite3_file *file) { CHECK(file->pMethods == &original); return SQLITE_IOCAP_SAFE_APPEND; }
static int shm_map(sqlite3_file *file, int page, int size, int extend, void volatile **out) {
    CHECK(file->pMethods == &original && page == 2 && size == 16 && extend == 1);
    *out = shared;
    seen |= 16;
    return SQLITE_IOERR_SHMMAP;
}
static int shm_lock(sqlite3_file *file, int offset, int count, int flags) {
    CHECK(file->pMethods == &original && offset == 2 && count == 3 && flags == 7);
    seen |= 32;
    return SQLITE_BUSY;
}
static void barrier(sqlite3_file *file) { CHECK(file->pMethods == &original); seen |= 64; }
static int shm_unmap(sqlite3_file *file, int remove) {
    CHECK(file->pMethods == &original && remove == 1);
    seen |= 128;
    return SQLITE_IOERR_SHMOPEN;
}
static int fetch_file(sqlite3_file *file, sqlite3_int64 offset, int amount, void **out) {
    CHECK(file->pMethods == &original && offset == 17 && amount == 8);
    *out = shared;
    seen |= 256;
    return SQLITE_OK;
}
static int unfetch_file(sqlite3_file *file, sqlite3_int64 offset, void *value) {
    CHECK(file->pMethods == &original && offset == 17 && value == shared);
    seen |= 512;
    return SQLITE_IOERR;
}
static int open_file(sqlite3_vfs *vfs, const char *name, sqlite3_file *file, int flags, int *out) {
    CHECK(vfs == &parent && name == expected_name && flags == (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READWRITE));
    CHECK(errno == EACCES);
    file->pMethods = open_has_methods ? &original : 0;
    *out = SQLITE_OPEN_READONLY;
    errno = EIO;
    return open_result;
}
static int delete_file(sqlite3_vfs *vfs, const char *name, int sync_dir) {
    CHECK(vfs == &parent && name == expected_name && sync_dir == 1);
    return SQLITE_IOERR_DELETE;
}
static int access_file(sqlite3_vfs *vfs, const char *name, int flags, int *out) {
    CHECK(vfs == &parent && name == expected_name && flags == 7);
    *out = 1;
    return SQLITE_IOERR_ACCESS;
}
static int full_path(sqlite3_vfs *vfs, const char *name, int size, char *out) {
    CHECK(vfs == &parent && name == expected_name && size == 8);
    memcpy(out, "path", 5);
    return SQLITE_CANTOPEN;
}
static int random_bytes(sqlite3_vfs *vfs, int size, char *out) {
    CHECK(vfs == &parent && size == 8);
    memcpy(out, "random", 7);
    return 7;
}
static int sleep_us(sqlite3_vfs *vfs, int micros) { CHECK(vfs == &parent && micros == 17); return 19; }
static int current_time(sqlite3_vfs *vfs, double *out) { CHECK(vfs == &parent); *out = 3.5; return SQLITE_OK; }
static int last_error(sqlite3_vfs *vfs, int size, char *out) {
    CHECK(vfs == &parent && size == 8);
    memcpy(out, "error", 6);
    return 71;
}
static int current_int64(sqlite3_vfs *vfs, sqlite3_int64 *out) { CHECK(vfs == &parent); *out = 42; return SQLITE_OK; }


static void callback_token(void) {}
static void *dl_open(sqlite3_vfs *vfs, const char *name) {
    CHECK(vfs == &parent && name == expected_name);
    return &token;
}
static void dl_error(sqlite3_vfs *vfs, int size, char *out) {
    CHECK(vfs == &parent && size == 8);
    memcpy(out, "dlerror", 8);
}
static void (*dl_symbol(sqlite3_vfs *vfs, void *handle, const char *name))(void) {
    CHECK(vfs == &parent && handle == &token && name == expected_name);
    return callback_token;
}
static void dl_close(sqlite3_vfs *vfs, void *handle) { CHECK(vfs == &parent && handle == &token); }
static int set_call(sqlite3_vfs *vfs, const char *name, sqlite3_syscall_ptr call) {
    CHECK(vfs == &parent && name == expected_name && call == callback_token);
    return SQLITE_NOTFOUND;
}
static sqlite3_syscall_ptr get_call(sqlite3_vfs *vfs, const char *name) {
    CHECK(vfs == &parent && name == expected_name);
    return callback_token;
}
static const char *next_call(sqlite3_vfs *vfs, const char *name) {
    CHECK(vfs == &parent && name == expected_name);
    return expected_name;
}

static void init(GuardVfs *owner) {
    memset(owner, 0, sizeof(*owner));
    memset(&original, 0, sizeof(original));
    original.iVersion = version;
    original.xClose = closed;
    original.xRead = read_file;
    original.xWrite = write_file;
    original.xTruncate = truncate_file;
    original.xSync = sync_file;
    original.xFileSize = file_size;
    original.xLock = lock_file;
    original.xUnlock = unlock_file;
    original.xCheckReservedLock = reserved;
    original.xFileControl = file_control;
    original.xSectorSize = sector;
    original.xDeviceCharacteristics = characteristics;
    original.xShmMap = shm_map;
    original.xShmLock = shm_lock;
    original.xShmBarrier = barrier;
    original.xShmUnmap = shm_unmap;
    original.xFetch = optional_methods ? fetch_file : 0;
    original.xUnfetch = optional_methods ? unfetch_file : 0;
    memset(&parent, 0, sizeof(parent));
    parent.iVersion = 3;
    parent.szOsFile = sizeof(sqlite3_file);
    parent.mxPathname = 512;
    parent.xOpen = open_file;
    parent.xDelete = delete_file;
    parent.xAccess = access_file;
    parent.xFullPathname = full_path;
    parent.xRandomness = random_bytes;
    parent.xSleep = sleep_us;
    parent.xCurrentTime = current_time;
    parent.xGetLastError = last_error;
    parent.xCurrentTimeInt64 = current_int64;
    parent.xDlOpen = dl_open;
    parent.xDlError = dl_error;
    parent.xDlSym = dl_symbol;
    parent.xDlClose = dl_close;
    parent.xSetSystemCall = set_call;
    parent.xGetSystemCall = get_call;
    parent.xNextSystemCall = next_call;
    owner->original = &parent;
    owner->registered = 1;
    owner->database = "/owned.db";
    guard_vfs_methods(owner);
}
static GuardFile *opened(GuardVfs *owner, int expected_result) {
    GuardFile *file = calloc(1, (size_t)owner->base.szOsFile);
    CHECK(file);
    int out = 0;
    errno = EACCES;
    int result = owner->base.xOpen(&owner->base, expected_name, &file->base,
        SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READWRITE, &out);
    CHECK(result == expected_result && out == SQLITE_OPEN_READONLY && errno == EIO);
    return file;
}
static void *other_thread(void *pointer) {
    sqlite3_file *file = pointer;
    CHECK(file->pMethods->xSync(file, SQLITE_SYNC_FULL | SQLITE_SYNC_DATAONLY) == SQLITE_IOERR_FSYNC);
    CHECK(errno == EIO);
    return 0;
}
static void test_forward(void) {
    GuardVfs owner;
    init(&owner);
    GuardFile *file = opened(&owner, SQLITE_OK);
    const sqlite3_io_methods *methods = file->base.pMethods;
    CHECK(methods && methods->iVersion == version && owner.active == 1);
    unsigned char buffer[8];
    memset(buffer, 0xcc, sizeof(buffer));
    expected_buffer = buffer;
    CHECK(methods->xRead(&file->base, buffer, 8, 17) == SQLITE_IOERR_SHORT_READ);
    CHECK(errno == EIO && memcmp(buffer, "abcd\0\0\0\0", 8) == 0);
    memcpy(buffer, "abcdefgh", 8);
    CHECK(methods->xWrite(&file->base, buffer, 8, 17) == SQLITE_IOERR_WRITE);
    CHECK(errno == ENOSPC && memcmp(effects, "abcd\0\0\0\0", 8) == 0);
    CHECK(methods->xSync(&file->base, SQLITE_SYNC_FULL | SQLITE_SYNC_DATAONLY) == SQLITE_IOERR_FSYNC);
    CHECK(errno == EIO);
    CHECK(methods->xTruncate(&file->base, 17) == SQLITE_FULL && errno == EFBIG);
    sqlite3_int64 size = 0;
    CHECK(methods->xFileSize(&file->base, &size) == SQLITE_IOERR_FSTAT && size == 73 && errno == EIO);
    CHECK(methods->xLock(&file->base, 3) == SQLITE_BUSY);
    CHECK(methods->xUnlock(&file->base, 1) == SQLITE_IOERR_UNLOCK);
    CHECK(methods->xCheckReservedLock(&file->base, &token) == SQLITE_OK && token == 1);
    CHECK(methods->xFileControl(&file->base, 1234, &token) == SQLITE_NOTFOUND && token == 29);
    CHECK(methods->xSectorSize(&file->base) == 4096);
    CHECK(methods->xDeviceCharacteristics(&file->base) == SQLITE_IOCAP_SAFE_APPEND);
    if (version >= 2) {
        void volatile *shm = 0;
        CHECK(methods->xShmMap(&file->base, 2, 16, 1, &shm) == SQLITE_IOERR_SHMMAP && shm == shared);
        CHECK(methods->xShmLock(&file->base, 2, 3, 7) == SQLITE_BUSY);
        methods->xShmBarrier(&file->base);
        CHECK(methods->xShmUnmap(&file->base, 1) == SQLITE_IOERR_SHMOPEN);
    } else CHECK(!methods->xShmMap && !methods->xShmBarrier);
    if (version >= 3 && optional_methods) {
        void *mapped = 0;
        CHECK(methods->xFetch(&file->base, 17, 8, &mapped) == SQLITE_OK && mapped == shared);
        CHECK(methods->xUnfetch(&file->base, 17, mapped) == SQLITE_IOERR);
    } else CHECK(!methods->xFetch && !methods->xUnfetch);
    CHECK(seen == (version == 1 ? 15 : version == 2 || !optional_methods ? 255 : 1023));
    sqlite3_int64 *cell = owner.values[GUARD_WRITER][GUARD_MAIN];
    CHECK(cell[G_WRITE_REQUESTED] == 8 && cell[G_WRITE_OK_BYTES] == 0);
    CHECK(cell[G_WRITE_ERROR] == 1 && cell[G_WRITE_ERROR_REQUESTED] == 8);
    CHECK(cell[G_READ_ERROR] == 1 && cell[G_READ_OK_BYTES] == 0);
    CHECK(cell[G_SYNC_FULL] == 1 && cell[G_SYNC_DATAONLY] == 1 && cell[G_SYNC_ERROR] == 1);
    CHECK(methods->xClose(&file->base) == SQLITE_IOERR_CLOSE && errno == ENOSPC);
    CHECK(!file->base.pMethods && owner.active == 0 && closes == 1 && cell[G_CLOSE_ERROR] == 1);
    free(file);
}
static void test_vfs(void) {
    GuardVfs owner;
    init(&owner);
    sqlite3_vfs *vfs = &owner.base;
    char buffer[8];
    int out = 0;
    double now = 0;
    sqlite3_int64 wide = 0;
    CHECK(vfs->xDelete(vfs, expected_name, 1) == SQLITE_IOERR_DELETE);
    CHECK(vfs->xAccess(vfs, expected_name, 7, &out) == SQLITE_IOERR_ACCESS && out == 1);
    CHECK(vfs->xFullPathname(vfs, expected_name, 8, buffer) == SQLITE_CANTOPEN && strcmp(buffer, "path") == 0);
    CHECK(vfs->xRandomness(vfs, 8, buffer) == 7 && strcmp(buffer, "random") == 0);
    CHECK(vfs->xSleep(vfs, 17) == 19);
    CHECK(vfs->xCurrentTime(vfs, &now) == SQLITE_OK && now == 3.5);
    CHECK(vfs->xGetLastError(vfs, 8, buffer) == 71 && strcmp(buffer, "error") == 0);
    CHECK(vfs->xCurrentTimeInt64(vfs, &wide) == SQLITE_OK && wide == 42);
    CHECK(vfs->xDlOpen(vfs, expected_name) == &token);
    vfs->xDlError(vfs, 8, buffer);
    CHECK(strcmp(buffer, "dlerror") == 0);
    CHECK(vfs->xDlSym(vfs, &token, expected_name) == callback_token);
    vfs->xDlClose(vfs, &token);
    CHECK(vfs->xSetSystemCall(vfs, expected_name, callback_token) == SQLITE_NOTFOUND);
    CHECK(vfs->xGetSystemCall(vfs, expected_name) == callback_token);
    CHECK(vfs->xNextSystemCall(vfs, expected_name) == expected_name);
    parent.iVersion = 1;
    memset(&owner.base, 0, sizeof(owner.base));
    guard_vfs_methods(&owner);
    CHECK(owner.base.iVersion == 1 && !owner.base.xCurrentTimeInt64 && !owner.base.xGetSystemCall);
    parent.iVersion = 2;
    guard_vfs_methods(&owner);
    CHECK(owner.base.iVersion == 2 && owner.base.xCurrentTimeInt64 && !owner.base.xGetSystemCall);
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    expected_name = "/owned.db";
    if (strcmp(argv[1], "v1") == 0 || strcmp(argv[1], "v2") == 0 || strcmp(argv[1], "v3") == 0) {
        version = argv[1][1] - '0';
        test_forward();
    } else if (strcmp(argv[1], "optional") == 0) {
        optional_methods = 0;
        test_forward();
    } else if (strcmp(argv[1], "vfs") == 0) {
        test_vfs();
    } else {
        GuardVfs owner;
        if (strcmp(argv[1], "failed_open_without_methods") == 0) {
            open_result = SQLITE_CANTOPEN;
            open_has_methods = 0;
        } else if (strcmp(argv[1], "failed_open_with_methods") == 0) open_result = SQLITE_IOERR;
        else if (strcmp(argv[1], "unknown_version") == 0) version = 4;
        init(&owner);
        int expected = version == 4 ? SQLITE_CANTOPEN : open_result;
        GuardFile *file = opened(&owner, expected);
        if (strcmp(argv[1], "failed_open_without_methods") == 0) {
            CHECK(!file->base.pMethods && owner.active == 0 && owner.unsupported == 0 && closes == 0);
        } else if (strcmp(argv[1], "unknown_version") == 0) {
            CHECK(!file->base.pMethods && owner.active == 0 && owner.unsupported == 1 && closes == 1);
        } else {
            if (strcmp(argv[1], "thread") == 0) {
                pthread_t thread;
                CHECK(pthread_create(&thread, 0, other_thread, file) == 0);
                CHECK(pthread_join(thread, 0) == 0);
                CHECK(owner.values[GUARD_WRITER][GUARD_MAIN][G_CROSS_THREAD] == 1);
            } else if (strcmp(argv[1], "saturation") == 0) {
                owner.values[GUARD_WRITER][GUARD_MAIN][G_SYNC] = INT64_MAX;
                file->base.pMethods->xSync(&file->base, SQLITE_SYNC_FULL | SQLITE_SYNC_DATAONLY);
                CHECK(owner.values[GUARD_WRITER][GUARD_MAIN][G_SYNC] == INT64_MAX && owner.saturated);
            } else CHECK(strcmp(argv[1], "failed_open_with_methods") == 0);
            CHECK(file->base.pMethods->xClose(&file->base) == SQLITE_IOERR_CLOSE && closes == 1);
            CHECK(owner.active == 0);
        }
        free(file);
    }
    printf("{\"control\":\"%s\",\"passed\":true,\"scope\":\"portable_callback_fixture\"}\n", argv[1]);
    return 0;
}
