/* Each wrapper forwards the original buffer, flags, offset, and return code. */
#include "guard_vfs.h"

sqlite3_file *guard_real(sqlite3_file *file) {
    return (sqlite3_file *)((unsigned char *)file + GUARD_FILE_OFFSET);
}

void guard_add(GuardVfs *owner, sqlite3_int64 *field, sqlite3_int64 amount) {
    if (amount < 0 || *field > INT64_MAX - amount) {
        *field = INT64_MAX;
        owner->saturated = 1;
    } else {
        *field += amount;
    }
}

void guard_measure(GuardFile *file, int metric, sqlite3_int64 amount) {
    int saved = errno;
    GuardVfs *owner = file->owner;
    sqlite3_mutex_enter(owner->mutex);
    guard_add(owner, &owner->values[file->scope][file->role][metric], amount);
    sqlite3_mutex_leave(owner->mutex);
    errno = saved;
}

void guard_touch(GuardFile *file) {
    int saved = errno;
    if (!pthread_equal(file->opening_thread, pthread_self())) {
        guard_measure(file, G_CROSS_THREAD, 1);
    }
    errno = saved;
}

static int io_close(sqlite3_file *base) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    int result = real->pMethods->xClose(real);
    int saved = errno;
    guard_measure(file, G_CLOSE, 1);
    if (result != SQLITE_OK) guard_measure(file, G_CLOSE_ERROR, 1);
    sqlite3_mutex_enter(file->owner->mutex);
    file->owner->active--;
    sqlite3_mutex_leave(file->owner->mutex);
    base->pMethods = 0;
    errno = saved;
    return result;
}

static int io_read(sqlite3_file *base, void *buffer, int amount, sqlite3_int64 offset) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    int result = real->pMethods->xRead(real, buffer, amount, offset);
    int saved = errno;
    guard_measure(file, G_READ, 1);
    guard_measure(file, G_READ_REQUESTED, amount);
    guard_measure(file, result == SQLITE_OK ? G_READ_OK_BYTES : G_READ_ERROR,
                  result == SQLITE_OK ? amount : 1);
    errno = saved;
    return result;
}

static int io_write(sqlite3_file *base, const void *buffer, int amount, sqlite3_int64 offset) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    int result = real->pMethods->xWrite(real, buffer, amount, offset);
    int saved = errno;
    guard_measure(file, G_WRITE, 1);
    guard_measure(file, G_WRITE_REQUESTED, amount);
    if (result == SQLITE_OK) {
        guard_measure(file, G_WRITE_OK_BYTES, amount);
    } else {
        /* A failing xWrite may have written a prefix. Its actual byte count is unknown. */
        guard_measure(file, G_WRITE_ERROR, 1);
        guard_measure(file, G_WRITE_ERROR_REQUESTED, amount);
    }
    errno = saved;
    return result;
}

static int io_sync(sqlite3_file *base, int flags) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    int result = real->pMethods->xSync(real, flags);
    int saved = errno;
    guard_measure(file, G_SYNC, 1);
    if (result != SQLITE_OK) guard_measure(file, G_SYNC_ERROR, 1);
    if ((flags & 0x0f) == SQLITE_SYNC_NORMAL) guard_measure(file, G_SYNC_NORMAL, 1);
    if ((flags & 0x0f) == SQLITE_SYNC_FULL) guard_measure(file, G_SYNC_FULL, 1);
    if (flags & SQLITE_SYNC_DATAONLY) guard_measure(file, G_SYNC_DATAONLY, 1);
    errno = saved;
    return result;
}

static int io_truncate(sqlite3_file *base, sqlite3_int64 size) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    int result = real->pMethods->xTruncate(real, size);
    int saved = errno;
    guard_measure(file, G_TRUNCATE, 1);
    if (result != SQLITE_OK) guard_measure(file, G_TRUNCATE_ERROR, 1);
    errno = saved;
    return result;
}

static int io_fetch(sqlite3_file *base, sqlite3_int64 offset, int amount, void **out) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    int result = real->pMethods->xFetch(real, offset, amount, out);
    int saved = errno;
    guard_measure(file, G_FETCH, 1);
    if (result == SQLITE_OK && *out) guard_measure(file, G_FETCH_MAPPED, 1);
    errno = saved;
    return result;
}

#define FORWARD_INT(name, declaration, arguments) \
    static int io_##name declaration { \
        GuardFile *file = (GuardFile *)base; \
        sqlite3_file *real = guard_real(base); \
        guard_touch(file); \
        return real->pMethods->name arguments; \
    }

FORWARD_INT(xFileSize, (sqlite3_file *base, sqlite3_int64 *size), (real, size))
FORWARD_INT(xLock, (sqlite3_file *base, int level), (real, level))
FORWARD_INT(xUnlock, (sqlite3_file *base, int level), (real, level))
FORWARD_INT(xCheckReservedLock, (sqlite3_file *base, int *out), (real, out))
FORWARD_INT(xFileControl, (sqlite3_file *base, int operation, void *out), (real, operation, out))
FORWARD_INT(xSectorSize, (sqlite3_file *base), (real))
FORWARD_INT(xDeviceCharacteristics, (sqlite3_file *base), (real))
FORWARD_INT(xShmMap, (sqlite3_file *base, int page, int size, int extend, void volatile **out),
            (real, page, size, extend, out))
FORWARD_INT(xShmLock, (sqlite3_file *base, int offset, int count, int flags), (real, offset, count, flags))
FORWARD_INT(xShmUnmap, (sqlite3_file *base, int remove), (real, remove))
FORWARD_INT(xUnfetch, (sqlite3_file *base, sqlite3_int64 offset, void *value), (real, offset, value))

static void io_barrier(sqlite3_file *base) {
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    guard_touch(file);
    real->pMethods->xShmBarrier(real);
}

int guard_methods(GuardFile *file) {
    const sqlite3_io_methods *original = guard_real(&file->base)->pMethods;
    sqlite3_io_methods *out = &file->methods;
    memset(out, 0, sizeof(*out));
    if (original->iVersion < 1 || original->iVersion > 3) return SQLITE_CANTOPEN;
    out->iVersion = original->iVersion;
#define ASSIGN(method, replacement) out->method = original->method ? replacement : 0
    ASSIGN(xClose, io_close);
    ASSIGN(xRead, io_read);
    ASSIGN(xWrite, io_write);
    ASSIGN(xTruncate, io_truncate);
    ASSIGN(xSync, io_sync);
    ASSIGN(xFileSize, io_xFileSize);
    ASSIGN(xLock, io_xLock);
    ASSIGN(xUnlock, io_xUnlock);
    ASSIGN(xCheckReservedLock, io_xCheckReservedLock);
    ASSIGN(xFileControl, io_xFileControl);
    ASSIGN(xSectorSize, io_xSectorSize);
    ASSIGN(xDeviceCharacteristics, io_xDeviceCharacteristics);
    if (original->iVersion >= 2) {
        ASSIGN(xShmMap, io_xShmMap);
        ASSIGN(xShmLock, io_xShmLock);
        ASSIGN(xShmBarrier, io_barrier);
        ASSIGN(xShmUnmap, io_xShmUnmap);
    }
    if (original->iVersion >= 3) {
        ASSIGN(xFetch, io_fetch);
        ASSIGN(xUnfetch, io_xUnfetch);
    }
#undef ASSIGN
    file->base.pMethods = out;
    return SQLITE_OK;
}
