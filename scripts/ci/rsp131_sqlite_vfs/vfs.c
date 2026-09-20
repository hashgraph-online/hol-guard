/* Named, non-default VFS. All original VFS callbacks receive their original VFS. */
#include "guard_vfs.h"

static GuardVfs *owner_of(sqlite3_vfs *vfs) {
    return (GuardVfs *)vfs->pAppData;
}

int guard_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *base, int flags, int *out) {
    GuardVfs *owner = owner_of(vfs);
    GuardFile *file = (GuardFile *)base;
    sqlite3_file *real = guard_real(base);
    int incoming = errno;
    memset(file, 0, sizeof(*file));
    memset(real, 0, (size_t)owner->original->szOsFile);
    file->owner = owner;
    file->opening_thread = pthread_self();
    if (flags & SQLITE_OPEN_MAIN_DB) file->role = GUARD_MAIN;
    else if (flags & SQLITE_OPEN_WAL) file->role = GUARD_WAL;
    else if (flags & SQLITE_OPEN_MAIN_JOURNAL) file->role = GUARD_JOURNAL;
    int outside_owned = 0;
    if (name && file->role != GUARD_AUX) {
        const char *database = sqlite3_filename_database(name);
        outside_owned = !database || strcmp(database, owner->database) != 0;
        /* SQLite >= 3.31 supplies associated URI parameters for WAL/journal names. */
        const char *scope = sqlite3_uri_parameter(name, "guard_scope");
        if (scope && strcmp(scope, "writer") == 0) file->scope = GUARD_WRITER;
        else if (scope && strcmp(scope, "readback") == 0) file->scope = GUARD_READBACK;
    }
    if (outside_owned) {
        file->scope = GUARD_OTHER;
        file->role = GUARD_AUX;
    }
    sqlite3_mutex_enter(owner->mutex);
    if (!owner->registered) {
        sqlite3_mutex_leave(owner->mutex);
        errno = incoming;
        return SQLITE_CANTOPEN;
    }
    owner->opening++;
    if (outside_owned) guard_add(owner, &owner->outside_owned, 1);
    sqlite3_mutex_leave(owner->mutex);
    errno = incoming;
    int result = owner->original->xOpen(owner->original, name, real, flags, out);
    int saved = errno;
    int wrapped = 0;
    int unsupported = 0;
    if (real->pMethods) {
        wrapped = guard_methods(file) == SQLITE_OK;
        if (!wrapped) {
            unsupported = 1;
            /* Unsupported method versions are a refused diagnostic host, not coverage. */
            if (real->pMethods->xClose) real->pMethods->xClose(real);
            real->pMethods = 0;
            if (result == SQLITE_OK) result = SQLITE_CANTOPEN;
        }
    }
    if (result == SQLITE_OK && !wrapped) {
        unsupported = 1;
        result = SQLITE_CANTOPEN;
    }
    guard_measure(file, G_OPEN, 1);
    if (result != SQLITE_OK) guard_measure(file, G_OPEN_ERROR, 1);
    sqlite3_mutex_enter(owner->mutex);
    owner->opening--;
    if (wrapped) owner->active++;
    if (unsupported) owner->unsupported++;
    sqlite3_mutex_leave(owner->mutex);
    errno = saved;
    return result;
}

#define VFS_INT(method, declaration, arguments) \
    static int vfs_##method declaration { \
        sqlite3_vfs *original = owner_of(vfs)->original; \
        return original->method arguments; \
    }
VFS_INT(xDelete, (sqlite3_vfs *vfs, const char *name, int sync_dir), (original, name, sync_dir))
VFS_INT(xAccess, (sqlite3_vfs *vfs, const char *name, int flags, int *out), (original, name, flags, out))
VFS_INT(xFullPathname, (sqlite3_vfs *vfs, const char *name, int size, char *out),
        (original, name, size, out))
VFS_INT(xRandomness, (sqlite3_vfs *vfs, int size, char *out), (original, size, out))
VFS_INT(xSleep, (sqlite3_vfs *vfs, int microseconds), (original, microseconds))
VFS_INT(xCurrentTime, (sqlite3_vfs *vfs, double *out), (original, out))
VFS_INT(xGetLastError, (sqlite3_vfs *vfs, int size, char *out), (original, size, out))
VFS_INT(xCurrentTimeInt64, (sqlite3_vfs *vfs, sqlite3_int64 *out), (original, out))
VFS_INT(xSetSystemCall, (sqlite3_vfs *vfs, const char *name, sqlite3_syscall_ptr call),
        (original, name, call))

static void *vfs_dlopen(sqlite3_vfs *vfs, const char *name) {
    sqlite3_vfs *original = owner_of(vfs)->original;
    return original->xDlOpen(original, name);
}
static void vfs_dlerror(sqlite3_vfs *vfs, int size, char *out) {
    sqlite3_vfs *original = owner_of(vfs)->original;
    original->xDlError(original, size, out);
}
static void (*vfs_dlsym(sqlite3_vfs *vfs, void *handle, const char *name))(void) {
    sqlite3_vfs *original = owner_of(vfs)->original;
    return original->xDlSym(original, handle, name);
}
static void vfs_dlclose(sqlite3_vfs *vfs, void *handle) {
    sqlite3_vfs *original = owner_of(vfs)->original;
    original->xDlClose(original, handle);
}
static sqlite3_syscall_ptr vfs_getsystemcall(sqlite3_vfs *vfs, const char *name) {
    sqlite3_vfs *original = owner_of(vfs)->original;
    return original->xGetSystemCall(original, name);
}
static const char *vfs_nextsystemcall(sqlite3_vfs *vfs, const char *name) {
    sqlite3_vfs *original = owner_of(vfs)->original;
    return original->xNextSystemCall(original, name);
}

void guard_vfs_methods(GuardVfs *owner) {
    sqlite3_vfs *out = &owner->base;
    sqlite3_vfs *original = owner->original;
    out->iVersion = original->iVersion;
    out->szOsFile = (int)GUARD_FILE_OFFSET + original->szOsFile;
    out->mxPathname = original->mxPathname;
    out->zName = owner->name;
    out->pAppData = owner;
    out->xOpen = guard_open;
#define ASSIGN(method, replacement) out->method = original->method ? replacement : 0
    ASSIGN(xDelete, vfs_xDelete);
    ASSIGN(xAccess, vfs_xAccess);
    ASSIGN(xFullPathname, vfs_xFullPathname);
    ASSIGN(xDlOpen, vfs_dlopen);
    ASSIGN(xDlError, vfs_dlerror);
    ASSIGN(xDlSym, vfs_dlsym);
    ASSIGN(xDlClose, vfs_dlclose);
    ASSIGN(xRandomness, vfs_xRandomness);
    ASSIGN(xSleep, vfs_xSleep);
    ASSIGN(xCurrentTime, vfs_xCurrentTime);
    ASSIGN(xGetLastError, vfs_xGetLastError);
    if (original->iVersion >= 2) ASSIGN(xCurrentTimeInt64, vfs_xCurrentTimeInt64);
    if (original->iVersion >= 3) {
        ASSIGN(xSetSystemCall, vfs_xSetSystemCall);
        ASSIGN(xGetSystemCall, vfs_getsystemcall);
        ASSIGN(xNextSystemCall, vfs_nextsystemcall);
    }
#undef ASSIGN
}
