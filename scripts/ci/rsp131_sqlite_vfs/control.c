/* The API table comes from the engine that loads this extension. No -lsqlite3. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include "guard_vfs.h"
SQLITE_EXTENSION_INIT1

#define GUARD_REGISTRATION_LIMIT 16
static pthread_mutex_t registrations_mutex = PTHREAD_MUTEX_INITIALIZER;
static GuardVfs *permanent_contexts[GUARD_REGISTRATION_LIMIT];
static int registration_count;

static const char *scopes[] = {"other", "writer", "readback"};
static const char *roles[] = {"other", "main_database", "wal", "rollback_journal"};
static const char *metrics[] = {
    "vfs_x_open_calls", "vfs_x_open_errors", "vfs_x_close_calls", "vfs_x_close_errors",
    "vfs_x_read_calls", "vfs_x_read_errors", "vfs_x_read_requested_bytes", "vfs_x_read_success_bytes",
    "vfs_x_write_calls", "vfs_x_write_errors", "vfs_x_write_requested_bytes", "vfs_x_write_success_bytes",
    "vfs_x_write_error_requested_bytes", "vfs_x_sync_calls", "vfs_x_sync_errors",
    "vfs_x_sync_normal_calls", "vfs_x_sync_full_calls", "vfs_x_sync_dataonly_calls",
    "vfs_x_truncate_calls", "vfs_x_truncate_errors", "vfs_x_fetch_calls",
    "vfs_x_fetch_mapped_calls", "calls_on_different_thread"
};

static void json_string(sqlite3_str *out, const char *value) {
    sqlite3_str_appendchar(out, 1, '"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            sqlite3_str_appendchar(out, 1, '\\');
            sqlite3_str_appendchar(out, 1, (char)*p);
        } else if (*p < 32) {
            sqlite3_str_appendf(out, "\\u%04x", (unsigned int)*p);
        } else {
            sqlite3_str_appendchar(out, 1, (char)*p);
        }
    }
    sqlite3_str_appendchar(out, 1, '"');
}

static void snapshot(sqlite3_context *context, GuardVfs *owner) {
    sqlite3_str *out = sqlite3_str_new(sqlite3_context_db_handle(context));
    sqlite3_mutex_enter(owner->mutex);
    Dl_info image;
    memset(&image, 0, sizeof(image));
    int identified = dladdr((const void *)(uintptr_t)sqlite3_api->libversion_number, &image);
    sqlite3_str_appendf(out, "{\"schema\":1,\"observer_code_address\":\"0x%llx\","
        "\"sqlite_api_code_address\":\"0x%llx\",\"sqlite_api_image\":",
        (sqlite3_uint64)(uintptr_t)guard_control,
        (sqlite3_uint64)(uintptr_t)sqlite3_api->libversion_number);
    json_string(out, identified && image.dli_fname ? image.dli_fname : "");
    sqlite3_str_appendall(out, ",\"callback_context_retained_until_process_exit\":true,"
        "\"context_registration_limit\":16,\"sqlite_source_id\":");
    json_string(out, sqlite3_sourceid());
    sqlite3_str_appendf(out, ",\"sqlite_version_number\":%d,\"vfs_name\":", sqlite3_libversion_number());
    json_string(out, owner->name);
    sqlite3_str_appendall(out, ",\"parent_vfs_name\":");
    json_string(out, owner->original ? owner->original->zName : "");
    sqlite3_str_appendf(out,
        ",\"registered\":%s,\"default_vfs_unchanged\":%s,\"active_files\":%lld,"
        "\"opening_files\":%lld,\"unsupported_method_versions\":%lld,"
        "\"outside_owned_file_opens\":%lld,\"saturated\":%s,\"cells\":[",
        owner->registered ? "true" : "false",
        owner->original && sqlite3_vfs_find(0) == owner->original ? "true" : "false",
        owner->active, owner->opening, owner->unsupported, owner->outside_owned, owner->saturated ? "true" : "false");
    for (int scope = 0; scope < GUARD_SCOPES; ++scope) {
        for (int role = 0; role < GUARD_ROLES; ++role) {
            if (scope || role) sqlite3_str_appendchar(out, 1, ',');
            sqlite3_str_appendf(out, "{\"scope\":\"%s\",\"file_role\":\"%s\"", scopes[scope], roles[role]);
            for (int metric = 0; metric < GUARD_METRICS; ++metric) {
                sqlite3_str_appendf(out, ",\"%s\":%lld", metrics[metric], owner->values[scope][role][metric]);
            }
            sqlite3_str_appendchar(out, 1, '}');
        }
    }
    sqlite3_str_appendall(out, "]}");
    sqlite3_mutex_leave(owner->mutex);
    char *result = sqlite3_str_finish(out);
    if (!result) sqlite3_result_error_nomem(context);
    else sqlite3_result_text(context, result, -1, sqlite3_free);
}

static int name_valid(const char *name, int bytes) {
    if (bytes < 14 || bytes > 64 || strncmp(name, "guard_rsp131_", 13) != 0) return 0;
    for (int i = 0; i < bytes; ++i) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    return name[bytes] == 0;
}

static int register_vfs(GuardVfs *owner, const char *name, int bytes, const char *database, int path_bytes) {
    if (!database || path_bytes < 2 || path_bytes > 4096 || database[0] != '/' ||
        (int)strlen(database) != path_bytes) return SQLITE_MISUSE;
    if (owner->original || !name_valid(name, bytes) || sqlite3_vfs_find(name)) return SQLITE_MISUSE;
    sqlite3_vfs *original = sqlite3_vfs_find(0);
    if (!original || original->iVersion < 1 || original->iVersion > 3 ||
        original->szOsFile <= 0 || original->szOsFile > INT_MAX - (int)GUARD_FILE_OFFSET ||
        !original->xOpen || !original->xDelete || !original->xAccess || !original->xFullPathname ||
        !original->xRandomness || !original->xSleep || !original->xCurrentTime) {
        return SQLITE_MISUSE;
    }
    owner->database = sqlite3_mprintf("%s", database);
    if (!owner->database) return SQLITE_NOMEM;
    owner->original = original;
    memcpy(owner->name, name, (size_t)bytes + 1);
    guard_vfs_methods(owner);
    pthread_mutex_lock(&registrations_mutex);
    if (registration_count == GUARD_REGISTRATION_LIMIT) {
        pthread_mutex_unlock(&registrations_mutex);
        return SQLITE_MISUSE;
    }
    permanent_contexts[registration_count++] = owner;
    owner->permanent = 1;
    pthread_mutex_unlock(&registrations_mutex);
    owner->registered = 1;
    int result = sqlite3_vfs_register(&owner->base, 0);
    if (result != SQLITE_OK || sqlite3_vfs_find(0) != original) {
        sqlite3_vfs_unregister(&owner->base);
        owner->registered = 0;
        return result == SQLITE_OK ? SQLITE_MISUSE : result;
    }
    return SQLITE_OK;
}

void guard_control(sqlite3_context *context, int argc, sqlite3_value **argv) {
    GuardVfs *owner = sqlite3_user_data(context);
    (void)argc;
    const char *command = (const char *)sqlite3_value_text(argv[0]);
    if (!command || sqlite3_value_bytes(argv[0]) > 16) {
        sqlite3_result_error(context, "invalid observer command", -1);
        return;
    }
    int result = SQLITE_OK;
    if (strcmp(command, "register") == 0) {
        const char *name = (const char *)sqlite3_value_text(argv[1]);
        const char *database = (const char *)sqlite3_value_text(argv[2]);
        result = name ? register_vfs(owner, name, sqlite3_value_bytes(argv[1]),
            database, sqlite3_value_bytes(argv[2])) : SQLITE_MISUSE;
    } else if (strcmp(command, "unregister") == 0) {
        sqlite3_mutex_enter(owner->mutex);
        if (!owner->registered || owner->active || owner->opening) result = SQLITE_BUSY;
        else {
            result = sqlite3_vfs_unregister(&owner->base);
            if (result == SQLITE_OK) owner->registered = 0;
        }
        sqlite3_mutex_leave(owner->mutex);
    } else if (strcmp(command, "snapshot") != 0 || !owner->original) {
        result = SQLITE_MISUSE;
    }
    if (result != SQLITE_OK) {
        sqlite3_result_error(context, "SQLite VFS observer admission or lifecycle refused", -1);
        sqlite3_result_error_code(context, result);
        return;
    }
    snapshot(context, owner);
}

void guard_destroy(void *pointer) {
    GuardVfs *owner = pointer;
    sqlite3_mutex_enter(owner->mutex);
    if (owner->registered) sqlite3_vfs_unregister(&owner->base);
    owner->registered = 0;
    if (owner->permanent) {
        /* xClose may precede later VFS cleanup inside sqlite3_close(). Keep both
         * code and callback data alive. At most 16 contexts are admitted per image. */
        owner->abandoned = owner->active || owner->opening;
        sqlite3_mutex_leave(owner->mutex);
        return;
    }
    sqlite3_mutex_leave(owner->mutex);
    sqlite3_mutex_free(owner->mutex);
    sqlite3_free(owner->database);
    sqlite3_free(owner);
}

__attribute__((visibility("default")))
int sqlite3_guardvfsext_init(sqlite3 *db, char **error, const sqlite3_api_routines *api) {
    (void)error;
    if (sqlite3_api && sqlite3_api != api) return SQLITE_MISUSE;
    SQLITE_EXTENSION_INIT2(api);
    if (sqlite3_libversion_number() < 3031000 || !sqlite3_threadsafe()) return SQLITE_MISUSE;
    GuardVfs *owner = sqlite3_malloc64(sizeof(*owner));
    if (!owner) return SQLITE_NOMEM;
    memset(owner, 0, sizeof(*owner));
    owner->mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
    if (!owner->mutex) {
        sqlite3_free(owner);
        return SQLITE_MISUSE;
    }
    int result = sqlite3_create_function_v2(db, "guard_sqlite_vfs", 3,
        SQLITE_UTF8 | SQLITE_DIRECTONLY, owner, guard_control, 0, 0, guard_destroy);
    /* SQLite calls the destructor if function registration fails. */
    return result == SQLITE_OK ? SQLITE_OK_LOAD_PERMANENTLY : result;
}
