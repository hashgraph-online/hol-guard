/* Trusted Linux initializer for a separately declared Root-created namespace.
 * Not setuid, not a product executable, and not an authorization decision.
 * The outside controller must inspect the blocked process before releasing it.
 * No candidate/product code runs before all identity/capability/FD drops.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void fail(const char *operation) {
    perror(operation);
    _exit(126);
}

static void limit(int resource, rlim_t value) {
    struct rlimit bounds = {value, value};
    if (setrlimit(resource, &bounds) != 0) fail("setrlimit");
}

int main(int argc, char **argv) {
    const uid_t actor = 10004;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct capabilities[2] = {{0}, {0}};
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    unsigned char gate = 0;

    if (argc < 2 || argv[1][0] != '/' || getuid() != 0 || geteuid() != 0 ||
        getgid() != 0 || getegid() != 0 || getpid() != 1) {
        errno = EINVAL;
        fail("private Root PID1 initializer required");
    }
    /* The controller supplies only inherited stdio; close all other authority.
     * No fallback to a guessed descriptor ceiling is permitted. */
    if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0) fail("close_range");
    if (clearenv() != 0 || setenv("PATH", "/usr/bin:/bin", 1) != 0 ||
        setenv("HOME", "/nonexistent", 1) != 0 ||
        setenv("LANG", "C.UTF-8", 1) != 0) fail("clean environment");
    if (chdir("/") != 0) fail("chdir");
    umask(0077);
    limit(RLIMIT_CORE, 0);
    limit(RLIMIT_NOFILE, 512);
    limit(RLIMIT_NPROC, 128);
    limit(RLIMIT_FSIZE, 64U * 1024U * 1024U);
    limit(RLIMIT_AS, 1024U * 1024U * 1024U);
    limit(RLIMIT_CPU, 900);
    if (prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) != 0) fail("clear keepcaps");
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) != 0)
        fail("clear ambient capabilities");
    if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED, 0L, 0L, 0L) != 0)
        fail("lock root exec capability fixup");
    for (int cap = 0; cap < 64; ++cap) {
        if (prctl(PR_CAPBSET_DROP, cap, 0L, 0L, 0L) != 0 && errno != EINVAL)
            fail("drop bounding capabilities");
    }
    if (setgroups(0, NULL) != 0 || setresgid(actor, actor, actor) != 0 ||
        setresuid(actor, actor, actor) != 0) fail("drop all actor identities");
    if (syscall(SYS_capset, &header, capabilities) != 0) fail("clear capabilities");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0 ||
        prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) fail("lock privilege boundary");
    /* Changing credentials clears an inherited parent-death signal. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0L, 0L, 0L) != 0) fail("restore parent lifecycle");
    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_uid != actor || effective_uid != actor || saved_uid != actor ||
        real_gid != actor || effective_gid != actor || saved_gid != actor ||
        getgroups(0, NULL) != 0 || syscall(SYS_capget, &header, capabilities) != 0)
        fail("verify actor identities");
    for (int index = 0; index < 2; ++index) {
        if (capabilities[index].effective || capabilities[index].permitted || capabilities[index].inheritable) {
            errno = EPERM;
            fail("verify empty capability sets");
        }
    }
    for (int cap = 0; cap < 64; ++cap) {
        int present = prctl(PR_CAPBSET_READ, cap, 0L, 0L, 0L);
        if (present > 0 || (present < 0 && errno != EINVAL)) fail("verify empty bounding set");
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1) fail("verify no new privileges");
    /* This ready marker is not an attestation. Root must inspect /proc itself. */
    if (write(STDOUT_FILENO, "HOL_INITIALIZER_READY_V1\n", 25) != 25) fail("ready marker");
    ssize_t count;
    do { count = read(STDIN_FILENO, &gate, 1); } while (count < 0 && errno == EINTR);
    if (count != 1 || gate != 1) {
        errno = ECANCELED;
        fail("controller launch gate");
    }
    int empty = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (empty < 0 || dup2(empty, STDIN_FILENO) < 0) fail("clear gate input");
    if (empty != STDIN_FILENO && close(empty) != 0) fail("close empty input");
    execv(argv[1], &argv[1]);
    fail("exec actor program");
}
