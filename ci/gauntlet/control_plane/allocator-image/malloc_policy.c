/* Keep the existing two-arena policy when a child sanitizes its environment.
 * This changes allocation reservations only; all kernel limits remain active. */
#define _GNU_SOURCE
#include <malloc.h>
#include <unistd.h>

__attribute__((constructor)) static void initialize_malloc_policy(void) {
    if (mallopt(M_ARENA_MAX, 2) != 1) _exit(70);
}
