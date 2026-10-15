/* SPDX-License-Identifier: GPL-2.0-or-later */
/* System call group: kernel, threads and memory. Threads and thread attributes (libkernel,
   libScePosix).

   Facts used: a thread or attribute variable holds a pointer to an object the library allocates
   (FreeBSD libthr, which the PS4's thread library is); the SCE names return 0 or 0x80020000 plus a
   FreeBSD error number, and their POSIX names (libScePosix) return that error number itself. An
   attribute records only what has been set or copied into it; reading a value the runtime does not
   know (one the system would supply) is not implemented, so the boot stops there by name instead of
   guessing. */
#include "runtime/process.h"
#include "runtime/syslib.h"

#include <sched.h>
#include <stdint.h>
#include <stdlib.h>

enum { BSD_ENOMEM = 12, BSD_EINVAL = 22 };
#define SCE_KERNEL_ERROR(e) ((int)(0x80020000u + (unsigned)(e)))

/* PTHREAD_CREATE_JOINABLE and PTHREAD_CREATE_DETACHED in FreeBSD's <pthread.h>. The PS4 homebrew
   SDK's headers (OpenOrbis, include/orbis/_types/pthread.h) give the SCE names the same two values. */
enum { DETACH_JOINABLE = 0, DETACH_DETACHED = 1 };

typedef struct {
    void *stack;
    uint64_t stack_size;
} guest_thread;

typedef struct {
    int has_stack;
    void *stack;
    uint64_t stack_size;
    int has_detach_state;
    int detach_state;
} guest_attr;

static int sce(int bsd) { return bsd ? SCE_KERNEL_ERROR(bsd) : 0; }

static guest_thread main_thread;
static _Thread_local guest_thread *current;

void rt_thread_register_main(void *stack, uint64_t stack_size)
{
    main_thread.stack = stack;
    main_thread.stack_size = stack_size;
    current = &main_thread;
}

static guest_thread *thread_self(void)
{
    if (!current) rt_fatal("scePthreadSelf", "no guest thread registered on this host thread");
    return current;
}

/* Two thread variables name the same thread when they hold the same object pointer. Non-zero when
   equal, zero otherwise, with no error return (FreeBSD pthread_equal(3)). */
static int thread_equal(guest_thread *a, guest_thread *b)
{
    return a == b;
}

/* sched_yield: the calling thread gives up the processor and the call returns 0 (POSIX and FreeBSD
   sched_yield(2), which define no error for it). A guest thread runs on a host thread, so the
   host's yield is the same request. A host failure has no FreeBSD error number we could report, so
   it stops by name instead. */
static int kernel_sched_yield(void)
{
    if (sched_yield() != 0) rt_fatal("sched_yield", "the host did not yield the processor");
    return 0;
}

/* scePthreadYield asks for the same yield, but its PS4-visible signature is not established:
   FreeBSD's pthread_yield(3) returns nothing, Linux's returns an int, and no PS4-specific public
   source or guest call site we can cite says which one the guest sees. Returning would leave the
   value a caller might read undefined, so the call stops by name. It is registered with
   RT_SYSLIB_UNRESOLVED: a boot that reaches it names the call, and coverage leaves the import
   unchecked, since a diagnostic is not an implementation. */
static void thread_yield(void)
{
    rt_fatal("scePthreadYield", "the PS4 return behaviour is not established by public evidence");
}

static int attr_init(guest_attr **attr)
{
    if (!attr) return SCE_KERNEL_ERROR(BSD_EINVAL);
    guest_attr *a = calloc(1, sizeof *a);
    if (!a) return SCE_KERNEL_ERROR(BSD_ENOMEM);
    *attr = a;
    return 0;
}

static int attr_destroy(guest_attr **attr)
{
    if (!attr || !*attr) return SCE_KERNEL_ERROR(BSD_EINVAL);
    free(*attr);
    *attr = NULL;
    return 0;
}

/* Copies a running thread's attributes into an initialised attribute object. The copy replaces
   what the object held, so a detach state set on it before is dropped: the thread's own detach
   state is one the system supplies, and the runtime does not know it. */
static int attr_get(guest_thread *thread, guest_attr **attr)
{
    if (!thread || !attr || !*attr) return SCE_KERNEL_ERROR(BSD_EINVAL);
    (*attr)->has_stack = 1;
    (*attr)->stack = thread->stack;
    (*attr)->stack_size = thread->stack_size;
    (*attr)->has_detach_state = 0;
    return 0;
}

/* Whether a thread created with the attribute starts detached or joinable. Any other value, or an
   attribute variable that holds no object, is EINVAL (FreeBSD pthread_attr_setdetachstate(3)). */
static int attr_set_detach_state(guest_attr **attr, int state)
{
    if (!attr || !*attr || (state != DETACH_JOINABLE && state != DETACH_DETACHED)) return BSD_EINVAL;
    (*attr)->has_detach_state = 1;
    (*attr)->detach_state = state;
    return 0;
}

static int sce_attr_set_detach_state(guest_attr **attr, int state) { return sce(attr_set_detach_state(attr, state)); }

RT_SYSLIB("libkernel", scePthreadSelf, thread_self);
RT_SYSLIB("libkernel", scePthreadEqual, thread_equal);
RT_SYSLIB("libkernel", sched_yield, kernel_sched_yield);
RT_SYSLIB_UNRESOLVED("libkernel", scePthreadYield, thread_yield);
RT_SYSLIB("libkernel", scePthreadAttrInit, attr_init);
RT_SYSLIB("libkernel", scePthreadAttrDestroy, attr_destroy);
RT_SYSLIB("libkernel", scePthreadAttrGet, attr_get);
RT_SYSLIB("libkernel", scePthreadAttrSetdetachstate, sce_attr_set_detach_state);
RT_SYSLIB("libScePosix", pthread_attr_setdetachstate, attr_set_detach_state);
