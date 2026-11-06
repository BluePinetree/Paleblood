/* SPDX-License-Identifier: GPL-2.0-or-later */
/* System call group: PlayGo, a title's chunk and install state (libScePlayGo). A system module:
   the runtime provides it (game/modules.csv, action "runtime"), so a load succeeds and these entries
   answer.

   Facts used:
   - The names come from the public OpenOrbis toolchain (lib/libScePlayGo.so), which has no header
     and gives no signatures. The shapes come from the executable's own calls (docs/runtime-syscalls.md):
     scePlayGoInitialize(parameters), the parameters a buffer, its size in bytes and a zero word, the
     result not checked; scePlayGoOpen(int32_t *handle, NULL); scePlayGoGetChunkId(handle, uint16_t
     ids[], capacity, uint32_t *count); scePlayGoSetInstallSpeed(handle, speed) with speed 0, 1 or 2.
   - The caller keeps the count, and asks for each chunk's location (scePlayGoGetLocus) only when it
     is not 0. With no chunks its install state stays at its initial value, the one it also keeps
     when no chunk reports location 0 or 2.
   - The handle's value, the PlayGo error values and what a PS4 lists for a title are not public.

   So the runtime, which serves the whole title from the user's copy (/app0) and tracks no chunks,
   opens one handle and lists no chunks. scePlayGoGetLocus is then never reached and stays unbound.
   The buffer belongs to the caller, which frees it without a terminate call: the runtime keeps
   no pointer to it and never touches it. Any other shape stops by name. */
#include "runtime/process.h"
#include "runtime/syslib.h"

#include <stdint.h>

#define PLAYGO_HANDLE 1 /* the runtime's choice: the caller only passes it back */

typedef struct {
    void *buffer;
    uint32_t size;
    uint32_t reserved;
} playgo_parameters;

static int initialized, opened;

static int32_t initialize(const playgo_parameters *parameters)
{
    static const char fn[] = "scePlayGoInitialize";
    if (!parameters || !parameters->buffer || !parameters->size)
        rt_fatal(fn, "no parameters, buffer or size: the error value is not established");
    if (parameters->reserved) rt_fatal(fn, "a nonzero third word: its meaning is not established");
    if (initialized) rt_fatal(fn, "a second initialization: its answer is not established");
    initialized = 1;
    return 0;
}

static int32_t open_handle(int32_t *handle, const void *parameter)
{
    static const char fn[] = "scePlayGoOpen";
    if (!initialized) rt_fatal(fn, "called before scePlayGoInitialize: the error value is not established");
    if (!handle) rt_fatal(fn, "no variable for the handle: the error value is not established");
    if (parameter) rt_fatal(fn, "a parameter: the executable passes none, and its layout is not established");
    if (opened) rt_fatal(fn, "a second open: its answer is not established");
    opened = 1;
    *handle = PLAYGO_HANDLE;
    return 0;
}

static void check_handle(const char *fn, int32_t handle)
{
    if (!opened || handle != PLAYGO_HANDLE)
        rt_fatal(fn, "a handle scePlayGoOpen did not give: the error value is not established");
}

static int32_t get_chunk_id(int32_t handle, uint16_t *ids, uint32_t capacity, uint32_t *count)
{
    static const char fn[] = "scePlayGoGetChunkId";
    check_handle(fn, handle);
    if (!ids || !capacity) rt_fatal(fn, "no room for ids: the executable always passes some");
    if (!count) rt_fatal(fn, "no variable for the count: the error value is not established");
    *count = 0; /* the runtime tracks no chunks: the whole title is in /app0 */
    return 0;
}

static int32_t set_install_speed(int32_t handle, int32_t speed)
{
    static const char fn[] = "scePlayGoSetInstallSpeed";
    check_handle(fn, handle);
    if (speed < 0 || speed > 2) rt_fatal(fn, "a speed other than 0, 1 or 2: the executable passes only those");
    return 0; /* nothing is being installed */
}

RT_SYSLIB("libScePlayGo", scePlayGoInitialize, initialize);
RT_SYSLIB("libScePlayGo", scePlayGoOpen, open_handle);
RT_SYSLIB("libScePlayGo", scePlayGoGetChunkId, get_chunk_id);
RT_SYSLIB("libScePlayGo", scePlayGoSetInstallSpeed, set_install_speed);
