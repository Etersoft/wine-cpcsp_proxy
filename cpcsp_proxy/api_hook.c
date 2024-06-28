/*
 * Copyright 2019 Dmitry Timoshkov (for Etersoft)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpcsp_proxy);

#include <pshpack1.h>
#ifdef __x86_64__
struct jmp
{
    BYTE mov_rax[2];
    void *target;
    BYTE jmp_rax[2];
};
#elif defined(__i386__)
struct jmp
{
    BYTE jmp;
    LONG_PTR target;
};
#endif

struct thunk
{
    BYTE hotpatch[sizeof(struct jmp)];
    struct jmp jmp;
};
#include <poppack.h>

#ifdef __x86_64__
/* pushq %r15; pushq %r14; pushq %r13; pushq %r12; pushq %rsi; pushq %rdi; pushq %rbp; pushq %rbx */
static const BYTE hotpatch2[sizeof(struct jmp)] = { 0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x55,0x53 };
#elif defined(__i386__)
static const BYTE hotpatch1[sizeof(struct jmp)] = { 0x8b,0xff,0x55,0x8b,0xec }; /* mov edi,edi; push ebp; mov ebp,esp; */
static const BYTE hotpatch2[sizeof(struct jmp)] = { 0x55,0x89,0xe5,0x53,0x57 }; /* push ebp; mov ebp,esp; push ebx; push edi */
#endif
static BYTE hotpatch[16];
static size_t size_of_hotpatch;
static HANDLE heap;

void *set_api_hook(LPCSTR libname, LPCSTR apiname, void *hook)
{
    HMODULE hmod;
    DWORD old_prot, dummy;
    struct jmp *entry;
    struct thunk *thunk;

    hmod = GetModuleHandleA(libname);
    if (!hmod) return NULL;

    entry = (void *)GetProcAddress(hmod, apiname);
    if (!entry) return NULL;

#ifdef __x86_64__
    if (memcmp(entry, hotpatch2, sizeof(hotpatch2)) == 0)
    {
        memcpy(hotpatch, hotpatch2, sizeof(hotpatch2));
        size_of_hotpatch = sizeof(hotpatch2);
    }
    else
    {
        BYTE *p = (BYTE *)entry;
        FIXME("got %02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x\n",
              p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11]);
        memcpy(hotpatch, entry, sizeof(struct jmp));
        size_of_hotpatch = sizeof(struct jmp);
    }
#elif defined(__i386__)
    if (memcmp(entry, hotpatch1, sizeof(hotpatch1)) == 0)
    {
        memcpy(hotpatch, hotpatch1, sizeof(hotpatch1));
        size_of_hotpatch = sizeof(hotpatch1);
    }
    else if (memcmp(entry, hotpatch2, sizeof(hotpatch2)) == 0)
    {
        memcpy(hotpatch, hotpatch2, sizeof(hotpatch2));
        size_of_hotpatch = sizeof(hotpatch2);
    }
    else
    {
        BYTE *p = (BYTE *)entry;
        FIXME("got %02x,%02x,%02x,%02x,%02x\n", p[0], p[1], p[2], p[3], p[4]);
        memcpy(hotpatch, entry, sizeof(struct jmp));
        size_of_hotpatch = sizeof(struct jmp);
    }
#endif

    if (!heap)
        heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);

    thunk = (struct thunk *)HeapAlloc(heap, 0, sizeof(*thunk));
    memcpy(&thunk->hotpatch, hotpatch, size_of_hotpatch);
#ifdef __x86_64__
    thunk->jmp.mov_rax[0] = 0x48;
    thunk->jmp.mov_rax[1] = 0xb8;
    thunk->jmp.target = hook;
    thunk->jmp.jmp_rax[0] = 0xff;
    thunk->jmp.jmp_rax[1] = 0xe0;
#elif defined(__i386__)
    thunk->jmp.jmp = 0xe9;
    thunk->jmp.target = (LONG_PTR)entry - (LONG_PTR)&thunk->jmp;
#endif

    FlushInstructionCache(GetCurrentProcess(), entry, sizeof(struct jmp));

    VirtualProtect(entry, 0x1000, PAGE_EXECUTE_READWRITE, &old_prot);
#ifdef __x86_64__
    entry->mov_rax[0] = 0x48;
    entry->mov_rax[1] = 0xb8;
    entry->target = hook;
    entry->jmp_rax[0] = 0xff;
    entry->jmp_rax[1] = 0xe0;
#elif defined(__i386__)
    entry->jmp = 0xe9;
    entry->target = (LONG_PTR)hook - (LONG_PTR)entry - sizeof(struct jmp);
#endif
    VirtualProtect(entry, 0x1000, old_prot, &dummy);

    return thunk;
}

void reset_api_hook(LPCSTR libname, LPCSTR apiname, void *thunk)
{
    HMODULE hmod;
    DWORD old_prot, dummy;
    void *entry;

    hmod = GetModuleHandleA(libname);
    if (!hmod) return;

    entry = (void *)GetProcAddress(hmod, apiname);
    if (!entry) return;

    FlushInstructionCache(GetCurrentProcess(), entry, 5);

    VirtualProtect(entry, 0x1000, PAGE_EXECUTE_READWRITE, &old_prot);
    memcpy(entry, hotpatch, size_of_hotpatch);
    VirtualProtect(entry, 0x1000, old_prot, &dummy);

    HeapFree(heap, 0, thunk);
}
