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

#include <pshpack1.h>
struct jmp
{
    BYTE jmp;
    LONG_PTR api;
};

struct thunk
{
    BYTE hotpatch[5];
    struct jmp jmp;
};
#include <poppack.h>

static const BYTE hotpatch[5] = { 0x8b,0xff,0x55,0x8b,0xec }; /* mov edi,edi; push ebp; mov ebp,esp; */
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

    if (memcmp(entry, hotpatch, sizeof(hotpatch)) != 0)
        return NULL;

    if (!heap)
        heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);

    thunk = (struct thunk *)HeapAlloc(heap, 0, sizeof(*thunk));
    memcpy(&thunk->hotpatch, hotpatch, sizeof(hotpatch));
    thunk->jmp.jmp = 0xe9;
    thunk->jmp.api = (LONG_PTR)entry - (LONG_PTR)&thunk->jmp;

    FlushInstructionCache(GetCurrentProcess(), entry, 5);

    VirtualProtect(entry, 0x1000, PAGE_EXECUTE_READWRITE, &old_prot);
    entry->jmp = 0xe9;
    entry->api = (LONG_PTR)hook - (LONG_PTR)entry - 5;
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
    memcpy(entry, hotpatch, sizeof(hotpatch));
    VirtualProtect(entry, 0x1000, old_prot, &dummy);

    HeapFree(heap, 0, thunk);
}
