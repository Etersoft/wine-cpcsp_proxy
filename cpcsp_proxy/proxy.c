/*
 * Copyright 2018 Dmitry Timoshkov (for Etersoft)
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
 *
 * Install with any of the below commands:
 * $ rundll32 cpcsp_proxy.dll,Install
 * $ regsvr32 cpcsp_proxy.dll
 * $ regsvr32 /i cpcsp_proxy.dll
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "wincrypt.h"
#include "winternl.h"
#include "winnls.h"
#include "wine/debug.h"

#include "api_hook.h"
#include "unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpcsp_proxy);

void WINAPI Install(HWND hwnd, HINSTANCE hinst, void *cmdline, int showcmd);

static HCRYPTPROV hprov_def;
static HCRYPTPROV (WINAPI *orig_I_CryptGetDefaultCryptProv)(ALG_ID);

static NTSTATUS proxy_call(const char *name, UINT func, void *params)
{
    NTSTATUS status;

    TRACE("CALL %s: %s,%u,%p)\n", name, wine_dbgstr_longlong(__wine_unixlib_handle), func, params);
    status = WINE_UNIX_CALL(func, params);
    TRACE("RET: %08x%s\n", status, status ? " (FAILED)" : "");
    return status;
}

static void set_default_hprov(void)
{
    DWORD size;
    struct GetDefaultProviderA_params params = { 80, NULL, CRYPT_USER_DEFAULT, NULL, &size };

    if (!PROXY_CALL(GetDefaultProviderA, &params))
    {
        params.prov_name = malloc(size);
        if (params.prov_name && !PROXY_CALL(GetDefaultProviderA, &params))
        {
            TRACE("CryptGetDefaultProviderA => %s\n", debugstr_a(params.prov_name));
            if (!CryptAcquireContextA(&hprov_def, NULL, params.prov_name, params.type, CRYPT_VERIFYCONTEXT))
                ERR("CryptAcquireContextA(%s) error %#x\n", debugstr_a(params.prov_name), GetLastError());
            else
                TRACE("hprov_def => %#x\n", hprov_def);
        }
        free(params.prov_name);
    }
}

static HCRYPTPROV WINAPI hook_I_CryptGetDefaultCryptProv(ALG_ID algid)
{
    TRACE("%#x\n", algid);

    if (hprov_def)
    {
        CryptContextAddRef(hprov_def, NULL, 0);
        return hprov_def;
    }

    return orig_I_CryptGetDefaultCryptProv ? orig_I_CryptGetDefaultCryptProv(algid) : 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    TRACE("%p,%u,%p\n", hinst, reason, reserved);

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        if (__wine_init_unix_call() || PROXY_CALL(attach, NULL))
        {
            ERR("proxy failed to initialize\n");
            return FALSE;
        }

        Install(0, NULL, NULL, 0);

        set_default_hprov();
        orig_I_CryptGetDefaultCryptProv = set_api_hook("crypt32.dll", "I_CryptGetDefaultCryptProv", hook_I_CryptGetDefaultCryptProv);
        TRACE("orig_I_CryptGetDefaultCryptProv => %p\n", orig_I_CryptGetDefaultCryptProv);

        DisableThreadLibraryCalls(hinst);
        /* Avoid loading/unloading proxy */
        LoadLibraryA("cpcsp_proxy.dll");
        break;

    case DLL_PROCESS_DETACH:
        reset_api_hook("crypt32.dll", "I_CryptGetDefaultCryptProv", orig_I_CryptGetDefaultCryptProv);
        break;
    }
    return TRUE;
}

struct context_handle
{
    UINT64 handle;
};

static ULONG_PTR create_context_handle(UINT64 handle)
{
    struct context_handle *ctx = malloc(sizeof(*ctx));
    if (!ctx)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return 0;
    }
    ctx->handle = handle;
    return (ULONG_PTR)ctx;
}

BOOL WINAPI CPAcquireContext(HCRYPTPROV *prov, LPSTR container, DWORD flags, VTableProvStruc *vt)
{
    UINT64 h64 = 0;
    struct AcquireContext_params params = { &h64, container, flags, vt };
    DWORD err;

    TRACE("%p,%s,%s,%u,%08x\n", prov, debugstr_a(container), debugstr_a(vt->pszProvName), vt->dwProvType, flags);

    err = PROXY_CALL(CPAcquireContext, &params);
    if (err) SetLastError(err);
    else *prov = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPReleaseContext(HCRYPTPROV hprov, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct ReleaseContext_params params = { prov->handle, flags };
    DWORD err;

    TRACE("%08lx,%08x)\n", hprov, flags);

    err = PROXY_CALL(CPReleaseContext, &params);
    if (err) SetLastError(err);
    else free(prov);

    return !err;
}

BOOL WINAPI CPSetProvParam(HCRYPTPROV hprov, DWORD param, BYTE *data, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct SetProvParam_params params = { prov->handle, param, data, flags };
    DWORD err;

    TRACE("%08lx,%08x,%p,%08x)\n", hprov, param, data, flags);

    err = PROXY_CALL(CPSetProvParam, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPGetProvParam(HCRYPTPROV hprov, DWORD param, BYTE *data, DWORD *len, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct GetProvParam_params params = { prov->handle, param, data, len, flags };
    DWORD err;

    TRACE("%08lx,%08x,%p,%p,%08x)\n", hprov, param, data, len, flags);

    err = PROXY_CALL(CPGetProvParam, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPCreateHash(HCRYPTPROV hprov, ALG_ID algid, HCRYPTKEY hkey,
                         DWORD flags, HCRYPTHASH *hhash)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct CreateHash_params params = { prov->handle, algid, key ? key->handle : 0, flags, &h64 };
    DWORD err;

    TRACE("%08lx,%08x,%08lx,%08x,%p\n", hprov, algid, hkey, flags, hhash);

    err = PROXY_CALL(CPCreateHash, &params);
    if (err) SetLastError(err);
    else *hhash = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPDestroyHash(HCRYPTPROV hprov, HCRYPTHASH hhash)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct DestroyHash_params params = { prov->handle, hash->handle };
    DWORD err;

    TRACE("%08lx,%08lx\n", hprov, hhash);

    err = PROXY_CALL(CPDestroyHash, &params);
    if (err) SetLastError(err);
    else free(hash);

    return !err;
}

BOOL WINAPI CPDuplicateHash(HCRYPTPROV hprov, HCRYPTHASH hhash, DWORD *reserved,
                            DWORD flags, HCRYPTHASH *newhash)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct DuplicateHash_params params = { prov->handle, hash->handle, reserved, flags, &h64 };
    DWORD err;

    TRACE("%08lx,%08lx,%p,%08x,%p)\n", hprov, hhash, reserved, flags, newhash);

    err = PROXY_CALL(CPDuplicateHash, &params);
    if (err) SetLastError(err);
    else *newhash = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPSetHashParam(HCRYPTPROV hprov, HCRYPTHASH hhash, DWORD param,
                           BYTE *data, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct SetHashParam_params params = { prov->handle, hash->handle, param, data, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%08x,%p,%08x\n", hprov, hhash, param, data, flags);

    err = PROXY_CALL(CPSetHashParam, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPGetHashParam(HCRYPTPROV hprov, HCRYPTHASH hhash, DWORD param, BYTE *data,
                           DWORD *len, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct GetHashParam_params params = { prov->handle, hash->handle, param, data, len, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%08x,%p,%p,%08x\n", hprov, hhash, param, data, len, flags);

    err = PROXY_CALL(CPGetHashParam, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPGenKey(HCRYPTPROV hprov, ALG_ID algid, DWORD flags, HCRYPTKEY *hkey)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct GenKey_params params = { prov->handle, algid, flags, &h64 };
    DWORD err;

    TRACE("%08lx,%08x,%08x,%p\n", hprov, algid, flags, hkey);

    err = PROXY_CALL(CPGenKey, &params);
    if (err) SetLastError(err);
    else *hkey = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPGetUserKey(HCRYPTPROV hprov, DWORD keyspec, HCRYPTKEY *hkey)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct GetUserKey_params params = { prov->handle, keyspec, &h64 };
    DWORD err;

    TRACE("%08lx,%08x,%p)\n", hprov, keyspec, hkey);

    err = PROXY_CALL(CPGetUserKey, &params);
    if (err) SetLastError(err);
    else *hkey = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPExportKey(HCRYPTPROV hprov, HCRYPTKEY hkey, HCRYPTKEY hpubkey,
                        DWORD type, DWORD flags, BYTE *data, DWORD *len)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct context_handle *pubkey = (struct context_handle *)hpubkey;
    struct ExportKey_params params = { prov->handle, key ? key->handle : 0, pubkey ? pubkey->handle : 0, type, flags, data, len };
    DWORD err;

    TRACE("%08lx,%08lx,%08lx,%08x,%08x,%p,%p\n", hprov, hkey, hpubkey, type, flags, data, len);

    err = PROXY_CALL(CPExportKey, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPImportKey(HCRYPTPROV hprov, const BYTE *data, DWORD len,
                        HCRYPTKEY hpubkey, DWORD flags, HCRYPTKEY *hkey)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *pubkey = (struct context_handle *)hpubkey;
    struct ImportKey_params params = { prov->handle, data, len, pubkey ? pubkey->handle : 0, flags, &h64 };
    DWORD err;

    TRACE("%08lx,%p,%u,%08lx,%08x,%p\n", hprov, data, len, hpubkey, flags, hkey);

    err = PROXY_CALL(CPImportKey, &params);
    if (err) SetLastError(err);
    else *hkey = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPDestroyKey(HCRYPTPROV hprov, HCRYPTKEY hkey)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct DestroyKey_params params = { prov->handle, key->handle };
    DWORD err;

    TRACE("%08lx,%08lx)\n", hprov, hkey);

    err = PROXY_CALL(CPDestroyKey, &params);
    if (err) SetLastError(err);
    else free(key);

    return !err;
}

BOOL WINAPI CPDuplicateKey(HCRYPTPROV hprov, HCRYPTKEY hkey, DWORD *reserved,
                           DWORD flags, HCRYPTKEY *newkey)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct DuplicateKey_params params = { prov->handle, key->handle, reserved, flags, &h64 };
    DWORD err;

    TRACE("%08lx,%08lx,%p,%08x,%p\n", hprov, hkey, reserved, flags, newkey);

    err = PROXY_CALL(CPDuplicateKey, &params);
    if (err) SetLastError(err);
    else *newkey = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPSetKeyParam(HCRYPTPROV hprov, HCRYPTKEY hkey, DWORD param, BYTE *data, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct SetKeyParam_params params = { prov->handle, key->handle, param, data, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%08x,%p,%08x)\n", hprov, hkey, param, data, flags);

    err = PROXY_CALL(CPSetKeyParam, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPGetKeyParam(HCRYPTPROV hprov, HCRYPTKEY hkey, DWORD param, BYTE *data,
                          DWORD *len, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct GetKeyParam_params params = { prov->handle, key->handle, param, data, len, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%08x,%p,%p,%08x)\n", hprov, hkey, param, data, len, flags);

    err = PROXY_CALL(CPGetKeyParam, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPDeriveKey(HCRYPTPROV hprov, ALG_ID algid, HCRYPTHASH hhash,
                        DWORD flags, HCRYPTKEY *hkey)
{
    UINT64 h64 = 0;
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct DeriveKey_params params = { prov->handle, algid, hash->handle, flags, &h64 };
    DWORD err;

    TRACE("%08lx,%08x,%08lx,%08x,%p\n", hprov, algid, hhash, flags, hkey);

    err = PROXY_CALL(CPDeriveKey, &params);
    if (err) SetLastError(err);
    else *hkey = create_context_handle(h64);

    return !err;
}

BOOL WINAPI CPGenRandom(HCRYPTPROV hprov, DWORD len, BYTE *buffer)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct GenRandom_params params = { prov->handle, len, buffer };
    DWORD err;

    TRACE("%08lx,%u,%p)\n", hprov, len, buffer);

    err = PROXY_CALL(CPGenRandom, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPEncrypt(HCRYPTPROV hprov, HCRYPTKEY hkey, HCRYPTHASH hhash, BOOL final,
                      DWORD flags, BYTE *data, DWORD *datalen, DWORD buflen)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct Encrypt_params params = { prov->handle, key->handle, hash ? hash->handle : 0, final, flags, data, datalen, buflen };
    DWORD err;

    TRACE("%08lx,%08lx,%08lx,%d,%08x,%p,%p,%u\n", hprov, hkey, hhash, final, flags, data, datalen, buflen);

    err = PROXY_CALL(CPEncrypt, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPDecrypt(HCRYPTPROV hprov, HCRYPTKEY hkey, HCRYPTHASH hhash, BOOL final,
                      DWORD flags, BYTE *data, DWORD *len)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *key = (struct context_handle *)hkey;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct Decrypt_params params = { prov->handle, key->handle, hash ? hash->handle : 0, final, flags, data, len };
    DWORD err;

    TRACE("%08lx,%08lx,%08lx,%d,%08x,%p,%p\n", hprov, hkey, hhash, final, flags, data, len);

    err = PROXY_CALL(CPDecrypt, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPHashData(HCRYPTPROV hprov, HCRYPTHASH hhash, const BYTE *data, DWORD len, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct HashData_params params = { prov->handle, hash->handle, data, len, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%p,%u,%08x)\n", hprov, hhash, data, len, flags);

    err = PROXY_CALL(CPHashData, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPHashSessionKey(HCRYPTPROV hprov, HCRYPTHASH hhash, HCRYPTKEY hkey, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct context_handle *key = (struct context_handle *)hkey;
    struct HashSessionKey_params params = { prov->handle, hash->handle, key->handle, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%08lx,%08x)\n", hprov, hhash, hkey, flags);

    err = PROXY_CALL(CPHashSessionKey, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPSignHash(HCRYPTPROV hprov, HCRYPTHASH hhash, DWORD keyspec, LPCWSTR description,
                       DWORD flags, BYTE *signature, DWORD *len)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct SignHash_params params = { prov->handle, hash->handle, keyspec, description, flags, signature, len };
    DWORD err;

    TRACE("%08lx,%08lx,%08x,%s,%08x,%p,%p\n",
        hprov, hhash, keyspec, debugstr_w(description), flags, signature, len);

    err = PROXY_CALL(CPSignHash, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CPVerifySignature(HCRYPTPROV hprov, HCRYPTHASH hhash, const BYTE *signature, DWORD len,
                              HCRYPTKEY hpubkey, LPCWSTR description, DWORD flags)
{
    struct context_handle *prov = (struct context_handle *)hprov;
    struct context_handle *hash = (struct context_handle *)hhash;
    struct context_handle *pubkey = (struct context_handle *)hpubkey;
    struct VerifySignature_params params = { prov->handle, hash->handle, signature, len, pubkey ? pubkey->handle : 0, description, flags };
    DWORD err;

    TRACE("%08lx,%08lx,%p,%u,%08lx,%s,%08x\n",
        hprov, hhash, signature, len, hpubkey, debugstr_w(description), flags);

    err = PROXY_CALL(CPVerifySignature, &params);
    if (err) SetLastError(err);

    return !err;
}

BOOL WINAPI CertDllVerifyCertificateChainPolicy(LPCSTR policy, PCCERT_CHAIN_CONTEXT context,
                                                PCERT_CHAIN_POLICY_PARA para, PCERT_CHAIN_POLICY_STATUS status)
{
    struct VerifyCertificateChainPolicy_params params = { policy, context, para, status };
    DWORD err;

    TRACE("%s,%p,%p,%p\n", debugstr_a(policy), context, para, status);

    err = PROXY_CALL(CertDllVerifyCertificateChainPolicy, &params);
    if (err) SetLastError(err);

    return !err;
}

static const char proxy_dll[] = "cpcsp_proxy.dll";

static void setup_providers(void)
{
    HKEY hkey_provider, hkey_provider_types, hkey;
    DWORD type, size;
    struct CryptEnumProvidersA_params params = { 0, NULL, 0, &type, NULL, &size };
    struct CryptEnumProviderTypesA_params types_params = { 0, NULL, 0, &type, NULL, &size };

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\Defaults\\Provider", &hkey_provider))
    {
        ERR("failed to open provider key\n");
        return;
    }

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\Defaults\\Provider Types", &hkey_provider_types))
    {
        ERR("failed to open provider types key\n");
        return;
    }

    params.index = 0;
    while (!PROXY_CALL(CryptEnumProvidersA, &params))
    {
        params.name = malloc(size);

        if (!PROXY_CALL(CryptEnumProvidersA, &params))
        {
            char buf[32];

            TRACE("Adding: provider %s, type %u\n", debugstr_a(params.name), type);

            if (RegCreateKeyA(hkey_provider, params.name, &hkey))
            {
                ERR("failed to create key %s\n", params.name);
                return;
            }

            if (RegSetValueExA(hkey, "Type", 0, REG_DWORD, (const BYTE *)&type, sizeof(type)))
            {
                ERR("failed to set Type value %u\n", type);
                return;
            }

            if (RegSetValueExA(hkey, "Image Path", 0, REG_SZ, (const BYTE *)proxy_dll, sizeof(proxy_dll)))
            {
                ERR("failed to set Image Path value\n");
                return;
            }

            RegCloseKey(hkey);

            sprintf(buf, "Type %03u", type);

            if (RegCreateKeyA(hkey_provider_types, buf, &hkey))
            {
                ERR("failed to create key %s\n", buf);
                return;
            }

            if (RegSetValueExA(hkey, "Name", 0, REG_SZ, (BYTE *)params.name, strlen(params.name) + 1))
            {
                ERR("failed to set Name value\n");
                return;
            }

            RegCloseKey(hkey);
        }

        free(params.name);
        params.name = NULL;
        params.index++;
    }

    RegCloseKey(hkey_provider);

    types_params.index = 0;
    while (!PROXY_CALL(CryptEnumProviderTypesA, &types_params))
    {
        types_params.name = malloc(size);

        if (!PROXY_CALL(CryptEnumProviderTypesA, &types_params))
        {
            char buf[32];

            TRACE("Adding: provider type %s, type %u\n", debugstr_a(types_params.name), type);

            sprintf(buf, "Type %03u", type);

            if (!RegOpenKeyA(hkey_provider_types, buf, &hkey))
            {
                if (RegSetValueExA(hkey, "TypeName", 0, REG_SZ, (BYTE *)types_params.name, strlen(types_params.name) + 1))
                {
                    ERR("failed to set TypeName value\n");
                    return;
                }

                RegCloseKey(hkey);
            }
        }

        free(types_params.name);
        types_params.name = NULL;
        types_params.index++;
    }

    RegCloseKey(hkey_provider_types);
}

static BOOL register_publickey_converters(HKEY hkey_main)
{
    static const struct
    {
        const char *oid;
        const char *dll;
        const char *function;
    } converter_info[] =
    {
        { "1.2.643.2.2.19", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.643.2.2.98", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.643.7.1.1.1.1", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.643.7.1.1.1.2", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.840.10045.2.1", proxy_dll, "CryptDllConvertPublicKeyInfo" },
    };
    DWORD i;
    HKEY hkey;

    for (i = 0; i < ARRAY_SIZE(converter_info); i++)
    {
        if (RegCreateKeyA(hkey_main, converter_info[i].oid, &hkey))
        {
            ERR("failed to create key %s\n", converter_info[i].oid);
            return FALSE;
        }
        RegSetValueExA(hkey, "Dll", 0, REG_SZ, (BYTE *)converter_info[i].dll, strlen(converter_info[i].dll));
        RegSetValueExA(hkey, "FuncName", 0, REG_SZ, (BYTE *)converter_info[i].function, strlen(converter_info[i].function));
        RegCloseKey(hkey);
    }

    return TRUE;
}

static BOOL register_publickey_encoders(HKEY hkey_main)
{
    static const struct
    {
        const char *oid;
        const char *dll;
        const char *function;
    } converter_info[] =
    {
        { "1.2.643.2.2.19", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.643.2.2.98", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.643.7.1.1.1.1", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.643.7.1.1.1.2", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.840.10045.2.1", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
    };
    DWORD i;
    HKEY hkey;

    for (i = 0; i < ARRAY_SIZE(converter_info); i++)
    {
        if (RegCreateKeyA(hkey_main, converter_info[i].oid, &hkey))
        {
            ERR("failed to create key %s\n", converter_info[i].oid);
            return FALSE;
        }
        RegSetValueExA(hkey, "Dll", 0, REG_SZ, (BYTE *)converter_info[i].dll, strlen(converter_info[i].dll));
        RegSetValueExA(hkey, "FuncName", 0, REG_SZ, (BYTE *)converter_info[i].function, strlen(converter_info[i].function));
        RegCloseKey(hkey);
    }

    return TRUE;
}

static void register_oid_info(const struct PROXY_ENUM_OID *info, HKEY hkey_main)
{
    static const WCHAR nameW[] = { 'N','a','m','e',0 };
    static const WCHAR algidW[] = { 'A','l','g','i','d',0 };
    static const WCHAR extraW[] = { 'E','x','t','r','a','I','n','f','o',0 };
    HKEY hkey;
    char key_name[1024];

    TRACE("Adding: OID %s, name %s, GroupId %u, Algid %#x, ExtraInfo %u bytes\n",
           wine_dbgstr_a(info->pszOID), wine_dbgstr_w(info->pwszName), info->dwGroupId,
           info->Algid, info->extra.cbData);

    sprintf(key_name, "%s!%u", info->pszOID, info->dwGroupId);

    if (RegCreateKeyA(hkey_main, key_name, &hkey))
    {
        ERR("failed to create key %s\n", key_name);
        return;
    }

    RegSetValueExW(hkey, nameW, 0, REG_SZ, (BYTE *)info->pwszName, (lstrlenW(info->pwszName) + 1) * sizeof(WCHAR));

    if (info->Algid)
        RegSetValueExW(hkey, algidW, 0, REG_DWORD, (BYTE *)&info->Algid, sizeof(info->Algid));

    if (info->extra.cbData)
        RegSetValueExW(hkey, extraW, 0, REG_BINARY, info->extra.pbData, info->extra.cbData);

    RegCloseKey(hkey);
}

static void setup_oid_info(void)
{
    struct CryptEnumOIDInfo_params params;
    HKEY hkey_main;
    DWORD i;

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptDllFindOIDInfo", &hkey_main))
    {
        ERR("failed to open OID info key\n");
        return;
    }

    PROXY_CALL(CryptEnumOIDInfo, &params);
    for (i = 0; i < params.count; i++)
        register_oid_info(&params.info[i], hkey_main);

    RegCloseKey(hkey_main);

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 1\\CryptDllConvertPublicKeyInfo", &hkey_main))
    {
        ERR("failed to open OID info key\n");
        return;
    }
    register_publickey_converters(hkey_main);
    RegCloseKey(hkey_main);

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 1\\CryptDllEncodePublicKeyAndParameters", &hkey_main))
    {
        ERR("failed to open OID info key\n");
        return;
    }
    register_publickey_encoders(hkey_main);
    RegCloseKey(hkey_main);
}

static void register_verify_certificate_chain_handlers(void)
{
    static const struct
    {
        const char *guid;
        const char *dll;
        const char *function;
    } verify_info[] =
    {
        { "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}", proxy_dll, "CertDllVerifyCertificateChainPolicy" },
        { "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}", proxy_dll, "CertDllVerifyCertificateChainPolicy" },
        { "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}", proxy_dll, "CertDllVerifyCertificateChainPolicy" },
        { "{C03D5610-26C8-4B6F-9549-245B5B3AB743}", proxy_dll, "CertDllVerifyCertificateChainPolicy" }
    };
    DWORD i;
    HKEY hkey_main, hkey;

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CertDllVerifyCertificateChainPolicy", &hkey_main))
    {
        ERR("failed to open OID info key\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(verify_info); i++)
    {
        if (RegCreateKeyA(hkey_main, verify_info[i].guid, &hkey))
        {
            ERR("failed to create key %s\n", verify_info[i].guid);
            return;
        }
        RegSetValueExA(hkey, "Dll", 0, REG_SZ, (BYTE *)verify_info[i].dll, strlen(verify_info[i].dll));
        RegSetValueExA(hkey, "FuncName", 0, REG_SZ, (BYTE *)verify_info[i].function, strlen(verify_info[i].function));
        RegCloseKey(hkey);
    }

    RegCloseKey(hkey_main);
}

static const char *unix_cp(const char *buf)
{
    UINT in_cp;
    WCHAR in[512];
    static char out[512];

    in_cp = GetACP();
    if (in_cp == 1252) in_cp = 1251;

    MultiByteToWideChar(in_cp, 0, buf, -1, in, ARRAY_SIZE(in));
    WideCharToMultiByte(CP_UTF8, 0, in, -1, out, sizeof(out), NULL, NULL);
    out[sizeof(out) - 1] = 0;

    return out;
}

static BOOL copy_properties(PCCERT_CONTEXT from, PCCERT_CONTEXT to)
{
    NTSTATUS status;
    ULONG propid = 0;
    struct CertEnumCertificateContextProperties_params enum_params = { from, &propid };

    for (;;)
    {
        DWORD size = 0;
        struct CertGetCertificateContextProperty_params get_params;

        PROXY_CALL(CertEnumCertificateContextProperties, &enum_params);
        if (!propid) break;

        get_params.ctx = from;
        get_params.propid = propid;
        get_params.data = NULL;
        get_params.size = &size;

        if ((status = PROXY_CALL(CertGetCertificateContextProperty, &get_params)))
        {
            ERR("CertGetCertificateContextProperty error %#x\n", status);
            return FALSE;
        }

        get_params.data = malloc(size);
        if ((status = PROXY_CALL(CertGetCertificateContextProperty, &get_params)))
        {
            ERR("CertGetCertificateContextProperty error %#x\n", status);
            return FALSE;
        }

        if (propid == CERT_KEY_PROV_INFO_PROP_ID)
        {
            CRYPT_KEY_PROV_INFO *info = (CRYPT_KEY_PROV_INFO *)get_params.data;

            TRACE("CERT_KEY_PROV_INFO_PROP_ID: %s, %s, type %u, flags %#x, params: %u,%p, keyspec %#x\n",
                  debugstr_w(info->pwszContainerName), debugstr_w(info->pwszProvName), info->dwProvType,
                  info->dwFlags, info->cProvParam, info->rgProvParam, info->dwKeySpec);

            if (!CertSetCertificateContextProperty(to, get_params.propid, 0, get_params.data))
                ERR("CertSetCertificateContextProperty(%u) error %#x\n", get_params.propid, GetLastError());
        }
        else
        {
            CRYPT_DATA_BLOB blob = { size, get_params.data };
            if (!CertSetCertificateContextProperty(to, get_params.propid, 0, &blob))
                ERR("CertSetCertificateContextProperty(%u) error %#x\n", get_params.propid, GetLastError());
        }

        free(get_params.data);
    }

    return TRUE;
}

static BOOL import_store(const char *store_name)
{
    struct CertOpenStore_params open_params = { CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                                                store_name };
    struct CertEnumCertificatesInStore_params enum_params = { 0, NULL };
    struct CertCloseStore_params close_params;
    HCERTSTORE store;
    NTSTATUS status;

    TRACE("Reading certificates from %s store\n", store_name);

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                          CERT_SYSTEM_STORE_CURRENT_USER, store_name);
    if (!store)
    {
        ERR("CertOpenStore(%s) error %08x\n", store_name, GetLastError());
        return FALSE;
    }

    status = PROXY_CALL(CertOpenStore, &open_params);
    if (!open_params.store)
    {
        ERR("CertOpenStore(%s) error %08x\n", store_name, status);
        return FALSE;
    }

    for (;;)
    {
        PCCERT_CONTEXT new_ctx;
        char buf[512];
        DWORD size;
        struct CertGetNameStringA_params name_params = { NULL, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                         0, NULL, buf, &size };

        enum_params.store = open_params.store;
        PROXY_CALL(CertEnumCertificatesInStore, &enum_params);
        if (!enum_params.ctx) break;

        size = sizeof(buf);
        name_params.ctx = enum_params.ctx;
        if (PROXY_CALL(CertGetNameStringA, &name_params) || !size)
        {
            ERR("CertGetNameString error\n");
            break;
        }
        TRACE("Adding certificate %s\n", unix_cp(buf));

        if (!CertAddEncodedCertificateToStore(store, enum_params.ctx->dwCertEncodingType,
                                              enum_params.ctx->pbCertEncoded, enum_params.ctx->cbCertEncoded,
                                              CERT_STORE_ADD_ALWAYS, &new_ctx))
            ERR("CertAddEncodedCertificateToStore error %#x\n", GetLastError());
        else
        {
            copy_properties(enum_params.ctx, new_ctx);
            CertFreeCertificateContext(new_ctx);
        }

        enum_params.prev = enum_params.ctx;
    }

    close_params.store = open_params.store;
    close_params.flags = 0;
    PROXY_CALL(CertCloseStore, &close_params);

    CertCloseStore(store, 0);

    return TRUE;
}

void WINAPI Install(HWND hwnd, HINSTANCE hinst, void *cmdline, int showcmd)
{
    TRACE("%08x,%p,%s,%d\n", hwnd, hinst, wine_dbgstr_a(cmdline), showcmd);

    setup_providers();
    setup_oid_info();
    register_verify_certificate_chain_handlers();

    import_store("CA");
    import_store("Root");
    import_store("My");
}

HRESULT WINAPI DllInstall(BOOL install, WCHAR *cmdline)
{
    Install(0, 0, cmdline, 0);
    return S_OK;
}

HRESULT WINAPI DllRegisterServer(void)
{
    Install(0, 0, NULL, 0);
    return S_OK;
}
