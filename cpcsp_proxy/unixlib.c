/*
 * Copyright 2018,2021 Dmitry Timoshkov (for Etersoft)
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

#if 0
#pragma makedep unix
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <wchar.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincrypt.h"
#include "winternl.h"
#include "wine/debug.h"

#include "unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpcsp_proxy);

#ifdef _WIN64
#define SONAME_LIBSSP "/opt/cprocsp/lib/amd64/libssp.so"
#else
#define SONAME_LIBSSP "/opt/cprocsp/lib/ia32/libssp.so"
#endif

static void *libproxy_handle;

/* CryptoPro uses default calling convention under linux */
/* Provider */
static BOOL (*pCryptAcquireContextA)(HCRYPTPROV *,LPCSTR,LPCSTR,DWORD,DWORD);
static BOOL (*pCryptReleaseContext)(HCRYPTPROV,ULONG_PTR);
static BOOL (*pCryptSetProvParam)(HCRYPTPROV,DWORD,const BYTE *,DWORD);
static BOOL (*pCryptGetProvParam)(HCRYPTPROV,DWORD,BYTE *,DWORD *,DWORD);
static BOOL (*pCryptCreateHash)(HCRYPTPROV,ALG_ID,HCRYPTKEY,DWORD,HCRYPTHASH *);
static BOOL (*pCryptDestroyHash)(HCRYPTHASH);
static BOOL (*pCryptDuplicateHash)(HCRYPTHASH,DWORD *,DWORD,HCRYPTHASH *);
static BOOL (*pCryptSetHashParam)(HCRYPTHASH,DWORD,const BYTE *,DWORD);
static BOOL (*pCryptGetHashParam)(HCRYPTHASH,DWORD,BYTE *pbData,DWORD *,DWORD);
static BOOL (*pCryptGenKey)(HCRYPTPROV,ALG_ID,DWORD,HCRYPTKEY *);
static BOOL (*pCryptGetUserKey)(HCRYPTPROV,DWORD,HCRYPTKEY *);
static BOOL (*pCryptExportKey)(HCRYPTKEY,HCRYPTKEY,DWORD,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptImportKey)(HCRYPTPROV,const BYTE *,DWORD,HCRYPTKEY,DWORD,HCRYPTKEY *);
static BOOL (*pCryptDestroyKey)(HCRYPTKEY);
static BOOL (*pCryptDuplicateKey)(HCRYPTKEY,DWORD *,DWORD,HCRYPTKEY *);
static BOOL (*pCryptSetKeyParam)(HCRYPTKEY,DWORD,const BYTE *,DWORD);
static BOOL (*pCryptGetKeyParam)(HCRYPTKEY,DWORD,BYTE *,DWORD *,DWORD);
static BOOL (*pCryptDeriveKey)(HCRYPTPROV,ALG_ID,HCRYPTHASH,DWORD,HCRYPTKEY *);
static BOOL (*pCryptGenRandom)(HCRYPTPROV,DWORD,BYTE *);
static BOOL (*pCryptEncrypt)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE *,DWORD *,DWORD);
static BOOL (*pCryptDecrypt)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptHashData)(HCRYPTHASH,const BYTE *,DWORD,DWORD);
static BOOL (*pCryptHashSessionKey)(HCRYPTHASH,HCRYPTKEY,DWORD);
static BOOL (*pCryptSignHashA)(HCRYPTHASH,DWORD,LPCSTR,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptSignHashW)(HCRYPTHASH,DWORD,LPCWSTR,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptVerifySignatureW)(HCRYPTHASH,const BYTE *,DWORD,HCRYPTKEY,LPCWSTR,DWORD);
static BOOL (*pCryptGetDefaultProviderA)(DWORD,DWORD *,DWORD,LPSTR,DWORD *);
static DWORD (*pGetLastError)(void);
/* PKI Validator */
static BOOL (*pCertVerifyCertificateChainPolicy)(LPCSTR,PCCERT_CHAIN_CONTEXT,PCERT_CHAIN_POLICY_PARA,PCERT_CHAIN_POLICY_STATUS);
/* Setup */
static DWORD (*pCertEnumCertificateContextProperties)(PCCERT_CONTEXT,DWORD);
static PCCERT_CONTEXT (*pCertEnumCertificatesInStore)(HCERTSTORE,PCCERT_CONTEXT);
static PCCERT_CONTEXT (*pCertDuplicateCertificateContext)(PCCERT_CONTEXT);
static BOOL (*pCertGetCertificateContextProperty)(PCCERT_CONTEXT,DWORD,void *,DWORD *);
static DWORD (*pCertGetNameStringA)(PCCERT_CONTEXT,DWORD,DWORD,void *,LPSTR,DWORD);
static HCERTSTORE (*pCertOpenStore)(LPCSTR,DWORD,HCRYPTPROV_LEGACY,DWORD,const void *);
static BOOL (*pCertCloseStore)(HCERTSTORE,DWORD);
static BOOL (*pCertControlStore)(HCERTSTORE,DWORD,DWORD,void const *);
static BOOL (*pCryptEnumProvidersA)(DWORD,DWORD *,DWORD,DWORD *,LPSTR,DWORD *);
static BOOL (*pCryptEnumProviderTypesA)(DWORD,DWORD *,DWORD,DWORD *,LPSTR,DWORD *);
static BOOL (*pCryptEnumOIDInfo)(DWORD,DWORD,void *,PFN_CRYPT_ENUM_OID_INFO);

static void *memdup(const void *src, size_t size)
{
    void *dst;

    if (!src) return NULL;

    dst = malloc(size);
    if (dst) memcpy(dst, src, size);
    return dst;
}

static size_t wcslen_u(const int *str)
{
    const int *s = str;
    while (*s) s++;
    return s - str;
}

static void wcscpy_u2w(WCHAR *dst, const int *src)
{
    while ((*dst++ = *src++)) /* nothing */;
}

static LPWSTR wcsdup_u2w(const int *src)
{
    WCHAR *dst;

    if (!src) return NULL;

    dst = malloc((wcslen_u(src) + 1) * sizeof(*src));
    if (dst) wcscpy_u2w(dst, src);
    return dst;
}

static BOOL load_cpcsp(void)
{
    if (!(libproxy_handle = dlopen(SONAME_LIBSSP, RTLD_NOW)))
    {
        ERR("failed to load %s (%s)\n", SONAME_LIBSSP, dlerror());
        return FALSE;
    }
#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libproxy_handle, #f)) == NULL) \
    { \
        ERR("%s not found in %s\n", #f, SONAME_LIBSSP); \
        goto fail; \
    }
    /* Provider */
    LOAD_FUNCPTR(CryptAcquireContextA);
    LOAD_FUNCPTR(CryptReleaseContext);
    LOAD_FUNCPTR(CryptSetProvParam);
    LOAD_FUNCPTR(CryptGetProvParam);
    LOAD_FUNCPTR(CryptCreateHash);
    LOAD_FUNCPTR(CryptDestroyHash);
    LOAD_FUNCPTR(CryptDuplicateHash);
    LOAD_FUNCPTR(CryptSetHashParam);
    LOAD_FUNCPTR(CryptGetHashParam);
    LOAD_FUNCPTR(CryptGenKey);
    LOAD_FUNCPTR(CryptGetUserKey);
    LOAD_FUNCPTR(CryptExportKey);
    LOAD_FUNCPTR(CryptImportKey);
    LOAD_FUNCPTR(CryptDestroyKey);
    LOAD_FUNCPTR(CryptDuplicateKey);
    LOAD_FUNCPTR(CryptSetKeyParam);
    LOAD_FUNCPTR(CryptGetKeyParam);
    LOAD_FUNCPTR(CryptDeriveKey);
    LOAD_FUNCPTR(CryptGenRandom);
    LOAD_FUNCPTR(CryptEncrypt);
    LOAD_FUNCPTR(CryptDecrypt);
    LOAD_FUNCPTR(CryptHashData);
    LOAD_FUNCPTR(CryptHashSessionKey);
    LOAD_FUNCPTR(CryptSignHashA);
    LOAD_FUNCPTR(CryptSignHashW);
    LOAD_FUNCPTR(CryptVerifySignatureW);
    LOAD_FUNCPTR(CryptGetDefaultProviderA);
    LOAD_FUNCPTR(GetLastError);
    LOAD_FUNCPTR(CertVerifyCertificateChainPolicy);
    /* Setup */
    LOAD_FUNCPTR(CertEnumCertificateContextProperties);
    LOAD_FUNCPTR(CertEnumCertificatesInStore);
    LOAD_FUNCPTR(CertDuplicateCertificateContext);
    LOAD_FUNCPTR(CertGetCertificateContextProperty);
    LOAD_FUNCPTR(CertGetNameStringA);
    LOAD_FUNCPTR(CertOpenStore);
    LOAD_FUNCPTR(CertCloseStore);
    LOAD_FUNCPTR(CertControlStore);
    LOAD_FUNCPTR(CryptEnumProvidersA);
    LOAD_FUNCPTR(CryptEnumProviderTypesA);
    LOAD_FUNCPTR(CryptEnumOIDInfo);
#undef LOAD_FUNCPTR
    return TRUE;

fail:
    dlclose(libproxy_handle);
    libproxy_handle = NULL;
    return FALSE;
}

static void unload_cpcsp(void)
{
    dlclose(libproxy_handle);
    libproxy_handle = NULL;
}

static NTSTATUS proxy_CPAcquireContext(void *args)
{
    struct AcquireContext_params *params = args;
    HCRYPTPROV prov;

    /* Crypto-Pro doesn't have the REGISTRY reader under Linux, so
     * 1. either add an alias using
     * /opt/cprocsp/sbin/amd64/cpconfig -hardware reader -add HDIMAGE -name REGISTRY
     * (for some reason the alias doesn't work for me)
     * or
     * 2. replace REGISTRY\\ by HDIMAGE\\. (like the below code does)
     */
    if (params->container && !strncasecmp(params->container, "REGISTRY\\", 9))
    {
        char hdimage_cont[MAX_PATH];
        char *p = strchr(params->container, '\\');

        if (strlen(params->container) + 1 >= MAX_PATH)
            FIXME("contaner name %s exceeds MAX_PATH\n", debugstr_a(params->container));

        /* Crypto-Pro doesn't have the REGISTRY reader under Linux */
        lstrcpyA(hdimage_cont, "HDIMAGE");
        lstrcatA(hdimage_cont, p);

        if (!pCryptAcquireContextA(&prov, hdimage_cont, params->vt->pszProvName, params->vt->dwProvType, params->flags))
            return pGetLastError();

        *params->prov = prov;
        return STATUS_SUCCESS;
    }

    if (!pCryptAcquireContextA(&prov, params->container, params->vt->pszProvName, params->vt->dwProvType, params->flags))
        return pGetLastError();

    *params->prov = prov;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPReleaseContext(void *args)
{
    struct ReleaseContext_params *params = args;

    if (!pCryptReleaseContext(params->prov, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPSetProvParam(void *args)
{
    struct SetProvParam_params *params = args;

    if (!pCryptSetProvParam(params->prov, params->param, params->data, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPGetProvParam(void *args)
{
    struct GetProvParam_params *params = args;

    if (!pCryptGetProvParam(params->prov, params->param, params->data, params->len, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPCreateHash(void *args)
{
    struct CreateHash_params *params = args;
    HCRYPTHASH hash;

    if (!pCryptCreateHash(params->prov, params->algid, params->key, params->flags, &hash))
        return pGetLastError();

    *params->hash = hash;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPDestroyHash(void *args)
{
    struct DestroyHash_params *params = args;

    if (!pCryptDestroyHash(params->hash))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPDuplicateHash(void *args)
{
    struct DuplicateHash_params *params = args;
    HCRYPTHASH hash;

    if (!pCryptDuplicateHash(params->hash, params->reserved, params->flags, &hash))
        return pGetLastError();

    *params->newhash = hash;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPSetHashParam(void *args)
{
    struct SetHashParam_params *params = args;

    if (!pCryptSetHashParam(params->hash, params->param, params->data, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPGetHashParam(void *args)
{
    struct GetHashParam_params *params = args;

    if (!pCryptGetHashParam(params->hash, params->param, params->data, params->len, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPGenKey(void *args)
{
    struct GenKey_params *params = args;
    HCRYPTKEY key;

    if (!pCryptGenKey(params->prov, params->algid, params->flags, &key))
        return pGetLastError();

    *params->key = key;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPGetUserKey(void *args)
{
    struct GetUserKey_params *params = args;
    HCRYPTKEY key;

    if (!pCryptGetUserKey(params->prov, params->keyspec, &key))
        return pGetLastError();

    *params->key = key;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPExportKey(void *args)
{
    struct ExportKey_params *params = args;

    if (!pCryptExportKey(params->key, params->pubkey, params->type, params->flags, params->data, params->len))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPImportKey(void *args)
{
    struct ImportKey_params *params = args;
    HCRYPTKEY key;

    if (!pCryptImportKey(params->prov, params->data, params->len, params->pubkey, params->flags, &key))
        return pGetLastError();

    *params->newkey = key;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPDestroyKey(void *args)
{
    struct DestroyKey_params *params = args;

    if (!pCryptDestroyKey(params->key))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPDuplicateKey(void *args)
{
    struct DuplicateKey_params *params = args;
    HCRYPTKEY key;

    if (!pCryptDuplicateKey(params->key, params->reserved, params->flags, &key))
        return pGetLastError();

    *params->newkey = key;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPSetKeyParam(void *args)
{
    struct SetKeyParam_params *params = args;

    if (!pCryptSetKeyParam(params->key, params->param, params->data, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPGetKeyParam(void *args)
{
    struct GetKeyParam_params *params = args;

    if (!pCryptGetKeyParam(params->key, params->param, params->data, params->len, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPDeriveKey(void *args)
{
    struct DeriveKey_params *params = args;
    HCRYPTKEY key;

    if (!pCryptDeriveKey(params->prov, params->algid, params->hash, params->flags, &key))
        return pGetLastError();

    *params->key = key;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPGenRandom(void *args)
{
    struct GenRandom_params *params = args;

    if (!pCryptGenRandom(params->prov, params->len, params->buffer))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPEncrypt(void *args)
{
    struct Encrypt_params *params = args;

    if (!pCryptEncrypt(params->key, params->hash, params->final, params->flags, params->data, params->datalen, params->buflen))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPDecrypt(void *args)
{
    struct Decrypt_params *params = args;

    if (!pCryptDecrypt(params->key, params->hash, params->final, params->flags, params->data, params->len))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPHashData(void *args)
{
    struct HashData_params *params = args;

    if (!pCryptHashData(params->hash, params->data, params->len, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPHashSessionKey(void *args)
{
    struct HashSessionKey_params *params = args;

    if (!pCryptHashSessionKey(params->hash, params->key, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPSignHash(void *args)
{
    struct SignHash_params *params = args;

    if (!pCryptSignHashA(params->hash, params->keyspec, NULL, params->flags, params->signature, params->len))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CPVerifySignature(void *args)
{
    struct VerifySignature_params *params = args;

    if (!pCryptVerifySignatureW(params->hash, params->signature, params->len, params->pubkey, NULL, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_GetDefaultProviderA(void *args)
{
    struct GetDefaultProviderA_params *params = args;

    if (!pCryptGetDefaultProviderA(params->type, params->reserved, params->flags, params->prov_name, params->prov_name_size))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CertEnumCertificateContextProperties(void *args)
{
    struct CertEnumCertificateContextProperties_params *params = args;

    *params->propid = pCertEnumCertificateContextProperties(params->ctx, *params->propid);
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CertEnumCertificatesInStore(void *args)
{
    struct CertEnumCertificatesInStore_params *params = args;

    params->ctx = pCertEnumCertificatesInStore((HCERTSTORE)(ULONG_PTR)params->store, params->prev);
    return STATUS_SUCCESS;
}

static void provinfo_to_win32(CRYPT_KEY_PROV_INFO *info, size_t size)
{
    CRYPT_KEY_PROV_INFO *tmp = memdup(info, size);

    wcscpy_u2w(info->pwszContainerName, (const int *)tmp->pwszContainerName);
    wcscpy_u2w(info->pwszProvName, (const int *)tmp->pwszProvName);

    free(tmp);
}

static NTSTATUS proxy_CertGetCertificateContextProperty(void *args)
{
    struct CertGetCertificateContextProperty_params *params = args;

    if (!pCertGetCertificateContextProperty(params->ctx, params->propid, params->data, params->size))
        return pGetLastError();

    if (params->propid == CERT_KEY_PROV_INFO_PROP_ID && params->data)
    {
        CRYPT_KEY_PROV_INFO *info = (CRYPT_KEY_PROV_INFO *)params->data;
        provinfo_to_win32(info, *params->size);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CertGetNameStringA(void *args)
{
    struct CertGetNameStringA_params *params = args;
    DWORD size;

    size = pCertGetNameStringA(params->ctx, params->type, params->flags, params->para, params->name, *params->size);
    if (!size) return pGetLastError();
    *params->size = size;
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CertOpenStore(void *args)
{
    struct CertOpenStore_params *params = args;

    params->store = (UINT64)(ULONG_PTR)pCertOpenStore(params->provider, params->type, params->legacy, params->flags, params->para);
    if (!params->store)
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CertCloseStore(void *args)
{
    struct CertCloseStore_params *params = args;

    if (!pCertCloseStore((HCERTSTORE)(ULONG_PTR)params->store, params->flags))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CertControlStore(void *args)
{
    struct CertControlStore_params *params = args;

    if (!pCertControlStore((HCERTSTORE)(ULONG_PTR)params->store, params->flags, params->type, params->para))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CryptEnumProvidersA(void *args)
{
    struct CryptEnumProvidersA_params *params = args;

    if (!pCryptEnumProvidersA(params->index, params->reserved, params->flags,
                              params->type, params->name, params->size))
        return pGetLastError();

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_CryptEnumProviderTypesA(void *args)
{
    struct CryptEnumProviderTypesA_params *params = args;

    if (!pCryptEnumProviderTypesA(params->index, params->reserved, params->flags,
                                  params->type, params->name, params->size))
        return pGetLastError();

    return STATUS_SUCCESS;
}

struct OID_info_cache
{
    DWORD count, allocated;
    CRYPT_OID_INFO *info;
};

static BOOL enum_oid_info(const CRYPT_OID_INFO *info, void *args)
{
    struct OID_info_cache *cache = args;

#if 0
    fprintf(stderr, "enum_oid_info: OID %s, name %S, GroupId %u, Algid %#x, ExtraInfo %u bytes\n",
           info->pszOID, (wchar_t *)info->pwszName, info->dwGroupId,
           info->u.Algid, info->ExtraInfo.cbData);
#endif

    if (!cache->info)
    {
        cache->info = malloc(16 * sizeof(cache->info[0]));
        if (!cache->info) return FALSE;
        cache->allocated = 16;
    }
    else if (cache->count == cache->allocated)
    {
        cache->info = realloc(cache->info, cache->allocated * 2 * sizeof(cache->info[0]));
        if (!cache->info) return FALSE;
        cache->allocated *= 2;
    }

    cache->info[cache->count].cbSize = sizeof(CRYPT_OID_INFO);
    cache->info[cache->count].pszOID = strdup(info->pszOID);
    cache->info[cache->count].pwszName = wcsdup_u2w((const int *)info->pwszName);
    cache->info[cache->count].dwGroupId = info->dwGroupId;
    cache->info[cache->count].u.Algid = info->u.Algid;
    cache->info[cache->count].ExtraInfo.cbData = info->ExtraInfo.cbData;
    cache->info[cache->count].ExtraInfo.pbData = memdup(info->ExtraInfo.pbData, info->ExtraInfo.cbData);
#ifdef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
    cache->info[cache->count].pwszCNGAlgid = wcsdup_u2w((const int *)info->pwszCNGAlgid);
    cache->info[cache->count].pwszCNGExtraAlgid = wcsdup_u2w((const int *)info->pwszCNGExtraAlgid);
#endif
    cache->count++;

    return TRUE;
}

static NTSTATUS proxy_CryptEnumOIDInfo(void *args)
{
    static struct OID_info_cache cache;
    struct CryptEnumOIDInfo_params *params = args;
    ULONG i;

    if (!cache.count)
        pCryptEnumOIDInfo(0, 0, &cache, (PFN_CRYPT_ENUM_OID_INFO)enum_oid_info);

    params->count = cache.count;
    if (params->count > MAX_CACHE_SIZE)
    {
        FIXME("RPC item count %u is too small (needs %u items), please report!\n", MAX_CACHE_SIZE, params->count);
        params->count = MAX_CACHE_SIZE;
    }

    for (i = 0; i < params->count; i++)
    {
        TRACE("%u: OID %s, name %s, GroupId %u, Algid %#x, ExtraInfo %u bytes\n", i,
           wine_dbgstr_a(cache.info[i].pszOID), wine_dbgstr_w(cache.info[i].pwszName), cache.info[i].dwGroupId,
           cache.info[i].u.Algid, cache.info[i].ExtraInfo.cbData);

        memcpy(params->info[i].pszOID, cache.info[i].pszOID, min(strlen(cache.info[i].pszOID) + 1, sizeof(params->info[i].pszOID)));
        memcpy(params->info[i].pwszName, cache.info[i].pwszName, min((wcslen(cache.info[i].pwszName) + 1) * sizeof(WCHAR), sizeof(params->info[i].pwszName)));
        params->info[i].dwGroupId = cache.info[i].dwGroupId;
        params->info[i].Algid = cache.info[i].u.Algid;
        params->info[i].extra.cbData = min(cache.info[i].ExtraInfo.cbData, sizeof(params->info[i].extra.pbData));
        memcpy(params->info[i].extra.pbData, cache.info[i].ExtraInfo.pbData, params->info[i].extra.cbData);
#ifdef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
        memcpy(params->info[i].pwszCNGAlgid, cache.info[i].pwszCNGAlgid, min((wcslen(cache.info[i].pwszCNGAlgid) + 1) * sizeof(WCHAR), sizeof(params->info[i].pwszCNGAlgid)));
        memcpy(params->info[i].pwszCNGExtraAlgid, cache.info[i].pwszCNGExtraAlgid, min((wcslen(cache.info[i].pwszCNGExtraAlgid) + 1) * sizeof(WCHAR), sizeof(params->info[i].pwszCNGExtraAlgid)));
#endif
    }

    return STATUS_SUCCESS;
}

struct CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA
{
    DWORD cbSize;
    FILETIME *pPrivateKeyUsedTime;
};

struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA
{
    ULONG cbSize;
    FILETIME *pPrivateKeyUsedTime;
    ULONG cCertId;
    struct OCSP_CERT_ID *rgCertId;
    void *callback;
};

struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS
{
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    BOOL fNoCheck;
    BOOL *rgCertIdStatus;
};

static NTSTATUS proxy_CertDllVerifyCertificateChainPolicy(void *args)
{
    struct VerifyCertificateChainPolicy_params *params = args;
    CERT_CHAIN_POLICY_STATUS *status;

    TRACE("%s,%p,%p,%p\n", debugstr_a(params->policy), params->context, params->para, params->status);

    if (!strcasecmp(params->policy, "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"))
        TRACE("CertDllVerifyOCSPSigningCertificateChainPolicy\n");
    else if (!strcasecmp(params->policy, "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}"))
        TRACE("CertDllVerifyTimestampSigningCertificateChainPolicy\n");
    else if (!strcasecmp(params->policy, "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}"))
        TRACE("CertDllVerifySignatureCertificateChainPolicy\n");
    else if (!strcasecmp(params->policy, "{C03D5610-26C8-4B6F-9549-245B5B3AB743}"))
        TRACE("CertDllVerifyPrivateKeyUsagePeriodCertificateChainPolicy\n");
    else
        TRACE("Unknown policy %s\n", debugstr_a(params->policy));

    if (!pCertVerifyCertificateChainPolicy(params->policy, params->context, params->para, params->status))
        return pGetLastError();

    TRACE("status: lChainIndex %d, lElementIndex %d, dwError %08x\n",
          (int)params->status->lChainIndex, (int)params->status->lElementIndex, (int)params->status->dwError);

    if (params->status->pvExtraPolicyStatus)
    {
        status = params->status->pvExtraPolicyStatus;
        TRACE("extra status: lChainIndex %d, lElementIndex %d, dwError %08x\n",
              (int)status->lChainIndex, (int)status->lElementIndex, (int)status->dwError);
    }

    if (params->status->dwError)
    {
        WARN("%s: error %08x: fake success\n", debugstr_a(params->policy), (int)params->status->dwError);
        params->status->lChainIndex = -1;
        params->status->lElementIndex = -1;
        params->status->dwError = 0;
    }

    if (params->status->pvExtraPolicyStatus)
    {
        status = params->status->pvExtraPolicyStatus;
        if (status->dwError)
        {
            WARN("%s: extra error %08x: fake success\n", debugstr_a(params->policy), (int)status->dwError);
            status->lChainIndex = -1;
            status->lElementIndex = -1;
            status->dwError = 0;
        }

        if (!strcasecmp(params->policy, "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"))
        {
            struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA *para = params->para->pvExtraPolicyPara;
            struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS *extra = params->status->pvExtraPolicyStatus;
            ULONG i;

            TRACE("extra: fNoCheck %d, rgCertIdStatus %p\n", extra->fNoCheck, extra->rgCertIdStatus);

            for (i = 0; i < para->cCertId; i++)
            {
                if (!extra->rgCertIdStatus[i])
                {
                    WARN("extra: rgCertIdStatus[%u] = %d: fake success\n", i, extra->rgCertIdStatus[i]);
                    extra->rgCertIdStatus[i] = 1;
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS proxy_free(void *args)
{
    free(args);
    return STATUS_SUCCESS;
}

static NTSTATUS proxy_attach( void *args )
{
    if (load_cpcsp()) return STATUS_SUCCESS;
    if (libproxy_handle) unload_cpcsp();
    return STATUS_DLL_NOT_FOUND;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    proxy_attach,
    proxy_GetDefaultProviderA,
    proxy_CPAcquireContext,
    proxy_CPReleaseContext,
    proxy_CPSetProvParam,
    proxy_CPGetProvParam,
    proxy_CPCreateHash,
    proxy_CPDestroyHash,
    proxy_CPDuplicateHash,
    proxy_CPSetHashParam,
    proxy_CPGetHashParam,
    proxy_CPGenKey,
    proxy_CPGetUserKey,
    proxy_CPExportKey,
    proxy_CPImportKey,
    proxy_CPDestroyKey,
    proxy_CPDuplicateKey,
    proxy_CPSetKeyParam,
    proxy_CPGetKeyParam,
    proxy_CPDeriveKey,
    proxy_CPGenRandom,
    proxy_CPEncrypt,
    proxy_CPDecrypt,
    proxy_CPHashData,
    proxy_CPHashSessionKey,
    proxy_CPSignHash,
    proxy_CPVerifySignature,
    proxy_CertDllVerifyCertificateChainPolicy,
    proxy_CertEnumCertificateContextProperties,
    proxy_CertEnumCertificatesInStore,
    proxy_CertGetCertificateContextProperty,
    proxy_CertGetNameStringA,
    proxy_CertOpenStore,
    proxy_CertCloseStore,
    proxy_CertControlStore,
    proxy_CryptEnumProvidersA,
    proxy_CryptEnumProviderTypesA,
    proxy_CryptEnumOIDInfo,
    proxy_free
};

#ifdef _WIN64

typedef ULONG PTR32;

struct VTableProvStruc32
{
    ULONG Version;
    PTR32 FuncVerifyImage;
    PTR32 FuncReturnhWnd;
    ULONG dwProvType;
    PTR32 pbContextInfo;
    ULONG cbContextInfo;
    PTR32 pszProvName;
};

static void copy_VTableProvStruc32_to_64(const struct VTableProvStruc32 *vt32, VTableProvStruc *vt)
{
    vt->Version = vt32->Version;
    vt->FuncVerifyImage = ULongToPtr(vt32->FuncVerifyImage);
    vt->FuncReturnhWnd = ULongToPtr(vt32->FuncReturnhWnd);
    vt->dwProvType = vt32->dwProvType;
    vt->pbContextInfo = ULongToPtr(vt32->pbContextInfo);
    vt->cbContextInfo = vt32->cbContextInfo;
    vt->pszProvName = ULongToPtr(vt32->pszProvName);
}

static NTSTATUS wow64_proxy_CPAcquireContext(void *args)
{
    struct
    {
        PTR32 prov;
        PTR32 container;
        ULONG flags;
        PTR32 vt;
    } const *params32 = args;
    VTableProvStruc vt;
    struct AcquireContext_params params =
    {
        ULongToPtr(params32->prov),
        ULongToPtr(params32->container),
        params32->flags,
        &vt
    };
    copy_VTableProvStruc32_to_64(ULongToPtr(params32->vt), &vt);
    return proxy_CPAcquireContext(&params);
}

static NTSTATUS wow64_proxy_CPReleaseContext(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG flags;
    } const *params32 = args;
    struct ReleaseContext_params params =
    {
        params32->prov,
        params32->flags
    };
    return proxy_CPReleaseContext(&params);
}

static NTSTATUS wow64_proxy_CPSetProvParam(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG param;
        PTR32 data;
        ULONG flags;
    } const *params32 = args;
    struct SetProvParam_params params =
    {
        params32->prov,
        params32->param,
        ULongToPtr(params32->data),
        params32->flags
    };
    return proxy_CPSetProvParam(&params);
}

static NTSTATUS wow64_proxy_CPGetProvParam(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG param;
        PTR32 data;
        PTR32 len;
        ULONG flags;
    } const *params32 = args;
    struct GetProvParam_params params =
    {
        params32->prov,
        params32->param,
        ULongToPtr(params32->data),
        ULongToPtr(params32->len),
        params32->flags
    };
    return proxy_CPGetProvParam(&params);
}

static NTSTATUS wow64_proxy_CPCreateHash(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG algid;
        UINT64 key;
        ULONG flags;
        PTR32 hash;
    } const *params32 = args;
    struct CreateHash_params params =
    {
        params32->prov,
        params32->algid,
        params32->key,
        params32->flags,
        ULongToPtr(params32->hash)
    };
    return proxy_CPCreateHash(&params);
}

static NTSTATUS wow64_proxy_CPDestroyHash(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
    } const *params32 = args;
    struct DestroyHash_params params =
    {
        params32->prov,
        params32->hash
    };
    return proxy_CPDestroyHash(&params);
}

static NTSTATUS wow64_proxy_CPDuplicateHash(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        PTR32 reserved;
        ULONG flags;
        PTR32 newhash;
    } const *params32 = args;
    struct DuplicateHash_params params =
    {
        params32->prov,
        params32->hash,
        ULongToPtr(params32->reserved),
        params32->flags,
        ULongToPtr(params32->newhash)
    };
    return proxy_CPDuplicateHash(&params);
}

static NTSTATUS wow64_proxy_CPSetHashParam(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        ULONG param;
        PTR32 data;
        ULONG flags;
    } const *params32 = args;
    struct SetHashParam_params params =
    {
        params32->prov,
        params32->hash,
        params32->param,
        ULongToPtr(params32->data),
        params32->flags
    };
    return proxy_CPSetHashParam(&params);
}

static NTSTATUS wow64_proxy_CPGetHashParam(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        ULONG param;
        PTR32 data;
        PTR32 len;
        ULONG flags;
    } const *params32 = args;
    struct GetHashParam_params params =
    {
        params32->prov,
        params32->hash,
        params32->param,
        ULongToPtr(params32->data),
        ULongToPtr(params32->len),
        params32->flags
    };
    return proxy_CPGetHashParam(&params);
}

static NTSTATUS wow64_proxy_CPGenKey(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG algid;
        ULONG flags;
        PTR32 key;
    } const *params32 = args;
    struct GenKey_params params =
    {
        params32->prov,
        params32->algid,
        params32->flags,
        UlongToPtr(params32->key)
    };
    return proxy_CPGenKey(&params);
}

static NTSTATUS wow64_proxy_CPGetUserKey(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG keyspec;
        PTR32 key;
    } const *params32 = args;
    struct GetUserKey_params params =
    {
        params32->prov,
        params32->keyspec,
        ULongToPtr(params32->key)
    };
    return proxy_CPGetUserKey(&params);
}

static NTSTATUS wow64_proxy_CPExportKey(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
        UINT64 pubkey;
        ULONG type;
        ULONG flags;
        PTR32 data;
        PTR32 len;
    } const *params32 = args;
    struct ExportKey_params params =
    {
        params32->prov,
        params32->key,
        params32->pubkey,
        params32->type,
        params32->flags,
        ULongToPtr(params32->data),
        ULongToPtr(params32->len)
    };
    return proxy_CPExportKey(&params);
}

static NTSTATUS wow64_proxy_CPImportKey(void *args)
{
    struct
    {
        UINT64 prov;
        PTR32 data;
        ULONG len;
        UINT64 pubkey;
        ULONG flags;
        PTR32 newkey;
    } const *params32 = args;
    struct ImportKey_params params =
    {
        params32->prov,
        ULongToPtr(params32->data),
        params32->len,
        params32->pubkey,
        params32->flags,
        ULongToPtr(params32->newkey)
    };
    return proxy_CPImportKey(&params);
}

static NTSTATUS wow64_proxy_CPDestroyKey(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
    } const *params32 = args;
    struct DestroyKey_params params =
    {
        params32->prov,
        params32->key
    };
    return proxy_CPDestroyKey(&params);
}

static NTSTATUS wow64_proxy_CPDuplicateKey(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
        PTR32 reserved;
        ULONG flags;
        PTR32 newkey;
    } const *params32 = args;
    struct DuplicateKey_params params =
    {
        params32->prov,
        params32->key,
        ULongToPtr(params32->reserved),
        params32->flags,
        ULongToPtr(params32->newkey)
    };
    return proxy_CPDuplicateKey(&params);
}

static NTSTATUS wow64_proxy_CPSetKeyParam(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
        ULONG param;
        PTR32 data;
        ULONG flags;
    } const *params32 = args;
    struct SetKeyParam_params params =
    {
        params32->prov,
        params32->key,
        params32->param,
        ULongToPtr(params32->data),
        params32->flags
    };
    return proxy_CPSetKeyParam(&params);
}

static NTSTATUS wow64_proxy_CPGetKeyParam(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
        ULONG param;
        PTR32 data;
        PTR32 len;
        ULONG flags;
    } const *params32 = args;
    struct GetKeyParam_params params =
    {
        params32->prov,
        params32->key,
        params32->param,
        ULongToPtr(params32->data),
        ULongToPtr(params32->len),
        params32->flags
    };
    return proxy_CPGetKeyParam(&params);
}

static NTSTATUS wow64_proxy_CPDeriveKey(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG algid;
        UINT64 hash;
        ULONG flags;
        PTR32 key;
    } const *params32 = args;
    struct DeriveKey_params params =
    {
        params32->prov,
        params32->algid,
        params32->hash,
        params32->flags,
        ULongToPtr(params32->key)
    };
    return proxy_CPDeriveKey(&params);
}

static NTSTATUS wow64_proxy_CPGenRandom(void *args)
{
    struct
    {
        UINT64 prov;
        ULONG len;
        PTR32 buffer;
    } const *params32 = args;
    struct GenRandom_params params =
    {
        params32->prov,
        params32->len,
        ULongToPtr(params32->buffer)
    };
    return proxy_CPGenRandom(&params);
}

static NTSTATUS wow64_proxy_CPEncrypt(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
        UINT64 hash;
        ULONG final;
        ULONG flags;
        PTR32 data;
        PTR32 datalen;
        ULONG buflen;
    } const *params32 = args;
    struct Encrypt_params params =
    {
        params32->prov,
        params32->key,
        params32->hash,
        params32->final,
        params32->flags,
        ULongToPtr(params32->data),
        ULongToPtr(params32->datalen),
        params32->buflen
    };
    return proxy_CPEncrypt(&params);
}

static NTSTATUS wow64_proxy_CPDecrypt(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 key;
        UINT64 hash;
        ULONG final;
        ULONG flags;
        PTR32 data;
        PTR32 len;
    } const *params32 = args;
    struct Decrypt_params params =
    {
        params32->prov,
        params32->key,
        params32->hash,
        params32->final,
        params32->flags,
        ULongToPtr(params32->data),
        ULongToPtr(params32->len)
    };
    return proxy_CPDecrypt(&params);
}

static NTSTATUS wow64_proxy_CPHashData(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        PTR32 data;
        ULONG len;
        ULONG flags;
    } const *params32 = args;
    struct HashData_params params =
    {
        params32->prov,
        params32->hash,
        ULongToPtr(params32->data),
        params32->len,
        params32->flags
    };
    return proxy_CPHashData(&params);
}

static NTSTATUS wow64_proxy_CPHashSessionKey(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        UINT64 key;
        ULONG flags;
    } const *params32 = args;
    struct HashSessionKey_params params =
    {
        params32->prov,
        params32->hash,
        params32->key,
        params32->flags
    };
    return proxy_CPHashSessionKey(&params);
}

static NTSTATUS wow64_proxy_CPSignHash(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        ULONG keyspec;
        PTR32 description;
        ULONG flags;
        PTR32 signature;
        PTR32 len;
    } const *params32 = args;
    struct SignHash_params params =
    {
        params32->prov,
        params32->hash,
        params32->keyspec,
        ULongToPtr(params32->description),
        params32->flags,
        ULongToPtr(params32->signature),
        ULongToPtr(params32->len)
    };
    return proxy_CPSignHash(&params);
}

static NTSTATUS wow64_proxy_CPVerifySignature(void *args)
{
    struct
    {
        UINT64 prov;
        UINT64 hash;
        PTR32 signature;
        ULONG len;
        UINT64 pubkey;
        PTR32 description;
        ULONG flags;
    } const *params32 = args;
    struct VerifySignature_params params =
    {
        params32->prov,
        params32->hash,
        ULongToPtr(params32->signature),
        params32->len,
        params32->pubkey,
        ULongToPtr(params32->description),
        params32->flags
    };
    return proxy_CPVerifySignature(&params);
}

static NTSTATUS wow64_proxy_GetDefaultProviderA(void *args)
{
    struct
    {
        ULONG type;
        PTR32 reserved;
        ULONG flags;
        PTR32 prov_name;
        PTR32 prov_name_size;
    } const *params32 = args;
    struct GetDefaultProviderA_params params =
    {
        params32->type,
        ULongToPtr(params32->reserved),
        params32->flags,
        ULongToPtr(params32->prov_name),
        ULongToPtr(params32->prov_name_size)
    };
    return proxy_GetDefaultProviderA(&params);
}

struct CRYPT_OBJID_BLOB32
{
    ULONG cbData;
    PTR32 pbData;
};

struct CRYPT_ALGORITHM_IDENTIFIER32
{
    PTR32 pszObjId;
    struct CRYPT_OBJID_BLOB32 Parameters;
};

struct CRYPT_BIT_BLOB32
{
    ULONG cbData;
    PTR32 pbData;
    ULONG cUnusedBits;
};

struct CERT_PUBLIC_KEY_INFO32
{
    struct CRYPT_ALGORITHM_IDENTIFIER32 Algorithm;
    struct CRYPT_BIT_BLOB32 PublicKey;
};

struct CRYPT_INTEGER_BLOB32
{
    ULONG cbData;
    PTR32 pbData;
};

struct CERT_NAME_BLOB32
{
    ULONG cbData;
    PTR32 pbData;
};

struct CERT_EXTENSION32
{
    PTR32 pszObjId;
    ULONG fCritical;
    struct CRYPT_OBJID_BLOB32 Value;
};

struct CERT_INFO32
{
    ULONG dwVersion;
    struct CRYPT_INTEGER_BLOB32 SerialNumber;
    struct CRYPT_ALGORITHM_IDENTIFIER32 SignatureAlgorithm;
    struct CERT_NAME_BLOB32 Issuer;
    FILETIME NotBefore;
    FILETIME NotAfter;
    struct CERT_NAME_BLOB32 Subject;
    struct CERT_PUBLIC_KEY_INFO32 SubjectPublicKeyInfo;
    struct CRYPT_BIT_BLOB32 IssuerUniqueId;
    struct CRYPT_BIT_BLOB32 SubjectUniqueId;
    ULONG cExtension;
    PTR32 rgExtension;
};

struct CERT_CONTEXT32
{
    ULONG dwCertEncodingType;
    PTR32 pbCertEncoded;
    ULONG cbCertEncoded;
    PTR32 pCertInfo;
    ULONG hCertStore;
};

static void copy_CERT_PUBLIC_KEY_INFO64_to_32(const CERT_PUBLIC_KEY_INFO *info, struct CERT_PUBLIC_KEY_INFO32 *info32)
{
    info32->Algorithm.pszObjId = PtrToUlong(info->Algorithm.pszObjId);
    info32->Algorithm.Parameters.cbData = info->Algorithm.Parameters.cbData;
    info32->Algorithm.Parameters.pbData = PtrToUlong(info->Algorithm.Parameters.pbData);
    info32->PublicKey.cbData = info->PublicKey.cbData;
    info32->PublicKey.pbData = PtrToUlong(info->PublicKey.pbData);
    info32->PublicKey.cUnusedBits = info->PublicKey.cUnusedBits;
}

static struct CERT_INFO32 *copy_CERT_INFO64_to_32(const CERT_INFO *info)
{
    struct CERT_INFO32 *info32;
    struct CERT_EXTENSION32 *ext32;
    ULONG i;

    info32 = malloc(sizeof(*info32) + info->cExtension * sizeof(*ext32));
    if (!info) return NULL;

    info32->dwVersion = info->dwVersion;
    info32->SerialNumber.cbData = info->SerialNumber.cbData;
    info32->SerialNumber.pbData = PtrToUlong(info->SerialNumber.pbData);
    info32->SignatureAlgorithm.pszObjId = PtrToUlong(info->SignatureAlgorithm.pszObjId);
    info32->SignatureAlgorithm.Parameters.cbData = info->SignatureAlgorithm.Parameters.cbData;
    info32->SignatureAlgorithm.Parameters.pbData = PtrToUlong(info->SignatureAlgorithm.Parameters.pbData);
    info32->Issuer.cbData = info->Issuer.cbData;
    info32->Issuer.pbData = PtrToUlong(info->Issuer.pbData);
    info32->NotBefore = info->NotBefore;
    info32->NotAfter = info->NotAfter;
    info32->Subject.cbData = info->Subject.cbData;
    info32->Subject.pbData = PtrToUlong(info->Subject.pbData);
    copy_CERT_PUBLIC_KEY_INFO64_to_32(&info->SubjectPublicKeyInfo, &info32->SubjectPublicKeyInfo);
    info32->IssuerUniqueId.cbData = info->IssuerUniqueId.cbData;
    info32->IssuerUniqueId.pbData = PtrToUlong(info->IssuerUniqueId.pbData);
    info32->IssuerUniqueId.cUnusedBits = info->IssuerUniqueId.cUnusedBits;
    info32->SubjectUniqueId.cbData = info->SubjectUniqueId.cbData;
    info32->SubjectUniqueId.pbData = PtrToUlong(info->SubjectUniqueId.pbData);
    info32->SubjectUniqueId.cUnusedBits = info->SubjectUniqueId.cUnusedBits;

    if (info->cExtension) info32->rgExtension = PtrToUlong(info32 + 1);
    else info32->rgExtension = 0;

    info32->cExtension = info->cExtension;
    ext32 = (struct CERT_EXTENSION32 *)ULongToPtr(info32->rgExtension);

    for (i = 0; i < info->cExtension; i++)
    {
        ext32[i].pszObjId = PtrToUlong(info->rgExtension[i].pszObjId);
        ext32[i].fCritical = info->rgExtension[i].fCritical;
        ext32[i].Value.cbData = info->rgExtension[i].Value.cbData;
        ext32[i].Value.pbData = PtrToUlong(info->rgExtension[i].Value.pbData);
    }

    return info32;
}

static struct CERT_CONTEXT32 *copy_CERT_CONTEXT64_to_32(const CERT_CONTEXT *ctx)
{
    struct CERT_CONTEXT32 *ctx32;

    ctx32 = malloc(sizeof(*ctx32));
    if (!ctx32) return NULL;

    ctx32->dwCertEncodingType = ctx->dwCertEncodingType;
    ctx32->pbCertEncoded = PtrToUlong(ctx->pbCertEncoded);
    ctx32->cbCertEncoded = ctx->cbCertEncoded;
    ctx32->pCertInfo = PtrToUlong(copy_CERT_INFO64_to_32(ctx->pCertInfo));
    ctx32->hCertStore = PtrToUlong(ctx->hCertStore);

    return ctx32;
}

#define CC_CACHE_SIZE 1024

static struct
{
    ULONG count;
    struct
    {
        const CERT_CONTEXT *ctx;
        const struct CERT_CONTEXT32 *ctx32;
    } entry[CC_CACHE_SIZE];
} CC_cache;

static const CERT_CONTEXT *CC_cache_entry(const struct CERT_CONTEXT32 *ctx32)
{
    ULONG i;

    for (i = 0; i < CC_cache.count; i++)
    {
        if (ctx32->cbCertEncoded == CC_cache.entry[i].ctx->cbCertEncoded &&
            !memcmp(ULongToPtr(ctx32->pbCertEncoded), CC_cache.entry[i].ctx->pbCertEncoded, ctx32->cbCertEncoded))
        return CC_cache.entry[i].ctx;
    }

    FIXME("Couldn't find associated 64-bit CERT_CONTEXT in the cache for ctx32 %p\n", ctx32);
    return NULL;
}

static const struct CERT_CONTEXT32 *CC32_cache_entry(const CERT_CONTEXT *ctx)
{
    ULONG i;
    const struct CERT_CONTEXT32 *ctx32;

    for (i = 0; i < CC_cache.count; i++)
    {
        if (ctx->cbCertEncoded == CC_cache.entry[i].ctx->cbCertEncoded &&
            !memcmp(ctx->pbCertEncoded, CC_cache.entry[i].ctx->pbCertEncoded, ctx->cbCertEncoded))
        return CC_cache.entry[i].ctx32;
    }

    TRACE("Adding 64-bit CERT_CONTEXT %p to the cache at %u\n", ctx, i);

    if (i >= CC_CACHE_SIZE)
    {
        FIXME("CERT_CONTEXT cache is full (%u entries)\n", CC_CACHE_SIZE);
        return NULL;
    }

    ctx32 = copy_CERT_CONTEXT64_to_32(ctx);
    if (ctx32)
    {
        CC_cache.entry[i].ctx = ctx;
        CC_cache.entry[i].ctx32 = ctx32;
        CC_cache.count++;
    }
    return ctx32;
}

static NTSTATUS wow64_proxy_CertEnumCertificateContextProperties(void *args)
{
    struct
    {
        PTR32 ctx;
        PTR32 propid;
    } const *params32 = args;
    struct CertEnumCertificateContextProperties_params params =
    {
        CC_cache_entry(ULongToPtr(params32->ctx)),
        ULongToPtr(params32->propid)
    };
    return proxy_CertEnumCertificateContextProperties(&params);
}

static NTSTATUS wow64_proxy_CertEnumCertificatesInStore(void *args)
{
    struct
    {
        UINT64 store;
        PTR32 prev;
        PTR32 ctx;
    } *params32 = args;
    struct CertEnumCertificatesInStore_params params =
    {
        params32->store,
        NULL,
        NULL /* ret */
    };
    NTSTATUS status;
    if (params32->prev)
        params.prev = pCertDuplicateCertificateContext(CC_cache_entry(ULongToPtr(params32->prev)));
    status = proxy_CertEnumCertificatesInStore(&params);
    if (!status && params.ctx)
        params32->ctx = PtrToUlong(CC32_cache_entry(params.ctx));
    else params32->ctx = 0;
    return status;
}

static NTSTATUS wow64_proxy_CertGetCertificateContextProperty(void *args)
{
    struct
    {
        PTR32 ctx;
        ULONG propid;
        PTR32 data;
        PTR32 size;
    } *params32 = args;
    struct CertGetCertificateContextProperty_params params =
    {
        CC_cache_entry(ULongToPtr(params32->ctx)),
        params32->propid,
        ULongToPtr(params32->data),
        ULongToPtr(params32->size)
    };
    NTSTATUS status;
    status = proxy_CertGetCertificateContextProperty(&params);
    if (!status)
    {
        if (params.propid == CERT_KEY_PROV_INFO_PROP_ID && params32->data)
        {
            CRYPT_KEY_PROV_INFO *info = (CRYPT_KEY_PROV_INFO *)params.data;
            struct CRYPT_KEY_PROV_INFO32
            {
                PTR32 pwszContainerName;
                PTR32 pwszProvName;
                DWORD dwProvType;
                DWORD dwFlags;
                DWORD cProvParam;
                PTR32 rgProvParam;
                DWORD dwKeySpec;
            } info32 =
            {
                PtrToUlong(info->pwszContainerName),
                PtrToUlong(info->pwszProvName),
                info->dwProvType,
                info->dwFlags,
                info->cProvParam,
                PtrToUlong(info->rgProvParam),
                info->dwKeySpec
            };
            memcpy(ULongToPtr(params32->data), &info32, sizeof(info32));
        }
    }
    return status;
}

static NTSTATUS wow64_proxy_CertGetNameStringA(void *args)
{
    struct
    {
        PTR32 ctx;
        ULONG type;
        ULONG flags;
        PTR32 para;
        PTR32 name;
        PTR32 size;
    } const *params32 = args;
    struct CertGetNameStringA_params params =
    {
        CC_cache_entry(ULongToPtr(params32->ctx)),
        params32->type,
        params32->flags,
        ULongToPtr(params32->para),
        ULongToPtr(params32->name),
        ULongToPtr(params32->size)
    };
    return proxy_CertGetNameStringA(&params);
}

static NTSTATUS wow64_proxy_CertOpenStore(void *args)
{
    struct
    {
        PTR32 provider;
        ULONG type;
        UINT64 legacy;
        ULONG flags;
        PTR32 para;
        UINT64 store; /* ret */
    } *params32 = args;
    struct CertOpenStore_params params =
    {
        ULongToPtr(params32->provider),
        params32->type,
        params32->legacy,
        params32->flags,
        ULongToPtr(params32->para),
        0 /* ret */
    };
    NTSTATUS status = proxy_CertOpenStore(&params);
    if (!status) params32->store = params.store;
    return status;
}

static NTSTATUS wow64_proxy_CertCloseStore(void *args)
{
    struct
    {
        UINT64 store;
        ULONG flags;
    } const *params32 = args;
    struct CertCloseStore_params params =
    {
        params32->store,
        params32->flags
    };
    return proxy_CertCloseStore(&params);
}

static NTSTATUS wow64_proxy_CertControlStore(void *args)
{
    struct
    {
        UINT64 store;
        ULONG flags;
        ULONG type;
        PTR32 para;
    } const *params32 = args;
    struct CertControlStore_params params =
    {
        params32->store,
        params32->flags,
        params32->type,
        ULongToPtr(params32->para)
    };
    return proxy_CertControlStore(&params);
}

static NTSTATUS wow64_proxy_CryptEnumProvidersA(void *args)
{
    struct
    {
        ULONG index;
        PTR32 reserved;
        ULONG flags;
        PTR32 type;
        PTR32  name;
        PTR32 size;
    } const *params32 = args;
    struct CryptEnumProvidersA_params params =
    {
        params32->index,
        UlongToPtr(params32->reserved),
        params32->flags,
        UlongToPtr(params32->type),
        UlongToPtr(params32->name),
        UlongToPtr(params32->size)
    };
    return proxy_CryptEnumProvidersA(&params);
}

static NTSTATUS wow64_proxy_CryptEnumProviderTypesA(void *args)
{
    struct
    {
        ULONG index;
        PTR32 reserved;
        ULONG flags;
        PTR32 type;
        PTR32  name;
        PTR32 size;
    } const *params32 = args;
    struct CryptEnumProviderTypesA_params params =
    {
        params32->index,
        UlongToPtr(params32->reserved),
        params32->flags,
        UlongToPtr(params32->type),
        UlongToPtr(params32->name),
        UlongToPtr(params32->size)
    };
    return proxy_CryptEnumProviderTypesA(&params);
}

static NTSTATUS wow64_proxy_CryptEnumOIDInfo(void *args)
{
    struct CryptEnumOIDInfo_params *params = args;

    proxy_CryptEnumOIDInfo(params);

    return STATUS_SUCCESS;
}

struct CRYPT_HASH_BLOB32
{
    ULONG cbData;
    PTR32 pbData;
};

struct OCSP_CERT_ID
{
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB IssuerNameHash;
    CRYPT_HASH_BLOB IssuerKeyHash;
    CRYPT_INTEGER_BLOB SerialNumber;
};

struct OCSP_CERT_ID32
{
    struct CRYPT_ALGORITHM_IDENTIFIER32 HashAlgorithm;
    struct CRYPT_HASH_BLOB32 IssuerNameHash;
    struct CRYPT_HASH_BLOB32 IssuerKeyHash;
    struct CRYPT_INTEGER_BLOB32 SerialNumber;
};

struct CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA
{
    DWORD cbSize;
    FILETIME *pPrivateKeyUsedTime;
};

struct CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32
{
    DWORD cbSize;
    PTR32 pPrivateKeyUsedTime;
};

struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32
{
    ULONG cbSize;
    PTR32 pPrivateKeyUsedTime;
    ULONG cCertId;
    PTR32 rgCertId;
    PTR32 callback;
};

struct CERT_TRUST_STATUS32
{
    ULONG dwErrorStatus;
    ULONG dwInfoStatus;
};

struct CERT_CHAIN_ELEMENT32
{
    ULONG cbSize;
    PTR32 pCertContext; /* PCCERT_CONTEXT */
    struct CERT_TRUST_STATUS32 TrustStatus;
    PTR32 pRevocationInfo; /* PCERT_REVOCATION_INFO */
    PTR32 pIssuanceUsage; /* PCERT_ENHKEY_USAGE */
    PTR32 pApplicationUsage; /* PCERT_ENHKEY_USAGE */
    PTR32 pwszExtendedErrorInfo;
};

struct CERT_SIMPLE_CHAIN32
{
    ULONG cbSize;
    struct CERT_TRUST_STATUS32 TrustStatus;
    ULONG cElement;
    PTR32 rgpElement; /* PCERT_CHAIN_ELEMENT */
    PTR32 pTrustListInfo; /* PCERT_TRUST_LIST_INFO */
    ULONG fHasRevocationFreshnessTime;
    ULONG dwRevocationFreshnessTime;
};

struct CERT_CHAIN_CONTEXT32
{
    ULONG cbSize;
    struct CERT_TRUST_STATUS32 TrustStatus;
    ULONG cChain;
    PTR32 rgpChain; /* PCERT_SIMPLE_CHAIN */
    ULONG cLowerQualityChainContext;
    PTR32 rgpLowerQualityChainContext; /* PCCERT_CHAIN_CONTEXT */
    ULONG fHasRevocationFreshnessTime;
    ULONG dwRevocationFreshnessTime;
};

static void copy_CERT_CHAIN_CONTEXT32_to_64(const struct CERT_CHAIN_CONTEXT32 *ctx32, CERT_CHAIN_CONTEXT *ctx)
{
    ULONG i;

    ctx->cbSize = sizeof(*ctx);
    ctx->TrustStatus.dwErrorStatus = ctx32->TrustStatus.dwErrorStatus;
    ctx->TrustStatus.dwInfoStatus = ctx32->TrustStatus.dwInfoStatus;
    ctx->cChain = ctx32->cChain;
    if (ctx->cChain)
    {
        const PTR32 *rgpChain32 = UlongToPtr(ctx32->rgpChain);

        ctx->rgpChain = malloc(ctx->cChain * sizeof(ctx->rgpChain[0]));
        for (i = 0; i < ctx->cChain; i++)
        {
            const struct CERT_SIMPLE_CHAIN32 *chain32 = UlongToPtr(rgpChain32[i]);

            ctx->rgpChain[i] = malloc(sizeof(CERT_SIMPLE_CHAIN));
            ctx->rgpChain[i]->cbSize = sizeof(CERT_SIMPLE_CHAIN);
            ctx->rgpChain[i]->TrustStatus.dwErrorStatus = chain32->TrustStatus.dwErrorStatus;
            ctx->rgpChain[i]->TrustStatus.dwInfoStatus = chain32->TrustStatus.dwInfoStatus;
            ctx->rgpChain[i]->cElement = chain32->cElement;
            if (ctx->rgpChain[i]->cElement)
            {
                const PTR32 *rgpElement32 = UlongToPtr(chain32->rgpElement);
                ULONG k;

                ctx->rgpChain[i]->rgpElement = malloc(ctx->rgpChain[i]->cElement * sizeof(ctx->rgpChain[i]->rgpElement[0]));
                for (k = 0; k < ctx->rgpChain[i]->cElement; k++)
                {
                    const struct CERT_CHAIN_ELEMENT32 *element32 = UlongToPtr(rgpElement32[k]);

                    ctx->rgpChain[i]->rgpElement[k] = malloc(sizeof(CERT_CHAIN_ELEMENT));
                    ctx->rgpChain[i]->rgpElement[k]->cbSize = sizeof(CERT_CHAIN_ELEMENT);
                    ctx->rgpChain[i]->rgpElement[k]->pCertContext = CC_cache_entry(ULongToPtr(element32->pCertContext));
                    ctx->rgpChain[i]->rgpElement[k]->TrustStatus.dwErrorStatus = element32->TrustStatus.dwErrorStatus;
                    ctx->rgpChain[i]->rgpElement[k]->TrustStatus.dwInfoStatus = element32->TrustStatus.dwInfoStatus;
                    if (element32->pRevocationInfo || element32->pIssuanceUsage || element32->pApplicationUsage || element32->pwszExtendedErrorInfo)
                        FIXME("element32: pRevocationInfo = %#x, pIssuanceUsage = %#x, pApplicationUsage = %#x, pwszExtendedErrorInfo = %#x\n",
                               element32->pRevocationInfo, element32->pIssuanceUsage, element32->pApplicationUsage, element32->pwszExtendedErrorInfo);
                    ctx->rgpChain[i]->rgpElement[k]->pRevocationInfo = NULL;
                    ctx->rgpChain[i]->rgpElement[k]->pIssuanceUsage = NULL;
                    ctx->rgpChain[i]->rgpElement[k]->pApplicationUsage = NULL;
                    ctx->rgpChain[i]->rgpElement[k]->pwszExtendedErrorInfo = NULL;
                }
            }
            else
                ctx->rgpChain[i]->rgpElement = NULL;
            if (chain32->pTrustListInfo)
                FIXME("chain32[%u]->pTrustListInfo = %#x\n", i, chain32->pTrustListInfo);
            ctx->rgpChain[i]->pTrustListInfo = NULL;
            ctx->rgpChain[i]->fHasRevocationFreshnessTime = chain32->fHasRevocationFreshnessTime;
            ctx->rgpChain[i]->dwRevocationFreshnessTime = chain32->dwRevocationFreshnessTime;
        }
    }
    else
        ctx->rgpChain = NULL;
    ctx->cLowerQualityChainContext = ctx32->cLowerQualityChainContext;
    ctx->rgpLowerQualityChainContext = UlongToPtr(ctx32->rgpLowerQualityChainContext); /* PCCERT_CHAIN_CONTEXT */
    ctx->fHasRevocationFreshnessTime = ctx32->fHasRevocationFreshnessTime;
    ctx->dwRevocationFreshnessTime = ctx32->dwRevocationFreshnessTime;
}

struct CERT_CHAIN_POLICY_PARA32
{
    ULONG cbSize;
    ULONG dwFlags;
    PTR32 pvExtraPolicyPara;
};

static void copy_CERT_CHAIN_POLICY_PARA32_to_64(const struct CERT_CHAIN_POLICY_PARA32 *para32, CERT_CHAIN_POLICY_PARA *para)
{
    para->cbSize = sizeof(*para);
    para->dwFlags = para32->dwFlags;
    para->pvExtraPolicyPara = NULL;
}

struct CERT_CHAIN_POLICY_STATUS32
{
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    PTR32 pvExtraPolicyStatus;
};

struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS32
{
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    BOOL fNoCheck;
    PTR32 rgCertIdStatus;
};

static void copy_CERT_CHAIN_POLICY_STATUS32_to_64(const struct CERT_CHAIN_POLICY_STATUS32 *status32, CERT_CHAIN_POLICY_STATUS *status)
{
    status->cbSize = status32->cbSize;
    status->dwError = status32->dwError;
    status->lChainIndex = status32->lChainIndex;
    status->lElementIndex = status32->lElementIndex;
    status->pvExtraPolicyStatus = NULL;
}

static void copy_CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32_to_64(const struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32 *para32,
    struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA *para)
{
    ULONG i;

    para->cbSize = sizeof(*para);
    para->pPrivateKeyUsedTime = ULongToPtr(para32->pPrivateKeyUsedTime);
    if (para32->callback)
        FIXME("para32->callback = %#x\n", para32->callback);
    para->callback = NULL;
    para->cCertId = para32->cCertId;
    para->rgCertId = malloc(para->cCertId * sizeof(para->rgCertId[0]));
    for (i = 0; i < para->cCertId; i++)
    {
        const struct OCSP_CERT_ID32 *rgCertId32 = ULongToPtr(para32->rgCertId);

        para->rgCertId[i].HashAlgorithm.pszObjId = ULongToPtr(rgCertId32->HashAlgorithm.pszObjId);
        para->rgCertId[i].HashAlgorithm.Parameters.cbData = rgCertId32->HashAlgorithm.Parameters.cbData;
        para->rgCertId[i].HashAlgorithm.Parameters.pbData = ULongToPtr(rgCertId32->HashAlgorithm.Parameters.cbData);
        para->rgCertId[i].IssuerNameHash.cbData = rgCertId32->IssuerNameHash.cbData;
        para->rgCertId[i].IssuerNameHash.pbData = ULongToPtr(rgCertId32->IssuerNameHash.pbData);
        para->rgCertId[i].IssuerKeyHash.cbData = rgCertId32->IssuerKeyHash.cbData;
        para->rgCertId[i].IssuerKeyHash.pbData = ULongToPtr(rgCertId32->IssuerKeyHash.pbData);
        para->rgCertId[i].SerialNumber.cbData = rgCertId32->SerialNumber.cbData;
        para->rgCertId[i].SerialNumber.pbData = ULongToPtr(rgCertId32->SerialNumber.pbData);
    }
};

static NTSTATUS wow64_CertDllVerifyOCSPSigningCertificateChainPolicy(void *args)
{
    struct
    {
        PTR32 policy;
        PTR32 context;
        PTR32 para;
        PTR32 status;
    } *params32 = args;
    NTSTATUS status;
    CERT_CHAIN_CONTEXT context;
    CERT_CHAIN_POLICY_PARA para;
    struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA para_extra;
    CERT_CHAIN_POLICY_STATUS policy_status;
    struct CERT_CHAIN_POLICY_STATUS32 *policy_status32;
    struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS status_extra;
    struct VerifyCertificateChainPolicy_params params =
    {
        ULongToPtr(params32->policy),
        &context,
        NULL,
        &policy_status
    };

    copy_CERT_CHAIN_CONTEXT32_to_64(ULongToPtr(params32->context), &context);
    if (params32->para)
    {
        struct CERT_CHAIN_POLICY_PARA32 *para32 = ULongToPtr(params32->para);

        copy_CERT_CHAIN_POLICY_PARA32_to_64(para32, &para);
        if (para32->pvExtraPolicyPara)
        {
            const struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32 *para_extra32 = ULongToPtr(para32->pvExtraPolicyPara);

            copy_CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32_to_64(para_extra32, &para_extra);

            para.pvExtraPolicyPara = &para_extra;
        }

        params.para = &para;
    }

    policy_status32 = ULongToPtr(params32->status);
    copy_CERT_CHAIN_POLICY_STATUS32_to_64(policy_status32, &policy_status);
    if (policy_status32->pvExtraPolicyStatus)
    {
        struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS32 *status_extra32 = UlongToPtr(policy_status32->pvExtraPolicyStatus);

        status_extra.cbSize = sizeof(status_extra);
        status_extra.dwError = status_extra32->dwError;
        status_extra.lChainIndex = status_extra32->lChainIndex;
        status_extra.lElementIndex = status_extra32->lElementIndex;
        status_extra.fNoCheck = status_extra32->fNoCheck;
        status_extra.rgCertIdStatus = ULongToPtr(status_extra32->rgCertIdStatus);

        policy_status.pvExtraPolicyStatus = &status_extra;
    }

    status = proxy_CertDllVerifyCertificateChainPolicy(&params);
    if (!status)
    {
        policy_status32->cbSize = sizeof(*policy_status32);
        policy_status32->dwError = policy_status.dwError;
        policy_status32->lChainIndex = policy_status.lChainIndex;
        policy_status32->lElementIndex = policy_status.lElementIndex;

        if (policy_status32->pvExtraPolicyStatus)
        {
            const struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS *extra = policy_status.pvExtraPolicyStatus;
            struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS32 *extra32 = UlongToPtr(policy_status32->pvExtraPolicyStatus);

            extra32->cbSize = sizeof(*extra32);
            extra32->dwError = extra->dwError;
            extra32->lChainIndex = extra->lChainIndex;
            extra32->lElementIndex = extra->lElementIndex;
            extra32->fNoCheck = extra->fNoCheck;
            /* there's no need to translate back extra32->rgCertIdStatus */
        }
    }

    return status;
}

static NTSTATUS wow64_CertDllVerifyTimestampSigningCertificateChainPolicy(void *args)
{
    struct
    {
        PTR32 policy;
        PTR32 context;
        PTR32 para;
        PTR32 status;
    } *params32 = args;
    NTSTATUS status;
    CERT_CHAIN_CONTEXT context;
    CERT_CHAIN_POLICY_PARA para;
    struct CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA para_extra;
    CERT_CHAIN_POLICY_STATUS policy_status;
    struct CERT_CHAIN_POLICY_STATUS32 *policy_status32;
    struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS status_extra;
    struct VerifyCertificateChainPolicy_params params =
    {
        ULongToPtr(params32->policy),
        &context,
        NULL,
        &policy_status
    };

    copy_CERT_CHAIN_CONTEXT32_to_64(ULongToPtr(params32->context), &context);
    if (params32->para)
    {
        struct CERT_CHAIN_POLICY_PARA32 *para32 = ULongToPtr(params32->para);

        copy_CERT_CHAIN_POLICY_PARA32_to_64(para32, &para);
        if (para32->pvExtraPolicyPara)
        {
            const struct CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA32 *para_extra32 = ULongToPtr(para32->pvExtraPolicyPara);

            para_extra.cbSize = sizeof(para_extra);
            para_extra.pPrivateKeyUsedTime = ULongToPtr(para_extra32->pPrivateKeyUsedTime);

            para.pvExtraPolicyPara = &para_extra;
        }

        params.para = &para;
    }

    policy_status32 = ULongToPtr(params32->status);
    copy_CERT_CHAIN_POLICY_STATUS32_to_64(policy_status32, &policy_status);
    if (policy_status32->pvExtraPolicyStatus)
    {
        struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS32 *status_extra32 = UlongToPtr(policy_status32->pvExtraPolicyStatus);

        status_extra.cbSize = sizeof(status_extra);
        status_extra.dwError = status_extra32->dwError;
        status_extra.lChainIndex = status_extra32->lChainIndex;
        status_extra.lElementIndex = status_extra32->lElementIndex;
        status_extra.fNoCheck = status_extra32->fNoCheck;
        status_extra.rgCertIdStatus = ULongToPtr(status_extra32->rgCertIdStatus);

        policy_status.pvExtraPolicyStatus = &status_extra;
    }

    status = proxy_CertDllVerifyCertificateChainPolicy(&params);
    if (!status)
    {
        policy_status32->cbSize = sizeof(*policy_status32);
        policy_status32->dwError = policy_status.dwError;
        policy_status32->lChainIndex = policy_status.lChainIndex;
        policy_status32->lElementIndex = policy_status.lElementIndex;

        if (policy_status32->pvExtraPolicyStatus)
        {
            const struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS *status_extra = policy_status.pvExtraPolicyStatus;
            struct CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS32 *status_extra32 = UlongToPtr(policy_status32->pvExtraPolicyStatus);

            status_extra32->cbSize = sizeof(*status_extra32);
            status_extra32->dwError = status_extra->dwError;
            status_extra32->lChainIndex = status_extra->lChainIndex;
            status_extra32->lElementIndex = status_extra->lElementIndex;
            status_extra32->fNoCheck = status_extra->fNoCheck;
            /* there's no need to translate back extra32->rgCertIdStatus */
        }
    }

    return status;
}

struct CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA32
{
    DWORD cbSize;
    PTR32 pPrivateKeyUsedTime;
};

static NTSTATUS wow64_CertDllVerifySignatureCertificateChainPolicy(void *args)
{
    struct
    {
        PTR32 policy;
        PTR32 context;
        PTR32 para;
        PTR32 status;
    } *params32 = args;
    NTSTATUS status;
    CERT_CHAIN_CONTEXT context;
    CERT_CHAIN_POLICY_PARA para;
    struct CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA para_extra;
    CERT_CHAIN_POLICY_STATUS policy_status;
    struct CERT_CHAIN_POLICY_STATUS32 *policy_status32;
    struct VerifyCertificateChainPolicy_params params =
    {
        ULongToPtr(params32->policy),
        &context,
        NULL,
        &policy_status
    };

    copy_CERT_CHAIN_CONTEXT32_to_64(ULongToPtr(params32->context), &context);
    if (params32->para)
    {
        struct CERT_CHAIN_POLICY_PARA32 *para32 = ULongToPtr(params32->para);

        copy_CERT_CHAIN_POLICY_PARA32_to_64(para32, &para);
        if (para32->pvExtraPolicyPara)
        {
            const struct CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA32 *para_extra32 = ULongToPtr(para32->pvExtraPolicyPara);

            para_extra.cbSize = sizeof(para_extra);
            para_extra.pPrivateKeyUsedTime = ULongToPtr(para_extra32->pPrivateKeyUsedTime);

            para.pvExtraPolicyPara = &para_extra;
        }

        params.para = &para;
    }

    policy_status32 = ULongToPtr(params32->status);
    copy_CERT_CHAIN_POLICY_STATUS32_to_64(policy_status32, &policy_status);
    /* CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS doesn't contain pointers */
    policy_status.pvExtraPolicyStatus = ULongToPtr(policy_status32->pvExtraPolicyStatus);

    status = proxy_CertDllVerifyCertificateChainPolicy(&params);
    if (!status)
    {
        policy_status32->cbSize = sizeof(*policy_status32);
        policy_status32->dwError = policy_status.dwError;
        policy_status32->lChainIndex = policy_status.lChainIndex;
        policy_status32->lElementIndex = policy_status.lElementIndex;
    }

    return status;
}

static NTSTATUS wow64_CertDllVerifyPrivateKeyUsagePeriodCertificateChainPolicy(void *args)
{
    FIXME(": stub\n");
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS wow64_proxy_CertDllVerifyCertificateChainPolicy(void *args)
{
    struct
    {
        PTR32 policy;
        PTR32 context;
        PTR32 para;
        PTR32 status;
    } const *params32 = args;

    if (!strcasecmp(ULongToPtr(params32->policy), "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"))
        return wow64_CertDllVerifyOCSPSigningCertificateChainPolicy(args);
    else if (!strcasecmp(ULongToPtr(params32->policy), "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}"))
        return wow64_CertDllVerifyTimestampSigningCertificateChainPolicy(args);
    else if (!strcasecmp(ULongToPtr(params32->policy), "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}"))
        return wow64_CertDllVerifySignatureCertificateChainPolicy(args);
    else if (!strcasecmp(ULongToPtr(params32->policy), "{C03D5610-26C8-4B6F-9549-245B5B3AB743}"))
        return wow64_CertDllVerifyPrivateKeyUsagePeriodCertificateChainPolicy(args);

    FIXME("Unknown policy %s\n", debugstr_a(ULongToPtr(params32->policy)));
    return STATUS_NOT_IMPLEMENTED;
}

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    proxy_attach,
    wow64_proxy_GetDefaultProviderA,
    wow64_proxy_CPAcquireContext,
    wow64_proxy_CPReleaseContext,
    wow64_proxy_CPSetProvParam,
    wow64_proxy_CPGetProvParam,
    wow64_proxy_CPCreateHash,
    wow64_proxy_CPDestroyHash,
    wow64_proxy_CPDuplicateHash,
    wow64_proxy_CPSetHashParam,
    wow64_proxy_CPGetHashParam,
    wow64_proxy_CPGenKey,
    wow64_proxy_CPGetUserKey,
    wow64_proxy_CPExportKey,
    wow64_proxy_CPImportKey,
    wow64_proxy_CPDestroyKey,
    wow64_proxy_CPDuplicateKey,
    wow64_proxy_CPSetKeyParam,
    wow64_proxy_CPGetKeyParam,
    wow64_proxy_CPDeriveKey,
    wow64_proxy_CPGenRandom,
    wow64_proxy_CPEncrypt,
    wow64_proxy_CPDecrypt,
    wow64_proxy_CPHashData,
    wow64_proxy_CPHashSessionKey,
    wow64_proxy_CPSignHash,
    wow64_proxy_CPVerifySignature,
    wow64_proxy_CertDllVerifyCertificateChainPolicy,
    wow64_proxy_CertEnumCertificateContextProperties,
    wow64_proxy_CertEnumCertificatesInStore,
    wow64_proxy_CertGetCertificateContextProperty,
    wow64_proxy_CertGetNameStringA,
    wow64_proxy_CertOpenStore,
    wow64_proxy_CertCloseStore,
    wow64_proxy_CertControlStore,
    wow64_proxy_CryptEnumProvidersA,
    wow64_proxy_CryptEnumProviderTypesA,
    wow64_proxy_CryptEnumOIDInfo,
    proxy_free
};

#endif /* _WIN64 */
