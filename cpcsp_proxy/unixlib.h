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

#include "wine/unixlib.h"

struct AcquireContext_params
{
    UINT64 *prov;
    LPSTR container;
    ULONG flags;
    VTableProvStruc *vt;
};

struct ReleaseContext_params
{
    UINT64 prov;
    ULONG flags;
};

struct SetProvParam_params
{
    UINT64 prov;
    ULONG param;
    BYTE *data;
    ULONG flags;
};

struct GetProvParam_params
{
    UINT64 prov;
    ULONG param;
    BYTE *data;
    ULONG *len;
    ULONG flags;
};

struct CreateHash_params
{
    UINT64 prov;
    ULONG algid;
    UINT64 key;
    ULONG flags;
    UINT64 *hash;
};

struct DestroyHash_params
{
    UINT64 prov;
    UINT64 hash;
};

struct DuplicateHash_params
{
    UINT64 prov;
    UINT64 hash;
    ULONG *reserved;
    ULONG flags;
    UINT64 *newhash;
};

struct SetHashParam_params
{
    UINT64 prov;
    UINT64 hash;
    ULONG param;
    BYTE *data;
    ULONG flags;
};

struct GetHashParam_params
{
    UINT64 prov;
    UINT64 hash;
    ULONG param;
    BYTE *data;
    ULONG *len;
    ULONG flags;
};

struct GenKey_params
{
    UINT64 prov;
    ULONG algid;
    ULONG flags;
    UINT64 *key;
};

struct GetUserKey_params
{
    UINT64 prov;
    ULONG keyspec;
    UINT64 *key;
};

struct ExportKey_params
{
    UINT64 prov;
    UINT64 key;
    UINT64 pubkey;
    ULONG type;
    ULONG flags;
    BYTE *data;
    ULONG *len;
};

struct ImportKey_params
{
    UINT64 prov;
    const BYTE *data;
    ULONG len;
    UINT64 pubkey;
    ULONG flags;
    UINT64 *newkey;
};

struct DestroyKey_params
{
    UINT64 prov;
    UINT64 key;
};

struct DuplicateKey_params
{
    UINT64 prov;
    UINT64 key;
    ULONG *reserved;
    ULONG flags;
    UINT64 *newkey;
};

struct SetKeyParam_params
{
    UINT64 prov;
    UINT64 key;
    ULONG param;
    BYTE *data;
    ULONG flags;
};

struct GetKeyParam_params
{
    UINT64 prov;
    UINT64 key;
    ULONG param;
    BYTE *data;
    ULONG *len;
    ULONG flags;
};

struct DeriveKey_params
{
    UINT64 prov;
    ULONG algid;
    UINT64 hash;
    ULONG flags;
    UINT64 *key;
};

struct GenRandom_params
{
    UINT64 prov;
    ULONG len;
    BYTE *buffer;
};

struct Encrypt_params
{
    UINT64 prov;
    UINT64 key;
    UINT64 hash;
    BOOL final;
    ULONG flags;
    BYTE *data;
    ULONG *datalen;
    ULONG buflen;
};

struct Decrypt_params
{
    UINT64 prov;
    UINT64 key;
    UINT64 hash;
    BOOL final;
    ULONG flags;
    BYTE *data;
    ULONG *len;
};

struct HashData_params
{
    UINT64 prov;
    UINT64 hash;
    const BYTE *data;
    ULONG len;
    ULONG flags;
};

struct HashSessionKey_params
{
    UINT64 prov;
    UINT64 hash;
    UINT64 key;
    ULONG flags;
};

struct SignHash_params
{
    UINT64 prov;
    UINT64 hash;
    ULONG keyspec;
    LPCWSTR description;
    ULONG flags;
    BYTE *signature;
    ULONG *len;
};

struct VerifySignature_params
{
    UINT64 prov;
    UINT64 hash;
    const BYTE *signature;
    ULONG len;
    UINT64 pubkey;
    LPCWSTR description;
    ULONG flags;
};

struct GetDefaultProviderA_params
{
    ULONG type;
    ULONG *reserved;
    ULONG flags;
    LPSTR prov_name;
    ULONG *prov_name_size;
};

struct CertEnumCertificateContextProperties_params
{
    PCCERT_CONTEXT ctx;
    ULONG *propid; /* in/out */
};

struct CertEnumCertificatesInStore_params
{
    UINT64 store;
    PCCERT_CONTEXT prev;
    PCCERT_CONTEXT ctx;
};

struct CertGetCertificateContextProperty_params
{
    PCCERT_CONTEXT ctx;
    ULONG propid;
    void *data;
    ULONG *size;
};

struct CertGetNameStringA_params
{
    PCCERT_CONTEXT ctx;
    ULONG type;
    ULONG flags;
    void *para;
    LPSTR name;
    ULONG *size;
};

struct CertOpenStore_params
{
    LPCSTR provider;
    ULONG type;
    UINT64 legacy;
    ULONG flags;
    const void *para;
    UINT64 store; /* ret */
};

struct CertCloseStore_params
{
    UINT64 store;
    ULONG flags;
};

struct CertControlStore_params
{
    UINT64 store;
    ULONG flags;
    ULONG type;
    void const *para;
};

struct CryptEnumProvidersA_params
{
    ULONG index;
    ULONG *reserved;
    ULONG flags;
    ULONG *type;
    LPSTR name;
    ULONG *size;
};

struct CryptEnumProviderTypesA_params
{
    ULONG index;
    ULONG *reserved;
    ULONG flags;
    ULONG *type;
    LPSTR name;
    ULONG *size;
};

#define MAX_CACHE_SIZE 256
/* PROV_ENUMALGS_EX name limits are 20 and 40 */
struct PROXY_ENUM_OID
{
    char pszOID[256];
    WCHAR pwszName[40];
    ULONG dwGroupId;
    ULONG Algid;
    struct
    {
        ULONG cbData;
        BYTE pbData[256];
    } extra;
#ifdef CRYPT_OID_INFO_HAS_EXTRA_FIELDS
    WCHAR pwszCNGAlgid[40];
    WCHAR pwszCNGExtraAlgid[40];
#endif
};

struct CryptEnumOIDInfo_params
{
    ULONG count;
    struct PROXY_ENUM_OID info[MAX_CACHE_SIZE];
};

struct VerifyCertificateChainPolicy_params
{
    LPCSTR policy;
    PCCERT_CHAIN_CONTEXT context;
    PCERT_CHAIN_POLICY_PARA para;
    PCERT_CHAIN_POLICY_STATUS status;
};

enum unix_funcs
{
    unix_attach,
    unix_GetDefaultProviderA,
    unix_CPAcquireContext,
    unix_CPReleaseContext,
    unix_CPSetProvParam,
    unix_CPGetProvParam,
    unix_CPCreateHash,
    unix_CPDestroyHash,
    unix_CPDuplicateHash,
    unix_CPSetHashParam,
    unix_CPGetHashParam,
    unix_CPGenKey,
    unix_CPGetUserKey,
    unix_CPExportKey,
    unix_CPImportKey,
    unix_CPDestroyKey,
    unix_CPDuplicateKey,
    unix_CPSetKeyParam,
    unix_CPGetKeyParam,
    unix_CPDeriveKey,
    unix_CPGenRandom,
    unix_CPEncrypt,
    unix_CPDecrypt,
    unix_CPHashData,
    unix_CPHashSessionKey,
    unix_CPSignHash,
    unix_CPVerifySignature,
    unix_CertDllVerifyCertificateChainPolicy,
    unix_CertEnumCertificateContextProperties,
    unix_CertEnumCertificatesInStore,
    unix_CertGetCertificateContextProperty,
    unix_CertGetNameStringA,
    unix_CertOpenStore,
    unix_CertCloseStore,
    unix_CertControlStore,
    unix_CryptEnumProvidersA,
    unix_CryptEnumProviderTypesA,
    unix_CryptEnumOIDInfo,
    unix_free
};

#define PROXY_CALL(func, params) proxy_call(#func, unix_ ## func, params)
