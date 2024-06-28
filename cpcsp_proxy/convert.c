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

#define NONAMELESSUNION
#define NONAMELESSSTRUCT

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "wincrypt.h"
#include "snmp.h"
#include "winnls.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpcsp_proxy);

#define PUBKEY_MAGIC ('M' | 'A' << 8 | 'G' << 16 | '1' << 24)

#include "pshpack1.h"

typedef struct _CRYPT_PUBKEYPARAM
{
    DWORD Magic;
    DWORD BitLen;
} CRYPT_PUBKEYPARAM;

typedef struct _CRYPT_PUBKEY_INFO_HEADER
{
    BLOBHEADER BlobHeader;
    CRYPT_PUBKEYPARAM KeyParam;
} CRYPT_PUBKEY_INFO_HEADER;

typedef struct _CRYPT_PUBLICKEYBLOB
{
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
    BYTE bASN1GostR3410_2001_PublicKeyParameters[1];
    BYTE bPublicKey[1];
} CRYPT_PUBLICKEYBLOB;

#include "poppack.h"

static BOOL convert_pubkey_info(const CERT_PUBLIC_KEY_INFO *info, ALG_ID algid, BYTE **data, DWORD *size)
{
    CRYPT_PUBLICKEYBLOB *blob;
    DWORD blob_size, bitlen;
    const BYTE *pubkey;
    BYTE *blob_pubkey;

    blob_size = FIELD_OFFSET(CRYPT_PUBLICKEYBLOB, bASN1GostR3410_2001_PublicKeyParameters);
    blob_size += info->Algorithm.Parameters.cbData;

    pubkey = info->PublicKey.pbData;

    if (info->PublicKey.cbData == 131)
    {
        if (pubkey[0] != ASN_OCTETSTRING || pubkey[1] != 0x81 || pubkey[2] != 0x80)
        {
            SetLastError(NTE_BAD_PUBLIC_KEY);
            return FALSE;
        }
        bitlen = 1024;
        pubkey += 3;
        blob_size += info->PublicKey.cbData - 3;
    }
    else if (info->PublicKey.cbData == 66)
    {
        if (pubkey[0] != ASN_OCTETSTRING || pubkey[1] != 0x40)
        {
            SetLastError(NTE_BAD_PUBLIC_KEY);
            return FALSE;
        }
        bitlen = 512;
        pubkey += 2;
        blob_size += info->PublicKey.cbData - 2;
    }
    else
    {
        SetLastError(NTE_BAD_DATA);
        return FALSE;
    }

    blob = CryptMemAlloc(blob_size);
    if (!blob)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    blob->tPublicKeyParam.BlobHeader.bType = PUBLICKEYBLOB;
    blob->tPublicKeyParam.BlobHeader.bVersion = CUR_BLOB_VERSION;
    blob->tPublicKeyParam.BlobHeader.reserved = 0;
    blob->tPublicKeyParam.BlobHeader.aiKeyAlg = algid;

    blob->tPublicKeyParam.KeyParam.Magic = PUBKEY_MAGIC;
    blob->tPublicKeyParam.KeyParam.BitLen = bitlen;

    memcpy(blob->bASN1GostR3410_2001_PublicKeyParameters, info->Algorithm.Parameters.pbData, info->Algorithm.Parameters.cbData);

    blob_pubkey = (BYTE *)blob + FIELD_OFFSET(CRYPT_PUBLICKEYBLOB, bASN1GostR3410_2001_PublicKeyParameters) + info->Algorithm.Parameters.cbData;
    memcpy(blob_pubkey, pubkey, bitlen / 8);

    *data = (BYTE *)blob;
    *size = blob_size;

    return TRUE;
}

BOOL WINAPI CryptDllConvertPublicKeyInfo(DWORD type, const CERT_PUBLIC_KEY_INFO *info, ALG_ID algid,
                                         DWORD flags, BYTE **data, DWORD *size)
{
    PCCRYPT_OID_INFO oid_info;

    TRACE("(%08x,%p,%04x,%08x,%p,%p)\n", type, info, algid, flags, data, size);

    if (!(type & (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)) || (type & ~(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)))
    {
        SetLastError(NTE_BAD_TYPE);
        return FALSE;
    }

    if (flags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }

    if (!info || !data || !size)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    oid_info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, info->Algorithm.pszObjId, 0);
    if (!oid_info)
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }

    TRACE("cert algid %04x, cert oid %s, algid %04x\n", oid_info->u.Algid, debugstr_a(oid_info->pszOID), algid);

    if (!info->PublicKey.pbData || !info->PublicKey.cbData ||
        (!info->Algorithm.Parameters.pbData && info->Algorithm.Parameters.cbData))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    switch (algid)
    {
    case 0:
        algid = oid_info->u.Algid;
        /* fall through */
    case 0x2e23:
    case 0x2e3d:
    case 0x2e49:
    case 0xaa24:
    case 0xaa42:
    case 0xaa46:
        return convert_pubkey_info(info, algid, data, size);

    default:
        FIXME("unknown algid %#x\n", algid);
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }

    return TRUE;
}

static DWORD asn1_size(const BYTE *data, DWORD *hdr_size)
{
    DWORD size = 0;

    if (data[0] == ASN_SEQUENCE || data[0] == ASN_OBJECTIDENTIFIER || data[0] == ASN_NULL)
    {
        if (data[1] & 0x80)
        {
            DWORD count = data[1] & 0x7f;
            const BYTE *p = &data[2];

            if (hdr_size)
                *hdr_size = count + 2;

            while (count--)
                size = (size << 8) | (*p++);

            size += p - data;
        }
        else
        {
            if (hdr_size)
                *hdr_size = 2;
            size = data[1] + 2;
        }
    }

    return size;
}

static BOOL encode_pubkey_info(const CRYPT_PUBLICKEYBLOB *blob, DWORD blob_size,
                               BYTE **key_data, DWORD *key_size, BYTE **params_data, DWORD *params_size)
{
    const BYTE *blob_pubkey, *blob_params;
    BYTE *data, *pubkey, *params;
    DWORD size, blob_params_size;

    if (blob->tPublicKeyParam.KeyParam.Magic != PUBKEY_MAGIC)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    switch (blob->tPublicKeyParam.KeyParam.BitLen)
    {
    case 512:
        size = 66;
        break;

    case 1024:
        size = 131;
        break;

    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    blob_params = (const BYTE *)blob + FIELD_OFFSET(CRYPT_PUBLICKEYBLOB, bASN1GostR3410_2001_PublicKeyParameters);
    blob_params_size = asn1_size(blob_params, NULL);

    blob_pubkey = blob_params + blob_params_size;

    params = CryptMemAlloc(blob_params_size);
    if (!params)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    memcpy(params, blob_params, blob_params_size);

    data = pubkey = CryptMemAlloc(size);
    if (!pubkey)
    {
        CryptMemFree(params);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (blob->tPublicKeyParam.KeyParam.BitLen == 512)
    {
        pubkey[0] = ASN_OCTETSTRING;
        pubkey[1] = 0x40;
        pubkey += 2;
    }
    else /* 1024 */
    {
        pubkey[0] = ASN_OCTETSTRING;
        pubkey[1] = 0x81;
        pubkey[2] = 0x80;
        pubkey += 3;
    }

    memcpy(pubkey, blob_pubkey, blob->tPublicKeyParam.KeyParam.BitLen / 8);

    *key_data = data;
    *key_size = size;
    *params_data = params;
    *params_size = blob_params_size;

    return TRUE;
}

BOOL WINAPI CryptDllEncodePublicKeyAndParameters(DWORD type, LPSTR objid, const CRYPT_PUBLICKEYBLOB *blob, DWORD blob_size,
                                                 DWORD flags, void *aux, BYTE **key_data, DWORD *key_size,
                                                 BYTE **params, DWORD *params_size)
{
    PCCRYPT_OID_INFO oid_info;

    TRACE("(%08x,%s,%p,%08x,%08x,%p,%p,%p,%p,%p)\n", type, debugstr_a(objid), blob, blob_size, flags,
          aux, key_data, key_size, params, params_size);

    if (!(type & (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)) || (type & ~(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)))
    {
        SetLastError(NTE_BAD_TYPE);
        return FALSE;
    }

    if (flags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }

    if (!objid || !blob || !blob_size || !key_data || !key_size || !params || !params_size)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    oid_info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, objid, 0);
    if (!oid_info)
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }

    TRACE("cert algid %04x, cert oid %s\n", oid_info->u.Algid, debugstr_a(oid_info->pszOID));

    switch (blob->tPublicKeyParam.BlobHeader.aiKeyAlg)
    {
    case 0x2e23:
    case 0x2e3d:
    case 0x2e49:
    case 0xaa24:
    case 0xaa42:
    case 0xaa46:
        return encode_pubkey_info(blob, blob_size, key_data, key_size, params, params_size);

    default:
        FIXME("unknown algid %#x\n", blob->tPublicKeyParam.BlobHeader.aiKeyAlg);
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }

    return FALSE;
}
