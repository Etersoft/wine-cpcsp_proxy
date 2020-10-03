/*
 * Copyright (C) 2019 Dmitry Timoshkov for Etersoft
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

// include it after all needed headers

static const char *propid_to_name(DWORD propid)
{
#define name(id) if (propid == id) return #id
    name(CERT_KEY_PROV_HANDLE_PROP_ID);
    name(CERT_KEY_PROV_INFO_PROP_ID);
    name(CERT_SHA1_HASH_PROP_ID);
    name(CERT_MD5_HASH_PROP_ID);
    name(CERT_KEY_CONTEXT_PROP_ID);
    name(CERT_KEY_SPEC_PROP_ID);
    name(CERT_IE30_RESERVED_PROP_ID);
    name(CERT_PUBKEY_HASH_RESERVED_PROP_ID);
    name(CERT_ENHKEY_USAGE_PROP_ID);
    name(CERT_NEXT_UPDATE_LOCATION_PROP_ID);
    name(CERT_FRIENDLY_NAME_PROP_ID);
    name(CERT_PVK_FILE_PROP_ID);
    name(CERT_DESCRIPTION_PROP_ID);
    name(CERT_ACCESS_STATE_PROP_ID);
    name(CERT_SIGNATURE_HASH_PROP_ID);
    name(CERT_SMART_CARD_DATA_PROP_ID);
    name(CERT_EFS_PROP_ID);
    name(CERT_FORTEZZA_DATA_PROP_ID);
    name(CERT_ARCHIVED_PROP_ID);
    name(CERT_KEY_IDENTIFIER_PROP_ID);
    name(CERT_AUTO_ENROLL_PROP_ID);
    name(CERT_PUBKEY_ALG_PARA_PROP_ID);
    name(CERT_CROSS_CERT_DIST_POINTS_PROP_ID);
    name(CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID);
    name(CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID);
    name(CERT_ENROLLMENT_PROP_ID);
    name(CERT_DATE_STAMP_PROP_ID);
    name(CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID);
    name(CERT_SUBJECT_NAME_MD5_HASH_PROP_ID);
    name(CERT_EXTENDED_ERROR_INFO_PROP_ID);
    name(CERT_RENEWAL_PROP_ID);
    name(CERT_ARCHIVED_KEY_HASH_PROP_ID);
    name(CERT_AUTO_ENROLL_RETRY_PROP_ID);
    name(CERT_AIA_URL_RETRIEVED_PROP_ID);
    name(CERT_AUTHORITY_INFO_ACCESS_PROP_ID);
    name(CERT_BACKED_UP_PROP_ID);
    name(CERT_OCSP_RESPONSE_PROP_ID);
    name(CERT_REQUEST_ORIGINATOR_PROP_ID);
    name(CERT_SOURCE_LOCATION_PROP_ID);
    name(CERT_SOURCE_URL_PROP_ID);
    name(CERT_NEW_KEY_PROP_ID);
    name(CERT_OCSP_CACHE_PREFIX_PROP_ID);
    name(CERT_SMART_CARD_ROOT_INFO_PROP_ID);
    name(CERT_NO_AUTO_EXPIRE_CHECK_PROP_ID);
    name(CERT_NCRYPT_KEY_HANDLE_PROP_ID);
    name(CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID);
    name(CERT_SUBJECT_INFO_ACCESS_PROP_ID);
    name(CERT_CA_OCSP_AUTHORITY_INFO_ACCESS_PROP_ID);
    name(CERT_CA_DISABLE_CRL_PROP_ID);
    name(CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID);
    name(CERT_ROOT_PROGRAM_NAME_CONSTRAINTS_PROP_ID);
#undef name

    return "unknown";
}

