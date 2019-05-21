/* vim:set sw=4 ts=8 fileencoding=cp1251::���������:WINDOWS-1251[���������] */
#ifdef _WIN32
    #pragma setlocale("rus")
#endif
/*
 * Copyright(C) 2000-2014 ������ ���
 *
 * ���� ���� �������� ����������, ����������
 * �������������� �������� ������-���.
 *
 * ����� ����� ����� ����� �� ����� ���� �����������,
 * ����������, ���������� �� ������ �����,
 * ������������ ��� �������������� ����� ��������,
 * ���������������, �������� �� ���� � ��� ��
 * ����� ������������ ������� ��� ����������������
 * ���������� ���������� � ��������� ������-���.
 */

/*!
 * \file $RCSfile$
 * \version $Revision: 173188 $
 * \date $Date:: 2018-04-11 12:08:44 +0300#$
 * \author $Author: borodin $
 *
 * \brief ��������� ��������� CSP, ���������� � WinCrypt.h.
 */

#ifndef _WINCRYPTEX_H_INCLUDED
#define _WINCRYPTEX_H_INCLUDED

#ifndef _WINCRYPTEX_USE_EXTERNAL_TYPES

#if defined UNIX || defined CSP_LITE
#include "CSP_WinCrypt.h"
#else // UNIX
#include <wincrypt.h>
#endif // UNIX

#endif // _WINCRYPTEX_USE_EXTERNAL_TYPES

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// ����� ����������� ��� � CSP 1.1
#define CP_DEF_PROV_A "Crypto-Pro Cryptographic Service Provider"
#define CP_DEF_PROV_W L"Crypto-Pro Cryptographic Service Provider"
#ifdef UNICODE
#define CP_DEF_PROV CP_DEF_PROV_W
#else //!UNICODE
#define CP_DEF_PROV CP_DEF_PROV_A
#endif //!UNICODE

// ����� ����������� ��� � CSP 2.0
#define CP_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#define CP_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_94_PROV CP_GR3410_94_PROV_W
#else //!UNICODE
#define CP_GR3410_94_PROV CP_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#define CP_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2001_PROV CP_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_GR3410_2001_PROV CP_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_GR3410_2012_PROV_A "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2012_PROV CAT_L(CP_GR3410_2012_PROV_A)
#else //!UNICODE
#define CP_GR3410_2012_PROV CP_GR3410_2012_PROV_A
#endif //!UNICODE

#define CP_GR3410_2012_STRONG_PROV_A "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2012_STRONG_PROV CAT_L(CP_GR3410_2012_STRONG_PROV_A)
#else //!UNICODE
#define CP_GR3410_2012_STRONG_PROV CP_GR3410_2012_STRONG_PROV_A
#endif //!UNICODE

#define CP_RSA_AES_ENH_PROV_A "Crypto-Pro Enhanced RSA and AES CSP"
#ifdef UNICODE
#define CP_RSA_AES_ENH_PROV CAT_L(CP_RSA_AES_ENH_PROV_A)
#else //!UNICODE
#define CP_RSA_AES_ENH_PROV CP_RSA_AES_ENH_PROV_A
#endif //!UNICODE

#define CP_ECDSA_AES_PROV_A "Crypto-Pro ECDSA and AES CSP"
#ifdef UNICODE
#define CP_ECDSA_AES_PROV CAT_L(CP_ECDSA_AES_PROV_A)
#else //!UNICODE
#define CP_ECDSA_AES_PROV CP_ECDSA_AES_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 KC1 CSP"
#define CP_KC1_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_94_PROV CP_KC1_GR3410_94_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_94_PROV CP_KC1_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 KC1 CSP"
#define CP_KC1_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_PROV CP_KC1_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_PROV CP_KC1_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2012_PROV_A "Crypto-Pro GOST R 34.10-2012 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2012_PROV CAT_L(CP_KC1_GR3410_2012_PROV_A)
#else //!UNICODE
#define CP_KC1_GR3410_2012_PROV CP_KC1_GR3410_2012_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2012_STRONG_PROV_A "Crypto-Pro GOST R 34.10-2012 KC1 Strong CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2012_STRONG_PROV CAT_L(CP_KC1_GR3410_2012_STRONG_PROV_A)
#else //!UNICODE
#define CP_KC1_GR3410_2012_STRONG_PROV CP_KC1_GR3410_2012_STRONG_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 KC2 CSP"
#define CP_KC2_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_94_PROV CP_KC2_GR3410_94_PROV_W
#else //!UNICODE
#define CP_KC2_GR3410_94_PROV CP_KC2_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 KC2 CSP"
#define CP_KC2_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2001_PROV CP_KC2_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_KC2_GR3410_2001_PROV CP_KC2_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2012_PROV_A "Crypto-Pro GOST R 34.10-2012 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2012_PROV CAT_L(CP_KC2_GR3410_2012_PROV_A)
#else //!UNICODE
#define CP_KC2_GR3410_2012_PROV CP_KC2_GR3410_2012_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2012_STRONG_PROV_A "Crypto-Pro GOST R 34.10-2012 KC2 Strong CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2012_STRONG_PROV CAT_L(CP_KC2_GR3410_2012_STRONG_PROV_A)
#else //!UNICODE
#define CP_KC2_GR3410_2012_STRONG_PROV CP_KC2_GR3410_2012_STRONG_PROV_A
#endif //!UNICODE

#define PH_GR3410_2001_PROV_A "Phoenix-CS GOST R 34.10-2001 Cryptographic Service Provider"
#define PH_GR3410_2001_PROV_W L"Phoenix-CS GOST R 34.10-2001 Cryptographic Service Provider"
#ifdef UNICODE
#define PH_GR3410_2001_PROV PH_GR3410_2001_PROV_W
#else //!UNICODE
#define PH_GR3410_2001_PROV PH_GR3410_2001_PROV_A
#endif //!UNICODE

#ifdef _WIN32
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_A "GOST R 34.10-2001 Magistra CSP"
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_W L"GOST R 34.10-2001 Magistra CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_A "GOST R 34.10-2001 Rutoken CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_W L"GOST R 34.10-2001 Rutoken CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_A "GOST R 34.10-2001 eToken CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_W L"GOST R 34.10-2001 eToken CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_A "GOST R 34.10-2001 eToken GOST CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_W L"GOST R 34.10-2001 eToken GOST CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_A "CryptoPro GOST R 34.10-2001 UEC CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_W L"CryptoPro GOST R 34.10-2001 UEC CSP"
#else
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_MAGISTRA_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_RUTOKEN_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKEN_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_ETOKENGOST_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_A "Crypto-Pro GOST R 34.10-2001 FKC CSP"
#  define CP_KC1_GR3410_2001_UECFK_PROV_W L"Crypto-Pro GOST R 34.10-2001 FKC CSP"
#endif

#ifdef UNICODE
#define CP_KC1_GR3410_2001_MAGISTRA_PROV CP_KC1_GR3410_2001_MAGISTRA_PROV_W
#define CP_KC1_GR3410_2001_RUTOKEN_PROV CP_KC1_GR3410_2001_RUTOKEN_PROV_W
#define CP_KC1_GR3410_2001_ETOKEN_PROV CP_KC1_GR3410_2001_ETOKEN_PROV_W
#define CP_KC1_GR3410_2001_ETOKENGOST_PROV CP_KC1_GR3410_2001_ETOKENGOST_PROV_W
#define CP_KC1_GR3410_2001_UECFK_PROV CP_KC1_GR3410_2001_UECFK_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_MAGISTRA_PROV CP_KC1_GR3410_2001_MAGISTRA_PROV_A
#define CP_KC1_GR3410_2001_RUTOKEN_PROV CP_KC1_GR3410_2001_RUTOKEN_PROV_A
#define CP_KC1_GR3410_2001_ETOKEN_PROV CP_KC1_GR3410_2001_ETOKEN_PROV_A
#define CP_KC1_GR3410_2001_ETOKENGOST_PROV CP_KC1_GR3410_2001_ETOKENGOST_PROV_A
#define CP_KC1_GR3410_2001_UECFK_PROV CP_KC1_GR3410_2001_UECFK_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_FLASH_PROV_A "Crypto-Pro Flash Drive KC1 CSP"
#define CP_KC1_GR3410_2001_FLASH_PROV_W L"Crypto-Pro Flash Drive KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_FLASH_PROV CP_KC1_GR3410_2001_FLASH_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_FLASH_PROV CP_KC1_GR3410_2001_FLASH_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_REGISTRY_PROV_A "Crypto-Pro Registry KC1 CSP"
#define CP_KC1_GR3410_2001_REGISTRY_PROV_W L"Crypto-Pro Registry KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_REGISTRY_PROV CP_KC1_GR3410_2001_REGISTRY_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_REGISTRY_PROV CP_KC1_GR3410_2001_REGISTRY_PROV_A
#endif //!UNICODE

#define CRYPTOPRO_TRUSTED_CERT_STORE_NAME_A "CryptoProTrustedStore"
#define CRYPTOPRO_TRUSTED_CERT_STORE_NAME_W L"CryptoProTrustedStore"

/*
 * ???? ���� ��������� PROV_GOST_DH �������� ��������������,
 * �.�. PROV_GOST_DH == 2 == PROV_RSA_SIG
 * ����������� PROV_GOST_2001_DH
 */
#define PROV_GOST_DH 2

/*+
 * �� 09.07.01 � Platform SDK ��������� ������������������
 * CSP - PROV_RSA_AES == 24
 *
 * � ������ ���  PROV_GOST_* ��� ��������� ����� �� ��������� [53..89]
 */
//#pragma deprecated("PROV_GOST_94_DH")
#define PROV_GOST_94_DH 71
#define PROV_GOST_2001_DH 75
#define PROV_GOST_2012_256 80
#define PROV_GOST_2012_512 81

#ifndef PROV_RSA_AES
#define PROV_RSA_AES 24
#endif /*PROV_RSA_AES*/

/* ���� ���������� */
#define KEY_CARRIER_VERSION_V1 1
#define KEY_CARRIER_VERSION_V2 2
#define KEY_CARRIER_VERSION_V3 3 /* FKC-1. unused in 5.0 */
#define KEY_CARRIER_VERSION_V4 4 /* FKC-2. */

/* �������������� ���� �����������.
 * � Platform SDK ���������� ������ CRYPT_ASN_ENCODING (1),
 * CRYPT_NDR_ENCODING (2) � �������� ���� 0x10000 (PKCS7). */
#define CRYPT_XER_ENCODING (8)

/* �������������� ����� AcquireContext. ���������� ��������� ����������������. */
#define CRYPT_GENERAL				0x00004000
#define CRYPT_NOSERIALIZE			0x00010000 // ������� � 3.6.5327, �� ����� ��� 0x8000
#define CRYPT_REBOOT				0x00020000
#define CRYPT_PROMT_INSERT_MEDIA		0x00040000 // ������������ � 3.6.5360
#define CRYPT_UECDATACONTEXT			0x00080000
#define CRYPT_CMS_HIGHLOAD_NOSERIALIZE		0x00100000
#define CRYPT_LOCAL_PASSWORD_CACHE              0x00200000
#define CRYPT_NO_CONTAINER_CACHE                0x00400000

#define ACQUIRE_CONTEXT_SUPPORTED_FLAGS		(CRYPT_GENERAL | CRYPT_NOSERIALIZE | CRYPT_REBOOT | CRYPT_PROMT_INSERT_MEDIA | CRYPT_UECDATACONTEXT | CRYPT_CMS_HIGHLOAD_NOSERIALIZE | CRYPT_NO_CONTAINER_CACHE | CRYPT_LOCAL_PASSWORD_CACHE)

// �������������� ����� PFXImportCertStore
#ifndef PKCS12_IMPORT_SILENT
    #define PKCS12_IMPORT_SILENT        0x00000040
#endif

// �������������� ����� PFXExportCertStoreEx
#ifndef PKCS12_PROTECT_TO_DOMAIN_SIDS
    #define PKCS12_PROTECT_TO_DOMAIN_SIDS           0x0020
#endif
#ifndef PKCS12_EXPORT_SILENT
    #define PKCS12_EXPORT_SILENT                    0x0040
#endif

#define szOID_PKCS_12_pbeWithGostR3411_94_AndGost28147_89_CryptoPro_A_ParamSet        "1.2.840.113549.1.12.1.80"

#define szOID_PKCS_5_PBES2			    "1.2.840.113549.1.5.13"

/*
 * // dwFlags definitions for CryptAcquireContext
 * #define CRYPT_VERIFYCONTEXT			0xF0000000
 * #define CRYPT_NEWKEYSET			0x00000008
 * #define CRYPT_DELETEKEYSET			0x00000010
 * #define CRYPT_MACHINE_KEYSET			0x00000020
 * #define CRYPT_SILENT				0x00000040
 * #if (NTDDI_VERSION >= NTDDI_WINLH)
 * #define CRYPT_DEFAULT_CONTAINER_OPTIONAL	0x00000080
 * #endif //(NTDDI_VERSION >= NTDDI_WINLH)
 *... 
 * //  The following define must not collide with any of the
 * //  CryptAcquireContext dwFlag defines.
 * //-------------------------------------------------------
 * #define CERT_SET_KEY_PROV_HANDLE_PROP_ID	0x00000001
 * #define CERT_SET_KEY_CONTEXT_PROP_ID		0x00000001
 */

/*����� CryptSetProvParam*/
/* ���� ��� ����������� ������ � ������� */
#define CP_CRYPT_SAVE_PASSWORD 0x00001000

/* ����, �����������, ��� ����������� ���������������� ����� ��������� 
 * ������ � �������� ��������� ���������� */
#define CP_CRYPT_CACHE_ONLY 0x00002000

/* �������������� ����� CryptMsgOpenToEncode � CryptMsgControl, ������������
 * ��������� ��� ������������ ������� CAdES-BES. */
#define CPCMSG_CADES_STRICT		    (0x00000100)
#define CPCMSG_CADES_DISABLE                (0x00000200)
#define CPCMSG_CADES_DISABLE_CERT_SEARCH    (0x00000400)

/* �������������� ����� CryptMsgOpenToEncode, CryptMsgUpdate, CryptMsgControl,
 * ������������ ����� ������ (�������/��������) ����� ������������ 
 * �� pin-pad/SafeTouch. */
#define CPCMSG_DTBS_CONTENT                 (0x00000800)
#define CPCMSG_DTBS_ATTRIBUTE               (0x00001000)
#define CPCMSG_DTBS_CERTIFICATE             (0x00002000)

/* �������������� ����� CryptSignMessage, ������������
 * ��������� ��� ������������ ������� CAdES-BES. */
#define CPCRYPT_MESSAGE_CADES_STRICT	    (CPCMSG_CADES_STRICT)
#define CPCRYPT_MESSAGE_CADES_DISABLE	    (CPCMSG_CADES_DISABLE)

/* �������������� ����� CryptSignMessage, ������������
 * ����� ������ (�������/��������) ����� ������������ 
 * �� pin-pad/SafeTouch. */
#define CPCRYPT_MESSAGE_DTBS_CONTENT	    (CPCMSG_DTBS_CONTENT)
#define CPCRYPT_MESSAGE_DTBS_ATTRIBUTE	    (CPCMSG_DTBS_ATTRIBUTE)

/* ???? ���� CryptGenKey, ������������ �����, ������������ ��������� � ���.*/
#define CRYPT_ECCNEGATIVE	0x00000400 
#define CRYPT_PUBLICCOMPRESS	0x00000800 

/* ���� GenKey ��� ����������/������� �� ��� ������ ������� (�������������� CRYPT_SGCKEY) */
#define	CP_CRYPT_DH_ALLOWED        0x00002000

/* ���� KP_PERMISSIONS ��� ����������/������� �� */
#define CP_CRYPT_DH_PERMISSION	0x00010000

/* ���� ��������������� ���������� ��������� ����� ��� �������� */
#define CP_CRYPT_CALCULATE_PUBLIC_KEY	(0x80)

/* ���� ImportKey ��� ��������� ���������� ������������� �������������� ��������� ����� */
#define	CP_PUBKEY_REUSABLE        0x00002000

/* �������������� ������ ���������� ����� ��������� ������ �� ��������� ������� ����� ����������*/
#define ISO10126_PADDING 4
#define ANSI_X923_PADDING 5

/* ��������� ���������������� ������ */
#define USERKEY_KEYEXCHANGE			AT_KEYEXCHANGE
#define USERKEY_SIGNATURE			AT_SIGNATURE

#define CP_DISREGARD_STRENGTHENED_KEY_USAGE_CONTROL	(0x80000000)

#define CP_ECC_PLAIN_SIGNATURE				(0x00000008)
#define CP_CONTANER_AFFECTED_SIGNATURE			(0x00000010)

/* Algorithm types */
#define ALG_TYPE_GR3410				(7 << 9)
#define ALG_TYPE_SHAREDKEY			(8 << 9)
/* GR3411 sub-ids */
#define ALG_SID_GR3411				30
#define ALG_SID_GR3411_HASH			39
#define ALG_SID_GR3411_HASH34			40
#define	ALG_SID_GR3411_HMAC_FIXEDKEY		55
#define ALG_SID_UECMASTER_DIVERS		47
#define ALG_SID_SHAREDKEY_HASH			50
#define ALG_SID_FITTINGKEY_HASH			51
/* G28147 sub_ids */
#define ALG_SID_G28147				30
#define ALG_SID_PRODIVERS			38
#define ALG_SID_RIC1DIVERS			40
#define ALG_SID_PRO12DIVERS			45
#define ALG_SID_KDF_TREE_GOSTR3411_2012_256	35
/* Export Key sub_id */
#define ALG_SID_PRO_EXP				31
#define ALG_SID_SIMPLE_EXP			32
#define ALG_SID_PRO12_EXP			33
#define ALG_SID_KEXP_2015_M			36
#define ALG_SID_KEXP_2015_K			37
/* GR3412 sub_ids*/
#define ALG_SID_GR3412_2015_M			48
#define ALG_SID_GR3412_2015_K			49
/* Hash sub ids */
#define ALG_SID_G28147_MAC			31
#define ALG_SID_G28147_CHV			48
#define ALG_SID_TLS1_MASTER_HASH		32
#define ALG_SID_TLS1PRF_2012_256		49
#define ALG_SID_TLS1_MASTER_HASH_2012_256	54
#define ALG_SID_TLS1_MD5_SHA1			15

/*SHA Hash ids*/
#define	ALG_SID_SHA_224                 0x11d
#define ALG_SID_SHA_256                 12
#define ALG_SID_SHA_384                 13
#define ALG_SID_SHA_512                 14

/* GOST R 34.11-2012 hash sub ids */
#define ALG_SID_GR3411_2012_256			33
#define ALG_SID_GR3411_2012_512			34
#define ALG_SID_GR3411_2012_256_HMAC		52
#define ALG_SID_GR3411_2012_512_HMAC		53
#define ALG_SID_GR3411_2012_256_HMAC_FIXEDKEY	56
#define ALG_SID_GR3411_2012_512_HMAC_FIXEDKEY	57
#define ALG_SID_PBKDF2_2012_512			58
#define ALG_SID_PBKDF2_2012_256			59
#define ALG_SID_PBKDF2_94_256			64
#define ALG_SID_GR3411_PRFKEYMAT		74
#define ALG_SID_GR3411_2012_256_PRFKEYMAT	75
#define ALG_SID_GR3411_2012_512_PRFKEYMAT	76

/* GOST R 34.13-2015 hash sub ids */
#define ALG_SID_GR3413_2015_M_IMIT		60
#define ALG_SID_GR3413_2015_K_IMIT		61

#define ALG_SID_CMAC				62
#define ALG_SID_PBKDF2				63

/* VKO GOST R 34.10-2012 512-bit outputs sub-id*/
#define ALG_SID_SYMMETRIC_512			34

/* GOST_DH sub ids */
#define ALG_SID_DH_EX_SF			30
#define ALG_SID_DH_EX_EPHEM			31
#define ALG_SID_PRO_AGREEDKEY_DH		33
#define ALG_SID_GR3410				30
#define ALG_SID_GR3410EL			35
#define ALG_SID_GR3410_12_256			73
#define ALG_SID_GR3410_12_512			61
#define ALG_SID_DH_EL_SF			36
#define ALG_SID_DH_EL_EPHEM			37
#define ALG_SID_DH_GR3410_12_256_SF		70
#define ALG_SID_DH_GR3410_12_256_EPHEM		71
#define ALG_SID_DH_GR3410_12_512_SF		66
#define ALG_SID_DH_GR3410_12_512_EPHEM		67
#define ALG_SID_GR3410_94_ESDH			39
#define ALG_SID_GR3410_01_ESDH			40
#define ALG_SID_GR3410_12_256_ESDH		72
#define ALG_SID_GR3410_12_512_ESDH		63

#define ALG_SID_UECDIVERS			44
#define ALG_SID_UECSYMMETRIC			46
#define ALG_SID_UECSYMMETRIC_EPHEM		47

#define ALG_SID_GENERIC_SECRET			21

#define ALG_CLASS_UECSYMMETRIC                (6 << 13)

#define AT_UECSYMMETRICKEY		   0x80000004 //deprecated
#define AT_SYMMETRIC			   0x80000005


#ifndef CALG_SHA_224
#define CALG_SHA_224 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_224)
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef CALG_SHA_384
#define CALG_SHA_384 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
#endif

#ifndef CALG_SHA_512
#define CALG_SHA_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#endif

#define CALG_GR3411 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411)

#define CALG_GR3411_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256)

#define CALG_GR3411_2012_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512)

#define CALG_GR3411_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HASH)
#define CALG_GR3411_HMAC34 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HASH34)
#define CALG_UECMASTER_DIVERS \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_UECMASTER_DIVERS)
#define CALG_GR3411_HMAC_FIXEDKEY \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HMAC_FIXEDKEY)

#define CALG_GR3411_2012_256_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256_HMAC)
#define CALG_GR3411_2012_512_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512_HMAC)

#define CALG_GR3411_2012_256_HMAC_FIXEDKEY \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256_HMAC_FIXEDKEY)
#define CALG_GR3411_2012_512_HMAC_FIXEDKEY \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512_HMAC_FIXEDKEY)

#define CALG_GR3411_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_PRFKEYMAT)
#define CALG_GR3411_2012_256_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256_PRFKEYMAT)
#define CALG_GR3411_2012_512_PRFKEYMAT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_512_PRFKEYMAT)

#define CALG_G28147_MAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_G28147_IMIT \
    CALG_G28147_MAC

#define CALG_GR3413_2015_M_IMIT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3413_2015_M_IMIT)

#define CALG_GR3413_2015_K_IMIT \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3413_2015_K_IMIT)

#define CALG_CMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_CMAC)

#define CALG_G28147_CHV \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_GR3410 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410)

#define CALG_GR3410EL \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410EL)

#define CALG_GR3410_12_256 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410_12_256)

#define CALG_GR3410_12_512 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410_12_512)

#define CALG_G28147 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147)

#define CALG_SYMMETRIC_512 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SYMMETRIC_512)

#define CALG_GR3412_2015_M \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GR3412_2015_M)

#define CALG_GR3412_2015_K \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GR3412_2015_K)

#define CALG_DH_EX_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_SF)

#define CALG_DH_EX_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_EPHEM)

#define CALG_DH_EX \
    CALG_DH_EX_SF

#define CALG_DH_EL_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_SF)

#define CALG_DH_EL_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_EPHEM)

#define CALG_DH_GR3410_12_256_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_256_SF)

#define CALG_DH_GR3410_12_256_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_256_EPHEM)

#define CALG_DH_GR3410_12_512_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_512_SF)

#define CALG_DH_GR3410_12_512_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_GR3410_12_512_EPHEM)

#define CALG_UECSYMMETRIC \
    (ALG_CLASS_UECSYMMETRIC | ALG_TYPE_BLOCK | ALG_SID_UECSYMMETRIC)
#define CALG_UECSYMMETRIC_EPHEM \
    (ALG_CLASS_UECSYMMETRIC | ALG_TYPE_BLOCK | ALG_SID_UECSYMMETRIC_EPHEM)


#define CALG_GR3410_94_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_94_ESDH)

#define CALG_GR3410_01_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_01_ESDH)

#define CALG_GR3410_12_256_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_12_256_ESDH)

#define CALG_GR3410_12_512_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_12_512_ESDH)

#define CALG_PRO_AGREEDKEY_DH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_BLOCK | ALG_SID_PRO_AGREEDKEY_DH)

#define CALG_PRO12_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO12_EXP)

#define CALG_PRO_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP)

#define CALG_SIMPLE_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP)

#define CALG_KEXP_2015_M \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KEXP_2015_M)

#define CALG_KEXP_2015_K \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KEXP_2015_K)

#define CALG_TLS1PRF_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF_2012_256)

#define CALG_TLS1_MASTER_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH)

#define CALG_TLS1_MASTER_HASH_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH_2012_256)

#define CALG_TLS1_MD5SHA1 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MD5_SHA1)

#define CALG_TLS1_MAC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY)

#define CALG_TLS1_ENC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY)

#define CALG_PBKDF2_2012_512 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2_2012_512)

#define CALG_PBKDF2_2012_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2_2012_256)

#define CALG_PBKDF2_94_256 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2_94_256)

#define CALG_PBKDF2 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_PBKDF2)

#define CALG_SHAREDKEY_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_SHAREDKEY | ALG_SID_SHAREDKEY_HASH)
#define CALG_FITTINGKEY_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_SHAREDKEY | ALG_SID_FITTINGKEY_HASH)

#define CALG_GENERIC_SECRET \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_GENERIC_SECRET)

#define CALG_PRO_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRODIVERS)
#define CALG_RIC_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RIC1DIVERS)
#define CALG_OSCAR_DIVERS CALG_RIC_DIVERS
#define CALG_PRO12_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO12DIVERS)

#define CALG_KDF_TREE_GOSTR3411_2012_256 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_KDF_TREE_GOSTR3411_2012_256)

#ifndef CALG_ECDSA
    #ifndef ALG_SID_ECDSA
    #define ALG_SID_ECDSA                   3
    #endif
    #define CALG_ECDSA              (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA)
#endif

#ifndef CALG_ECDH
    #ifndef ALG_SID_ECDH
    #define ALG_SID_ECDH                    5
    #endif
    #define CALG_ECDH               (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH)
#endif

#ifndef szOID_ECC_PUBLIC_KEY
// iso(1) member-body(2) us(840) 10045 keyType(2) unrestricted(1)
#define szOID_ECC_PUBLIC_KEY	    "1.2.840.10045.2.1"
#endif

#ifndef szOID_ECC_CURVE_P256
// iso(1) member-body(2) us(840) 10045 curves(3) prime(1) 7
#define szOID_ECC_CURVE_P256	    "1.2.840.10045.3.1.7"
#endif

#ifndef szOID_ECC_CURVE_P384
// iso(1) identified-organization(3) certicom(132) curve(0) 34
#define szOID_ECC_CURVE_P384	    "1.3.132.0.34"
#endif

#define szOID_EC_DH		    "1.3.132.1.12"
#define szOID_ECC_CURVE_P192	    "1.2.840.10045.3.1.1"
#define szOID_ECC_CURVE_P224	    "1.3.132.0.33"

#ifndef szOID_ECDSA_SHA224
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 1
#define szOID_ECDSA_SHA224	    "1.2.840.10045.4.3.1"
#endif

#ifndef szOID_ECDSA_SHA256
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 2
#define szOID_ECDSA_SHA256	    "1.2.840.10045.4.3.2"
#endif

#ifndef szOID_ECDSA_SHA384
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 3
#define szOID_ECDSA_SHA384	    "1.2.840.10045.4.3.3"
#endif

#ifndef szOID_ECDSA_SHA512
// iso(1) member-body(2) us(840) 10045 signatures(4) specified(3) 4
#define szOID_ECDSA_SHA512	    "1.2.840.10045.4.3.4"
#endif

#ifndef szOID_NIST_sha224
#define szOID_NIST_sha224	    "2.16.840.1.101.3.4.2.4"
#endif

#ifndef szOID_RSA_SHA224RSA
#define szOID_RSA_SHA224RSA	    "1.2.840.113549.1.1.14"
#endif

// Algorithm is only implemented in CNG.
#define CALG_OID_INFO_CNG_ONLY                   0xFFFFFFFF
// Algorithm is defined in the encoded parameters. Only supported
// using CNG.
#define CALG_OID_INFO_PARAMETERS                 0xFFFFFFFE
// Macro to check for a special ALG_ID used in CRYPT_OID_INFO
#define IS_SPECIAL_OID_INFO_ALGID(Algid)        (Algid >= CALG_OID_INFO_PARAMETERS)

#define	TLS_CIPHER_2001				0x0081
#define TLS_CIPHER_SCSV				0x00FF
#define TLS_CIPHER_2012				0xFF85

#define TLS_LEGACY_SUITE_NAME		L"TLS_GOST_R_3410_WITH_28147_LEGACY"
#define TLS_CIPHER_94_SUITE_NAME	L"TLS_GOST_R_3410_94_WITH_28147_CNT_IMIT"

#define TLS_CIPHER_2001_SUITE_NAME	L"TLS_GOSTR341001_WITH_28147_CNT_IMIT"
#define TLS_CIPHER_2012_SUITE_NAME	L"TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"

#define ALG_TYPE_CIPHER_SUITE                   (15 << 9)

#define CALG_TLS_GOSTR341001_WITH_28147_CNT_IMIT \
    (ALG_TYPE_CIPHER_SUITE | TLS_CIPHER_2001)
#define CALG_TLS_GOSTR341112_256_WITH_28147_CNT_IMIT \
    (ALG_TYPE_CIPHER_SUITE | TLS_CIPHER_2012)

/* KP_PADDING for RSA*/
#define CRYPT_RSA_PKCS		0x00000050 // �� ���������
#define CRYPT_RSA_X_509		0x00000051

/* ������������ ����� ����� GENERIC_SECRET � ����� */
#define MAX_GENERIC_SECRET_KEY_BITLEN   4096

#define CRYPT_ALG_PARAM_OID_GROUP_ID            20


#define CRYPT_PROMIX_MODE	0x00000001
#define CRYPT_SIMPLEMIX_MODE	0x00000000
#define CRYPT_MIXDUPLICATE	0x00000002

/*��� ��������� ����� ��� �������������� ������ � �������
    ������� CPImportKey � ������ ����� ������� CALG_PRO_EXPORT*/
#define DIVERSKEYBLOB	0x70

/*��� ��������� ����� ��� �������� ���������� � ��������� ������� FKC*/
#define HASHPUBLICKEYEXBLOB 0x71

/*��� ��������� ����� ��� �������������� ������ ������*/
#define KDF_TREE_DIVERSBLOB	0x72

/*��� ��������� ����� PKCS#1 */
#define PKCS1KEYBLOB			    0x18

/*��� ��������� ����� PKCS#8 */
#define PKCS8KEYBLOB			    0x19

#define RSA_CKM_EXTRACT_KEY_FROM_KEY        0xE
#define RSA_CKM_DES_ENCRYPT_DATA            0xF
#define RSA_CKM_CONCATENATE_BASE_AND_KEY    0x2
#define RSA_CKM_CONCATENATE_BASE_AND_DATA   0x3
#define RSA_CKM_CONCATENATE_DATA_AND_BASE   0x4
#define RSA_CKM_XOR_BASE_AND_DATA           0x5
#define RSA_CKM_SHA1_KEY_DERIVATION         0x11

/* �������������� ��������� ���������������� */
#if !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 36) 
#define PP_LAST_ERROR 90 //deprecated
#endif
#define PP_ENUMOIDS_EX 91
#define PP_HASHOID 92
#define PP_CIPHEROID 93
#define PP_SIGNATUREOID 94
#define PP_DHOID 95
#define PP_RESERVED1 96
#define PP_BIO_STATISTICA_LEN 97
//#pragma deprecated("PP_REBOOT")
#define PP_REBOOT 98
/*��������� �������� ������������ ��� �������� �� ���������, �������� �� WIN32*/
/*#define PP_ANSILASTERROR 99*/
#define PP_RANDOM 100
/*#define PP_DRVCONTAINER	101*/
#define PP_MUTEX_ARG	102
#define PP_ENUM_HASHOID 103
#define PP_ENUM_CIPHEROID 104
#define PP_ENUM_SIGNATUREOID 105
#define PP_ENUM_DHOID	106
#define PP_SET_PIN 107
#define PP_CHANGE_PIN 108
#define PP_HCRYPTPROV 109
#define PP_SELECT_CONTAINER 110
#define PP_FQCN 111
#define PP_CHECKPUBLIC 112
#define PP_ADMIN_CHECKPUBLIC 113
#define PP_ENUMREADERS 114
#define PP_CACHE_SIZE 115
#define PP_NK_SYNC 117
#define PP_INFO 118
#define PP_PIN_INFO 120
#define PP_PASSWD_TERM 123
#define PP_SAME_MEDIA 124
#define PP_DELETE_KEYSET 125
#define PP_DELETE_SAVED_PASSWD 126
#define PP_VERSION_TIMESTAMP 127
#define PP_SECURITY_LEVEL 129
#define PP_FAST_CODE_FUNCS 131
#define PP_CONTAINER_EXTENSION 132
#define PP_ENUM_CONTAINER_EXTENSION 133
#define PP_CONTAINER_EXTENSION_DEL 134
#define PP_CONTAINER_DEFAULT 135
#define PP_LCD_QUERY 136
#define PP_ENUM_LOG 137
#define PP_VERSION_EX 138
#define PP_FAST_CODE_FLAGS 139
#define PP_ENCRYPTION_CARRIER 140
#define PP_FKC				141
#define PP_FRIENDLY_NAME		142
#define PP_FKC_DH_CHECK			143
#define PP_DELETE_SHORTCUT 144
#define PP_SELFTEST	    145
#define PP_CONTAINER_STATUS  146
#define PP_PUBLIC_EXPONENT 147
#define PP_UEC 147
#define PP_UEC_PHRASE 148
#define PP_UEC_PIN1 149
#define PP_UEC_AUTH 150
#define PP_UEC_DATA_TAG 151
#define PP_UEC_DATA_BIN 152
#define PP_UEC_PUK 153
#define PP_UEC_NEED_PIN 154
#define PP_KEY_PERIOD 155
#define PP_UEC_CONTAINER_NAME 156
#define PP_UEC_CHANGE_PIN1 157
#define PP_LICENSE 158
#define PP_RESERVED2	     159
#define PP_RESERVED3         160	
#define PP_THREAD_ID 161
#define PP_CREATE_THREAD_CSP 162
#define PP_HANDLE_COUNT 163
#define PP_CONTAINER_VERSION 164
#define PP_PASSWORD_CACHE 165
#define PP_RNG_INITIALIZED 166
#define PP_CPU_USAGE 167
#define PP_MEMORY_USAGE 168

#define PP_SIGNATURE_KEY_FP 211
#define PP_EXCHANGE_KEY_FP 212
#define PP_SUPPORTED_FLAGS 213

/* �����, ������������ � GetProvParam ��� ��������� �������� � ������������� ������ �������.*/
#define CRYPT_CUR_HANDLES 0
#define CRYPT_MAX_HANDLES 1

/*�����, ����������� � GetProvParam(PP_CPU_USAGE � PP_MEMORY_USAGE) */
#define CPU_USAGE 0
#define CPU_USAGE_BY_PROC 1
#define VIRTUAL_MEMORY_TOTAL 0
#define VIRTUAL_MEMORY_USED 1
#define VIRTUAL_MEMORY_USED_BY_CURRENT_PROC 2
#define PHYSICAL_MEMORY_TOTAL 3
#define PHYSICAL_MEMORY_USED 4
#define PHYSICAL_MEMORY_USED_BY_CURRENT_PROC 5


#define PP_WND_READER_INFO 214
#define PP_WND_ENUM_READERS 215
#define PP_WND_READER_ICON 216

#define PP_CARRIER_TYPES 217

#define PP_AUTH_INFO 218
#define PP_SET_AUTH 219
#define PP_CHANGE_AUTH 220
#define PP_SAVE_PASSWORD_POLICY 221
#define PP_CONTAINER_PARAM 222
#define PP_CARRIER_FLAGS 223
#define PP_ENUMRANDOMS 224
#define PP_HARDWARE_STORE_FLAGS 225

/* ����, ����������� ��� ������������ �������� ������ ���������� � �������, 
    ������������ � ����� ����������������.*/
#define CRYPT_FILTER_PROVIDER_TYPE 0x100

/* ����, ������������ ��� ������������ ������������, ��� ��������� ������ ������������ ������������
*/
#define CRYPT_AVAILABLE 0x40

/* ����, ������������ ��� ������������ ������������, ��� ��������� ����� ��������
*/
#define CRYPT_MEDIA 0x20

/* ����, ������������ ��� ������������ �����������, ��� ���������:
    Fully Qualified Container Name */
#define CRYPT_FQCN 0x10

/* ����, ������������ ��� ������������ �����������, ��� ����������
    ��������� ���������� ��� ����������� ����� �������� �������.
    � ������ ���������� ���������� ������ ��� ���������� �����,
    ����� ����������� ������ ���������� ������� ��� ����������. */
#define CRYPT_UNIQUE 0x08

/* ���� ������������ ��� ������������ ������� �������,
   ��� ���������� ������������ � ���������� �������. */
#define CRYPT_FINISH 0x04

/* ����, ��� ������ PP_DELETE_ERROR � �������� ���������� �����������
    �� ����� ����� ��������� �� ������. */
#define CRYPT_DELETEKEYSET_PART 0x1

/* ����� ������������ ������������, ���������� ���������� �������� � �����������. 
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_NO_MEDIA "NO_MEDIA"

/* ����� ������������ ������������, ����������, ��� �������� ��-���. ��� ���-�����������. 
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_NO_FKC "NO_FKC"

/* ����� ������������ ������������, ����������, ��� �������� ���. ��� ��-���-�����������.
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_FKC "IS_FKC"

/* ����� ������������ ������������, ���������� ���������� ����������� ������ �������� (������������� ��������).
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_NO_UNIQUE "NO_UNIQUE"

/* ����� ������������ ������������, ����������, ��� �������� ����������� ��������. 
   ��-���-��������� ����� ���������� ��� ������ ��� ��-��������.
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_INVALID "INVALID_MEDIA"

/* �������������� ��������� ������� ���� */
#define HP_HASHSTARTVECT 0x0008
#define HP_HASHCOPYVAL	 0x0009
#define HP_OID 0x000a
#define HP_OPEN 0x000B
#define HP_OPAQUEBLOB 0x000C

#define HP_KEYSPEC_SIGN	    0x0010
#define HP_KEYMIXSTART	    0x0011
#define HP_SHAREDKEYMODE    0x0012
#define HP_SHAREDKEYALGID   0x0013
#define HP_DISPLAY_DTBS	    0x0014
#define HP_HMAC_FIXEDKEY    0x0015
#define	HP_IKE_SPI_COOKIE   0x0016
#define HP_PBKDF2_SALT	    0x0017
#define HP_PBKDF2_PASSWORD  0x0018
#define HP_PBKDF2_COUNT	    0x0019
#define HP_PRFKEYMAT_SEED   0x0020
#define HP_HASHVAL_BLOB	    0x0021
#define HP_PBKDF2_HASH_ALGID 0x0022

/* �������������� ��������� ����� */
#define KP_START_DATE	43
#define KP_END_DATE	44
#define KP_UEC_DERIVE_COUNTER 45
#define KP_HANDLE	46
#define KP_SV		KP_IV
#define KP_MIXMODE	101
#define KP_MIXSTART	0x800000e0
#define KP_OID		102
#define KP_HASHOID	103
#define KP_CIPHEROID	104
#define KP_SIGNATUREOID 105
#define KP_DHOID	106
#define KP_FP		107
#define KP_IV_BLOB	108
#define KP_NOTAFTER 109
#define KP_SESSION_HASH 110
#define KP_KC1EXPORT	0x800000f0
#define KP_CHECK_VALUE	0x800000fa

#define KP_STORE	0x800000ff

#define KP_RESERVED1	0x800000fb
#define KP_RESERVED2	0x800000fc
#define KP_ACCLEN	0x800000fd
#define KP_RESERVED3	0x800000fe
#define KP_AUDIT_CONTROL 0x800000d1
#define KP_AUDIT_STATE 0x800000d2

#define CONTAINER_INVALID_HEADER (1<<0)
#define CONTAINER_INVALID_UNKNOWN (1<<30)

/* CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_PRIVATE_KEYS_V1 "1.2.643.2.2.37.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2 "1.2.643.2.2.37.2"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_FULL "1.2.643.2.2.37.2.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_PARTOF "1.2.643.2.2.37.2.2"

/* CRYPT_HASH_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411 "1.2.643.2.2.9"
#define szOID_CP_GOST_R3411_12_256 "1.2.643.7.1.1.2.2"
#define szOID_CP_GOST_R3411_12_512 "1.2.643.7.1.1.2.3"

/* CRYPT_ENCRYPT_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_28147 "1.2.643.2.2.21"
#define szOID_CP_GOST_R3412_2015_M "1.2.643.7.1.1.5.1"
#define szOID_CP_GOST_R3412_2015_K "1.2.643.7.1.1.5.2"

/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3410 "1.2.643.2.2.20"
#define szOID_CP_GOST_R3410EL "1.2.643.2.2.19"
#define szOID_CP_GOST_R3410_12_256 "1.2.643.7.1.1.1.1"
#define szOID_CP_GOST_R3410_12_512 "1.2.643.7.1.1.1.2"
#define szOID_CP_DH_EX "1.2.643.2.2.99"
#define szOID_CP_DH_EL "1.2.643.2.2.98"
#define szOID_CP_DH_12_256 "1.2.643.7.1.1.6.1"
#define szOID_CP_DH_12_512 "1.2.643.7.1.1.6.2"
#define szOID_CP_GOST_R3410_94_ESDH "1.2.643.2.2.97"
#define szOID_CP_GOST_R3410_01_ESDH "1.2.643.2.2.96"

/* CRYPT_SIGN_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411_R3410 "1.2.643.2.2.4"
#define szOID_CP_GOST_R3411_R3410EL "1.2.643.2.2.3"
#define szOID_CP_GOST_R3411_12_256_R3410 "1.2.643.7.1.1.3.2"
#define szOID_CP_GOST_R3411_12_512_R3410 "1.2.643.7.1.1.3.3"

/* CRYPT_ENHKEY_USAGE_OID_GROUP_ID */
#define szOID_KP_TLS_PROXY "1.2.643.2.2.34.1"
#define szOID_KP_RA_CLIENT_AUTH "1.2.643.2.2.34.2"
#define szOID_KP_WEB_CONTENT_SIGNING "1.2.643.2.2.34.3"
#define szOID_KP_RA_ADMINISTRATOR "1.2.643.2.2.34.4"
#define szOID_KP_RA_OPERATOR "1.2.643.2.2.34.5"

/* HMAC algorithms */
#define szOID_CP_GOST_R3411_94_HMAC "1.2.643.2.2.10"
#define szOID_CP_GOST_R3411_2012_256_HMAC "1.2.643.7.1.1.4.1"
#define szOID_CP_GOST_R3411_2012_512_HMAC "1.2.643.7.1.1.4.2"

/* Qualified Certificate */
#define szOID_OGRN "1.2.643.100.1"
#define szOID_OGRNIP "1.2.643.100.5"
#define szOID_SNILS "1.2.643.100.3"
#define szOID_INN "1.2.643.3.131.1.1"

/* Signature tool class */
#define szOID_SIGN_TOOL_KC1 "1.2.643.100.113.1"
#define szOID_SIGN_TOOL_KC2 "1.2.643.100.113.2"
#define szOID_SIGN_TOOL_KC3 "1.2.643.100.113.3"
#define szOID_SIGN_TOOL_KB1 "1.2.643.100.113.4"
#define szOID_SIGN_TOOL_KB2 "1.2.643.100.113.5"
#define szOID_SIGN_TOOL_KA1 "1.2.643.100.113.6"

/* CA tool class */
#define szOID_CA_TOOL_KC1 "1.2.643.100.114.1"
#define szOID_CA_TOOL_KC2 "1.2.643.100.114.2"
#define szOID_CA_TOOL_KC3 "1.2.643.100.114.3"
#define szOID_CA_TOOL_KB1 "1.2.643.100.114.4"
#define szOID_CA_TOOL_KB2 "1.2.643.100.114.5"
#define szOID_CA_TOOL_KA1 "1.2.643.100.114.6"

/* Our well-known policy ID */
#define szOID_CEP_BASE_PERSONAL	"1.2.643.2.2.38.1"
#define szOID_CEP_BASE_NETWORK	"1.2.643.2.2.38.2"

/* OIDs for HASH */
#define szOID_GostR3411_94_TestParamSet			"1.2.643.2.2.30.0"
#define szOID_GostR3411_94_CryptoProParamSet		"1.2.643.2.2.30.1"	/* ���� � 34.11-94, ��������� �� ��������� */
#define szOID_GostR3411_94_CryptoPro_B_ParamSet		"1.2.643.2.2.30.2"
#define szOID_GostR3411_94_CryptoPro_C_ParamSet		"1.2.643.2.2.30.3"
#define szOID_GostR3411_94_CryptoPro_D_ParamSet		"1.2.643.2.2.30.4"

/* OIDs for Crypt */
#define szOID_Gost28147_89_TestParamSet			"1.2.643.2.2.31.0"
#define szOID_Gost28147_89_CryptoPro_A_ParamSet		"1.2.643.2.2.31.1"	/* ���� 28147-89, ��������� �� ��������� */
#define szOID_Gost28147_89_CryptoPro_B_ParamSet		"1.2.643.2.2.31.2"	/* ���� 28147-89, ��������� ���������� 1 */
#define szOID_Gost28147_89_CryptoPro_C_ParamSet		"1.2.643.2.2.31.3" 	/* ���� 28147-89, ��������� ���������� 2 */
#define szOID_Gost28147_89_CryptoPro_D_ParamSet		"1.2.643.2.2.31.4"	/* ���� 28147-89, ��������� ���������� 3 */
#define szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet	"1.2.643.2.2.31.5"	/* ���� 28147-89, ��������� ����� 1.1 */
#define szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet	"1.2.643.2.2.31.6"	/* ���� 28147-89, ��������� ����� 1.0 */
#define szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet	"1.2.643.2.2.31.7"	/* ���� 28147-89, ��������� ��� 1 */

#define szOID_Gost28147_89_TC26_A_ParamSet		"1.2.643.2.2.31.12"	/* ���� 28147-89, ��������� ���������� TC26 2 */
#define szOID_Gost28147_89_TC26_B_ParamSet		"1.2.643.2.2.31.13"	/* ���� 28147-89, ��������� ���������� TC26 1 */
#define szOID_Gost28147_89_TC26_C_ParamSet		"1.2.643.2.2.31.14" 	/* ���� 28147-89, ��������� ���������� TC26 3 */
#define szOID_Gost28147_89_TC26_D_ParamSet		"1.2.643.2.2.31.15"	/* ���� 28147-89, ��������� ���������� TC26 4 */
#define szOID_Gost28147_89_TC26_E_ParamSet		"1.2.643.2.2.31.16" 	/* ���� 28147-89, ��������� ���������� TC26 5 */
#define szOID_Gost28147_89_TC26_F_ParamSet		"1.2.643.2.2.31.17"	/* ���� 28147-89, ��������� ���������� TC26 6 */

#define szOID_Gost28147_89_TC26_Z_ParamSet	"1.2.643.7.1.2.5.1.1"	/* ���� 28147-89, ��������� ���������� ��26 Z */

/* OID for Signature 1024*/
#define szOID_GostR3410_94_CryptoPro_A_ParamSet		"1.2.643.2.2.32.2" 	/*VerbaO*/
#define szOID_GostR3410_94_CryptoPro_B_ParamSet		"1.2.643.2.2.32.3"
#define szOID_GostR3410_94_CryptoPro_C_ParamSet		"1.2.643.2.2.32.4"
#define szOID_GostR3410_94_CryptoPro_D_ParamSet		"1.2.643.2.2.32.5"

/* OID for Signature 512*/
#define szOID_GostR3410_94_TestParamSet			"1.2.643.2.2.32.0" 	/*Test*/

/* OID for DH 1024*/
#define szOID_GostR3410_94_CryptoPro_XchA_ParamSet	"1.2.643.2.2.33.1"
#define szOID_GostR3410_94_CryptoPro_XchB_ParamSet	"1.2.643.2.2.33.2"
#define szOID_GostR3410_94_CryptoPro_XchC_ParamSet	"1.2.643.2.2.33.3"

/* OID for EC signature */
#define szOID_GostR3410_2001_TestParamSet		"1.2.643.2.2.35.0"      /* ���� � 34.10-2001, �������� ��������� */
#define szOID_GostR3410_2001_CryptoPro_A_ParamSet	"1.2.643.2.2.35.1"	/* ���� � 34.10-2001, ��������� �� ��������� */
#define szOID_GostR3410_2001_CryptoPro_B_ParamSet	"1.2.643.2.2.35.2"	/* ���� � 34.10-2001, ��������� ����� 2.x */
#define szOID_GostR3410_2001_CryptoPro_C_ParamSet	"1.2.643.2.2.35.3"	/* ���� � 34.10-2001, ��������� ������� 1 */

#define szOID_tc26_gost_3410_12_256_paramSetA		"1.2.643.7.1.2.1.1.1"	/* ���� � 34.10-2012, 256 ���, ��������� ��-26, ����� A */

#define szOID_tc26_gost_3410_12_512_paramSetA		"1.2.643.7.1.2.1.2.1"	/* ���� � 34.10-2012, 512 ���, ��������� �� ��������� */
#define szOID_tc26_gost_3410_12_512_paramSetB		"1.2.643.7.1.2.1.2.2"	/* ���� � 34.10-2012, 512 ���, ��������� ��-26, ����� B */
#define szOID_tc26_gost_3410_12_512_paramSetC		"1.2.643.7.1.2.1.2.3"	/* ���� � 34.10-2012, 512 ���, ��������� ��-26, ����� � */


/* OID for EC DH */
#define szOID_GostR3410_2001_CryptoPro_XchA_ParamSet	"1.2.643.2.2.36.0"	/* ���� � 34.10-2001, ��������� ������ �� ��������� */
#define szOID_GostR3410_2001_CryptoPro_XchB_ParamSet 	"1.2.643.2.2.36.1"	/* ���� � 34.10-2001, ��������� ������ 1 */

/* OIDs for private key container extensions */
/* ���������� ����������. �������������� ������� � CSP 3.6 */
#define szOID_CryptoPro_private_keys_extension_intermediate_store "1.2.643.2.2.37.3.1"
#define szOID_CryptoPro_private_keys_extension_signature_trust_store "1.2.643.2.2.37.3.2"
#define szOID_CryptoPro_private_keys_extension_exchange_trust_store "1.2.643.2.2.37.3.3"
#define szOID_CryptoPro_private_keys_extension_container_friendly_name "1.2.643.2.2.37.3.4"
#define szOID_CryptoPro_private_keys_extension_container_key_usage_period "1.2.643.2.2.37.3.5"
#define szOID_CryptoPro_private_keys_extension_container_uec_symmetric_key_derive_counter "1.2.643.2.2.37.3.6"

#define szOID_CryptoPro_private_keys_extension_container_primary_key_properties "1.2.643.2.2.37.3.7"
#define szOID_CryptoPro_private_keys_extension_container_secondary_key_properties "1.2.643.2.2.37.3.8"

#define szOID_CryptoPro_private_keys_extension_container_signature_key_usage_period "1.2.643.2.2.37.3.9"
#define szOID_CryptoPro_private_keys_extension_container_exchange_key_usage_period "1.2.643.2.2.37.3.10"
#define szOID_CryptoPro_private_keys_extension_container_key_time_validity_control_mode "1.2.643.2.2.37.3.11"

/* OIDs for certificate and CRL extensions */
/* ����� ������������� CRL � ������������ ��������. */
#define szOID_CryptoPro_extensions_certificate_and_crl_matching_technique "1.2.643.2.2.49.1"
/* �������� ����������� ������� ��������� */
#define szCPOID_SubjectSignTool "1.2.643.100.111"
/* �������� ����������� ������� � �� ��������*/
#define szCPOID_IssuerSignTool "1.2.643.100.112"

/* OIDs for signing certificate attributes */
/* ������ ��������� ��� �������� �������������� ����������� ����� ������� */
#define szCPOID_RSA_SMIMEaaSigningCertificate "1.2.840.113549.1.9.16.2.12"
#define szCPOID_RSA_SMIMEaaSigningCertificateV2 "1.2.840.113549.1.9.16.2.47"
#define szCPOID_RSA_SMIMEaaETSotherSigCert "1.2.840.113549.1.9.16.2.19"

/* GUIDs for extending CryptEncodeObject/CryptDecodeObject functionality */
/* ����� ���������� ���������������, ������������ ��� ���������� ����������������
   ������� CryptEncodeObject/CryptDecodeObject */
#define szCPGUID_RSA_SMIMEaaSigningCertificateEncode "{272ED084-4C55-42A9-AD88-A1502D9ED755}"
#define szCPGUID_RSA_SMIMEaaSigningCertificateV2Encode "{42AB327A-BE56-4899-9B81-1BF2F3C5E154}"
#define szCPGUID_RSA_SMIMEaaETSotherSigCertEncode "{410F6306-0ADE-4485-80CC-462DEB3AD109}"
#define szCPGUID_PRIVATEKEY_USAGE_PERIOD_Encode "{E36FC6F5-4880-4CB7-BA51-1FCD92CA1453}"

/*! \cond pkivalidator */
/* GUIDs for extending CertVerifyCertificateChainPolicy functionality */
/* ����� ���������� ���������������, ������������ ��� ���������� ����������������
   ������� CertVerifyCertificateChainPolicy */
#define CPCERT_CHAIN_POLICY_PRIVATEKEY_USAGE_PERIOD "{C03D5610-26C8-4B6F-9549-245B5B3AB743}"
#define CPCERT_CHAIN_POLICY_SIGNATURE "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}"
#define CPCERT_CHAIN_POLICY_TIMESTAMP_SIGNING "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}"
#define CPCERT_CHAIN_POLICY_OCSP_SIGNING "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"
/** \endcond */

/*! \cond csp */
/* �������� ��� ������������� � ������� 3.0*/
#define OID_HashVar_Default	szOID_GostR3411_94_CryptoProParamSet
#define OID_HashTest		szOID_GostR3411_94_TestParamSet
#define OID_HashVerbaO		szOID_GostR3411_94_CryptoProParamSet
#define OID_HashVar_1		szOID_GostR3411_94_CryptoPro_B_ParamSet
#define OID_HashVar_2		szOID_GostR3411_94_CryptoPro_C_ParamSet
#define OID_HashVar_3		szOID_GostR3411_94_CryptoPro_D_ParamSet

#define OID_CipherVar_Default	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_CryptTest		szOID_Gost28147_89_TestParamSet
#define OID_CipherVerbaO	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_CipherVar_1		szOID_Gost28147_89_CryptoPro_B_ParamSet
#define OID_CipherVar_2		szOID_Gost28147_89_CryptoPro_C_ParamSet
#define OID_CipherVar_3		szOID_Gost28147_89_CryptoPro_D_ParamSet
#define OID_CipherOSCAR		szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet
#define OID_CipherTestHash	szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet
#define OID_CipherRIC1		szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet

#define OID_CipherTC26_1	szOID_Gost28147_89_TC26_A_ParamSet	
#define OID_CipherTC26_2	szOID_Gost28147_89_TC26_B_ParamSet	
#define OID_CipherTC26_3	szOID_Gost28147_89_TC26_C_ParamSet	
#define OID_CipherTC26_4	szOID_Gost28147_89_TC26_D_ParamSet	
#define OID_CipherTC26_5	szOID_Gost28147_89_TC26_E_ParamSet	
#define OID_CipherTC26_6	szOID_Gost28147_89_TC26_F_ParamSet

#define OID_CipherRSTC26_1	szOID_Gost28147_89_TC26_Z_ParamSet

#define OID_SignDH128VerbaO	szOID_GostR3410_94_CryptoPro_A_ParamSet
#define OID_Sign128Var_1	szOID_GostR3410_94_CryptoPro_B_ParamSet
#define OID_Sign128Var_2	szOID_GostR3410_94_CryptoPro_C_ParamSet
#define OID_Sign128Var_3	szOID_GostR3410_94_CryptoPro_D_ParamSet
#define OID_DH128Var_1		szOID_GostR3410_94_CryptoPro_XchA_ParamSet
#define OID_DH128Var_2		szOID_GostR3410_94_CryptoPro_XchB_ParamSet
#define OID_DH128Var_3		szOID_GostR3410_94_CryptoPro_XchC_ParamSet

#define OID_Sg64_Test		szOID_GostR3410_94_TestParamSet

#define OID_ECCTest3410		szOID_GostR3410_2001_TestParamSet
#define OID_ECCSignDHPRO	szOID_GostR3410_2001_CryptoPro_A_ParamSet
#define OID_ECCSignDHOSCAR	szOID_GostR3410_2001_CryptoPro_B_ParamSet
#define OID_ECCSignDHVar_1	szOID_GostR3410_2001_CryptoPro_C_ParamSet

#define OID_ECC1024A		szOID_tc26_gost_3410_12_512_paramSetA
#define OID_ECC1024B		szOID_tc26_gost_3410_12_512_paramSetB


#define OID_ECCDHPRO		szOID_GostR3410_2001_CryptoPro_XchA_ParamSet
#define OID_ECCDHPVar_1		szOID_GostR3410_2001_CryptoPro_XchB_ParamSet

/* �������� ��� ������������� � ������� 1.1*/
#define OID_SipherVerbaO	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_SipherVar_1		szOID_Gost28147_89_CryptoPro_B_ParamSet
#define OID_SipherVar_2		szOID_Gost28147_89_CryptoPro_C_ParamSet
#define OID_SipherVar_3		szOID_Gost28147_89_CryptoPro_D_ParamSet
#define OID_SipherVar_Default	szOID_Gost28147_89_CryptoPro_A_ParamSet

#define X509_GR3410_PARAMETERS ((LPCSTR) 5001)
#define OBJ_ASN1_CERT_28147_ENCRYPTION_PARAMETERS ((LPCSTR) 5007)

//short names
#define CP_GOST_28147_ALG			"GOST 28147-89"
#define CP_GOST_R3412_2015_M_ALG		"GR 34.12 64 M"
#define CP_GOST_R3412_2015_K_ALG		"GR 34.12 128 K"
#define CP_GOST_28147_MAC_ALG			"GOST 28147-89 MAC"
#define CP_GOST_R3413_2015_M_MAC_ALG		"GR 34.13 64 M MAC"
#define CP_GOST_R3413_2015_K_MAC_ALG		"GR 34.13 128 K MAC"
#define CP_GOST_HMAC_ALG			"HMAC GOST 28147-89"
#define CP_GOST_R3411_ALG			"GOST R 34.11-94"
#define CP_GOST_R3411_2012_256_ALG		"GR 34.11-2012 256"
#define CP_GOST_R3411_2012_512_ALG		"GR 34.11-2012 512"
#define CP_GOST_R3411_HMAC_ALG			"GR34.11-94 256 HMAC"
#define CP_GOST_R3411_2012_256_HMAC_ALG		"GR34.11-12 256 HMAC"
#define CP_GOST_R3411_2012_512_HMAC_ALG		"GR34.11-12 512 HMAC"
#define CP_GOST_R3410EL_ALG			"GOST R 34.10-2001"
#define CP_GOST_R3410_2012_256_ALG		"GR 34.10-2012 256"
#define CP_GOST_R3410_2012_512_ALG		"GR 34.10-2012 512"
#define CP_GOST_R3410EL_DH_ALG			"DH 34.10-2001"
#define CP_GOST_R3410_2012_256_DH_ALG		"DH 34.10-2012 256"
#define CP_GOST_R3410_2012_512_DH_ALG		"DH 34.10-2012 512"

#define CP_GOST_28147_ALGORITHM			"GOST 28147-89"
#define CP_GOST_R3412_2015_M_ALGORITHM		"GOST R 34.12-2015 64 Magma"
#define CP_GOST_R3412_2015_K_ALGORITHM		"GOST R 34.12-2015 128 Kuznyechik"
#define CP_GOST_28147_MAC_ALGORITHM		"GOST 28147-89 MAC"
#define CP_GOST_R3413_2015_M_MAC_ALGORITHM	"GOST R 34.13-2015 64 Magma MAC"
#define CP_GOST_R3413_2015_K_MAC_ALGORITHM	"GOST R 34.13-2015 128 Kuznyechik MAC"
#define CP_GOST_HMAC_ALGORITHM			"HMAC GOST 28147-89"
#define CP_GOST_R3411_ALGORITHM			"GOST R 34.11-1994 256"
#define CP_GOST_R3411_2012_256_ALGORITHM	"GOST R 34.11-2012 256"
#define CP_GOST_R3411_2012_512_ALGORITHM	"GOST R 34.11-2012 512"
#define CP_GOST_R3411_HMAC_ALGORITHM		"GOST R 34.11-1994 256 HMAC"
#define CP_GOST_R3411_2012_256_HMAC_ALGORITHM	"GOST R 34.11-2012 256 HMAC"
#define CP_GOST_R3411_2012_512_HMAC_ALGORITHM	"GOST R 34.11-2012 512 HMAC"
#define CP_GOST_R3410EL_ALGORITHM		"GOST R 34.10-2001 256"
#define CP_GOST_R3410_2012_256_ALGORITHM	"GOST R 34.10-2012 256"
#define CP_GOST_R3410_2012_512_ALGORITHM	"GOST R 34.10-2012 512"
#define CP_GOST_R3410EL_DH_ALGORITHM		"GOST R 34.10-2001 256 DH"
#define CP_GOST_R3410_2012_256_DH_ALGORITHM	"GOST R 34.10-2012 256 DH"
#define CP_GOST_R3410_2012_512_DH_ALGORITHM	"GOST R 34.10-2012 512 DH"

#define CP_PRIMITIVE_PROVIDER			L"Crypto-Pro Primitive Provider"

#define CONCAT_L_INTERNAL(x) L##x
#define CAT_L(x) CONCAT_L_INTERNAL(x)

#define BCRYPT_CP_GOST_R3411_ALGORITHM		    CAT_L(CP_GOST_R3411_ALG)
#define BCRYPT_CP_GOST_28147_ALGORITHM		    CAT_L(CP_GOST_28147_ALG)
#define BCRYPT_CP_GOST_R3411_2012_256_ALGORITHM	    CAT_L(CP_GOST_R3411_2012_256_ALG)
#define BCRYPT_CP_GOST_R3411_2012_512_ALGORITHM	    CAT_L(CP_GOST_R3411_2012_512_ALG)
#define BCRYPT_CP_GOST_R3410EL_ALGORITHM	    L"GR 34.10-2001"	/*Do not change legacy algs names (PP_ENUMALGS)*/
#define BCRYPT_CP_GOST_R3410_2012_256_ALGORITHM	    CAT_L(CP_GOST_R3410_2012_256_ALG)
#define BCRYPT_CP_GOST_R3410_2012_512_ALGORITHM	    CAT_L(CP_GOST_R3410_2012_512_ALG)
#define BCRYPT_CP_GOST_R3410EL_DH_ALGORITHM	    L"GOST " CAT_L(CP_GOST_R3410EL_DH_ALG)
#define BCRYPT_CP_GOST_R3410_2012_256_DH_ALGORITHM  L"GOST " CAT_L(CP_GOST_R3410_2012_256_DH_ALG)
#define BCRYPT_CP_GOST_R3410_2012_512_DH_ALGORITHM  L"GOST " CAT_L( CP_GOST_R3410_2012_512_DH_ALG)

/* ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, ����-����� ����� ������ �������� IV ��� ����������.*/
/*! \ingroup ProCSPData
*  \brief ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, ����-����� ����� ������ �������� IV ��� ����������
*/
#define CRYPT_MODE_CBCSTRICT	1 

/* ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, �������� RFC 4357.*/
/*! \ingroup ProCSPData
*  \brief ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, �������� RFC 4357
*/
#define CRYPT_MODE_CBCRFC4357	31 

/* ����� ���������� "������������" �� ���� 28147-89.*/
/*! \ingroup ProCSPData
 *  \brief ����� ���������� "�������������" �� ���� 28147-89
 */
#define CRYPT_MODE_CNT          3      // GOST 28147-89 in "gammirovanie" (counter) mode

/* ����� ���������� "������������" �� ���� � 34.13-2015.*/
/*! \ingroup ProCSPData
*  \brief ����� ���������� "������������" �� ���� � 34.13-2015
*/
#define CRYPT_MODE_CTR          32

/* ����� ���������� ����� ��� ���� 28147-89, ������� � ������.*/
/*! \ingroup ProCSPData
 *  \brief ����� � ������ ����� ���� 28147-89 � �������� ������
 * ���� � 34.10-94 � ���� � 34.10-2001.
 */
#define SECRET_KEY_LEN		32
#define SECRET_KEY_BITLEN	256

#define SYMMETRIC_KEY_512_LEN		64
#define SYMMETRIC_KEY_512_BITLEN	512

#define FOREIGN_TLS_PREMASTER_KEY_LEN	    48
#define FOREIGN_TLS_PREMASTER_KEY_BITLEN    384

#define SCHANNEL_PRF_ALG		2

/*! \ingroup ProCSPData
 *  \brief ����� � ������ ����� ���� 28147-89
 * \sa SECRET_KEY_LEN
 */
#define G28147_KEYLEN        SECRET_KEY_LEN

/*! \ingroup ProCSPData
 *  \brief ����� � ������ ������������ ��� �������/��������
 */
#define EXPORT_IMIT_SIZE		4

/*! \ingroup ProCSPData
 *  \brief ����� � ������ ����������� �������� ����� ��� ������� � ��������� ��������� �����
 */
#define CHECK_VALUE_SIZE		3
/*! \ingroup ProCSPData
 *  \brief �����  � ������ ������� ������������� ���������
 */
#define SEANCE_VECTOR_LEN		8

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ����� ��������� ���������� (��� ������������� �������).
*/
#define MAX_CONTAINER_NAME_LEN		260

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ����� ����� ��������� ���������� (��� ������������� �������).
*/
#define MAX_FOLDER_NAME_LEN		MAX_CONTAINER_NAME_LEN

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ����������� ����� �������� (��� ������������� �������).
*/
#define MAX_UNIQUE_LEN			256

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ���� �������� (��� ������������� �������).
*/
#define MAX_MEDIA_TYPE_NAME_LEN		64

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ����� ����������� (��� ������������� �������).
*/
#define MAX_READER_NAME_LEN		64

/*! \ingroup ProCSPData
*  \brief ����� CRC.
*/
#define CONTAINER_CRC_LEN 4

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ������� ������, ������������ ���������, � CryptAcquireContext (��� ������������� �������).
*/
#define MAX_INPUT_CONTAINER_STRING_LEN	(4 + MAX_READER_NAME_LEN + 1 + MAX_MEDIA_TYPE_NAME_LEN + 1 + MAX_UNIQUE_LEN + MAX_FOLDER_NAME_LEN + 1 + CONTAINER_CRC_LEN)


/* ��������� � ��������� ��� ���� �������� ������� �*/
/* ��������� ������������� ������*/

/*! \ingroup ProCSPData
 *  \brief ������� ������ ���� � 34.10-94 � ���� � 34.10-2001
 */
#define GR3410_1_MAGIC			0x3147414D
#define GR3410_2_MAGIC			GR3410_1_MAGIC//0x3145474a

#define DH_1_MAGIC			GR3410_1_MAGIC
#define DH_2_MAGIC			GR3410_1_MAGIC
#define DH_3_MAGIC			GR3410_1_MAGIC

/*! \ingroup ProCSPData
 *  \brief ������� ������ ���� 28147-89 � ������ ������ TLS
 */
#define G28147_MAGIC			0x374a51fd
#define SIMPLEBLOB_MAGIC		G28147_MAGIC
#define G28147_OPAQUEMAGIC		0x374a51fe
/*! \ingroup ProCSPData
 *  \brief ������� ��������� ����� ������� �������������� �����
 */
#define DIVERS_MAGIC			0x31564944

/*! \ingroup ProCSPData
*  \brief ������� ��������� ����� ��������� KExp15
*/
#define KEXP15_MAGIC			0x374a51ff

/*! \ingroup ProCSPData
*  \brief ������� ��������� opaque-�����
*/
#define FOREIGN_OPAQUEKEYBLOB_MAGIC	0x324153ff

/*! \ingroup ProCSPData
 *  \brief ������� �������� ������ ��������� �����
 */
#define BLOB_VERSION			(BYTE)0x20

/*! \ingroup ProCSPData
*  \brief ������� �������� ������ ��������� ����� KExp15
*/
#define KEXP15_BLOB_VERSION		(BYTE)0x21

/*! \ingroup ProCSPData
*  \brief ������� ��������� ����� RSA
*/
#define RSA1_MAGIC			0x31415352
#define RSA2_MAGIC			0x32415352

/*! \ingroup ProCSPData
*  \brief ����, ��������������� ������� ��������� ��������� ����� �� �����������
*/
#define CP_CRYPT_PUBLICKEY_FROM_CERT	(0x00010000)

/* ����������� ��� */
/*! \ingroup ProCSPData
 * \brief ���������� ������ ������������.
 */
#define VER_TYPE_DEBUG 1
/*! \ingroup ProCSPData
* \brief �������� ������ ������������.
*/
#define VER_TYPE_RELEASE 0

/*! \ingroup ProCSPData
* \brief ����������� IA32.
*/
#define VER_ARCH_IA32	    0
/*! \ingroup ProCSPData
* \brief ����������� IA64.
*/
#define VER_ARCH_IA64	    1
/*! \ingroup ProCSPData
* \brief ����������� Sparc32.
*/
#define VER_ARCH_SPARC32    2
/*! \ingroup ProCSPData
* \brief ����������� Sparc64.
*/
#define VER_ARCH_SPARC64    3
/*! \ingroup ProCSPData
* \brief ����������� AMD64.
*/
#define VER_ARCH_AMD64	    4
/*! \ingroup ProCSPData
* \brief ����������� ARM.
*/
#define VER_ARCH_ARM	    5
/*! \ingroup ProCSPData
* \brief ����������� PowerPC32.
*/
#define VER_ARCH_PPC32      6
/*! \ingroup ProCSPData
* \brief ����������� PowerPC64.
*/
#define VER_ARCH_PPC64      7
/*! \ingroup ProCSPData
* \brief ����������� ARM64.
*/
#define VER_ARCH_ARM64	    8
/*! \ingroup ProCSPData
* \brief ����������� MIPS32.
*/
#define VER_ARCH_MIPS32	    9
/*! \ingroup ProCSPData
* \brief ����������� ������� 32.
*/
#define VER_ARCH_E2K32	    10

/*! \ingroup ProCSPData
* \brief ����������� ������� 64.
*/
#define VER_ARCH_E2K64	    11

/*! \ingroup ProCSPData
* \brief �� Windows.
*/
#define VER_OS_WINDOWS 0
/*! \ingroup ProCSPData
* \brief �� Solaris.
*/
#define VER_OS_SOLARIS 1
/*! \ingroup ProCSPData
* \brief �� FreeBSD.
*/
#define VER_OS_FREEBSD 2
/*! \ingroup ProCSPData
* \brief �� Linux.
*/
#define VER_OS_LINUX   3
/*! \ingroup ProCSPData
* \brief �� AIX.
*/
#define VER_OS_AIX     4

/*! \ingroup ProCSPData
* \brief �� Mac OS X.
*/
#define VER_OS_DARWIN  5
/*! \ingroup ProCSPData
* \brief Apple iOS */
#define VER_OS_IOS  6
/*! \ingroup ProCSPData
* \brief ANDROID OS */
#define VER_OS_ANDROID 7
/*! \ingroup ProCSPData
* \brief BITVISOR_OS */
#define VER_OS_BITVISOR 8
/*! \ingroup ProCSPData
* \brief UCLIBC runtime
*/
#define VER_OS_UCLIBC 9

/*! \ingroup ProCSPData
 *
 * \brief ��������� ��������� ������ ����, ����, ��� ������,
 * ���������� ����������� � ��, ��� ������� ������������ �������.
 */
typedef struct _PROV_PP_VERSION_EX {
    DWORD PKZI_Build;	/*!< ������ ����. */
    DWORD SKZI_Build;	/*!< ������ ����. */
    DWORD TypeDebRel;	/*!< ��� ������: VER_TYPE_DEBUG, VER_TYPE_RELEASE. */
    DWORD Architecture;	/*!< ���������� �����������: VER_ARCH_IA32, 
			 * VER_ARCH_IA64, VER_ARCH_SPARC32, VER_ARCH_SPARC64,
			 * VER_ARCH_AMD64, VER_ARCH_ARM, VER_ARCH_ARM64,
			 * VER_ARCH_PPC32, VER_ARCH_PPC64.
			 */
    DWORD OS;		/*!< ��� ��: VER_OS_WINDOWS, VER_OS_SOLARIS,
			 * VER_OS_FREEBSD, VER_OS_LINUX, VER_OS_AIX.
			 */
} PROV_PP_VERSION_EX;

/*! \ingroup ProCSPData
 *
 * \brief ��������� ���������� ����������� ������������ � �������� 
 *        ����������� ����.
 */
typedef struct _SELFTEST_HEADER {
    DWORD PKZI_Build;	  /*!< ������ ����. */
    DWORD SKZI_Build;	  /*!< ������ ����. */
    DWORD TypeDebRel;	  /*!< ��� ������: VER_TYPE_DEBUG, VER_TYPE_RELEASE. */
    DWORD Architecture;	  /*!< ���������� �����������: VER_ARCH_IA32, 
			   * VER_ARCH_IA64, VER_ARCH_SPARC32, VER_ARCH_SPARC64,
			   * VER_ARCH_AMD64, VER_ARCH_ARM, VER_ARCH_ARM64,
			   * VER_ARCH_PPC32, VER_ARCH_PPC64.
			   */
    DWORD OS;		  /*!< ��� ��: VER_OS_WINDOWS, VER_OS_SOLARIS,
			   * VER_OS_FREEBSD, VER_OS_LINUX, VER_OS_AIX.
			   */
    DWORD TesterFlags;	  /*!< ������� ������ ������ ���������� ������, 
			   * �������� ��������� �������� �����������.
			   * � ������ ������, ������ ���� ����� 0.
			   */
    DWORD TotalChecksums; /*!< ����� ���������� ������� ��� ������� 
			   * ���� ��������� �������� �����������. 
			   * ������ ������ ��� ����� 1.
			   */
    DWORD UnwrittenChecksums; 
			  /*!< ���������� �������, ���������� � �������
			   * �� ���� �������� � ���� Checksums ��������� 
			   * PROV_PP_SELFTEST, �� ������� ��������������
			   * ���������� ������, ���������� ��� ���������.
			   * ���� ������ ����������, ����� 0. */
} SELFTEST_HEADER;

/*! \ingroup ProCSPData
*
* \brief ��������� ��������� ����� ������ (����) ���������� � �������,
*  ������ ����, ���������������� ������, Nice ������, � ������ ����� ������ ����������
*/
typedef struct _CPU_INFO {
    ULONGLONG Idle;  // ����� � ������ �������
    ULONGLONG Kernel; // ����� � ������ ����
    ULONGLONG User; // ����� � ���������������� ������
    ULONGLONG Nice; // ����� � ������ Nice
    DWORD dwProcNumber; // ���������� ���� ����������
    DWORD Dummy;	// ��� ������������ ����
} CPU_INFO;

/*! \ingroup ProCSPData
 *
 * \brief ��������� �������� ����������� ������.
 */
typedef struct _SELFTEST_CHECKSUM_ELEMENT {
    char BlockName[40];		/*!< �������� ������. */
    BYTE InitialHash[32];	/*!< ��������� ����������� �����. */
    BYTE CalculatedHash[32];	/*!< ����������� ����������� �����. */
} SELFTEST_CHECKSUM_ELEMENT;

/*! \ingroup ProCSPData
 *
 * \brief ��������� ����������� ������������ � �������� 
 *        ����������� ����.
 */
typedef struct _PROV_PP_SELFTEST {
    SELFTEST_HEADER Header;	/*!< ��������� \ref SELFTEST_HEADER. */
    SELFTEST_CHECKSUM_ELEMENT Checksums[1];
				/*!< ������ \ref SELFTEST_CHECKSUM_ELEMENT 
				 * ������� Header.TotalChecksums. 
				 */
} PROV_PP_SELFTEST;

/* ����������� ��� ��������� SIMPLEBLOB*/
/* ��������� SIMPLEBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_SIMPLEBLOB_HEADER �������� ����������� ��������� BLOBHEADER �
 * ��������� � ������ ���� \b pbData ��������� ����� ���� SIMPLEBLOB ��� ������ "��������� CSP".
 *
 * \req_wincryptex
 * \sa _PUBLICKEYSTRUC
 * \sa PCRYPT_SIMPLEBLOB
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB_HEADER {
    BLOBHEADER BlobHeader;
                    /*!< ����� ��������� ��������� �����. ���������� �������� �����
                     * ������������ � �������� �����. ��. \ref _PUBLICKEYSTRUC.
                     */
    DWORD Magic;
                    /*!< ������� ������ �� ���� 28147-89 ��� ������ ������ TLS,
                     * ��������������� � \ref G28147_MAGIC.
                     */
    ALG_ID EncryptKeyAlgId;
                    /*!< ���������� �������� �������� �����. ���� �������� ��������
                     * ���������� ����� ��������. ��. \ref #CPGetKeyParam.
                     */
} CRYPT_SIMPLEBLOB_HEADER;
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� (�. �. ���������������� ���������) CRYPT_SIMPLEBLOB ��������� ��������� �������� ����
 * ���� SIMPLEBLOB ��� ������ "��������� CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*!< ������ ������������� ��� ��������� CALG_PRO_EXPORT.
                     * ��. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
                    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
                     * �� ������������ � ����������� ����� �������������.
                     * ��. \ref EXPORT_IMIT_SIZE.
                     */
    BYTE    bEncryptionParamSet[1];
                    /*!< �������� ASN1 ��������� � DER ���������, ������������
                     * ��������� ��������� ���������� ���� 28147-89:
                     * \code
                     *      encryptionParamSet
                     *          OBJECT IDENTIFIER (
                     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *              id-Gost28147-89-CryptoPro-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-D-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     * \endcode
                     */
}   CRYPT_SIMPLEBLOB, *PCRYPT_SIMPLEBLOB;
/*!
* \ingroup ProCSPData
*
* \brief ��������������� (�. �. ���������������� ���������) CRYPT_SIMPLEBLOB ��������� ��������� �������� ����
* ���� SIMPLEBLOB ��� ������ "��������� CSP".
*
* \req_wincryptex
* \sa CRYPT_SIMPLEBLOB_HEADER
* \sa CPExportKey
* \sa CPGetKeyParam
*/
typedef struct _CRYPT_SIMPLEBLOB_512 {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
    */
    BYTE    bSV[SEANCE_VECTOR_LEN];
    /*!< ������ ������������� ��� ��������� CALG_PRO_EXPORT.
    * ��. \ref SEANCE_VECTOR_LEN.
    */
    BYTE    bEncryptedKey[SYMMETRIC_KEY_512_LEN];
    /*!< ������������� ���� CALG_SYMMETRIC_512.
    * ��. \ref G28147_KEYLEN.
    */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
    * �� ������������ � ����������� ����� �������������.
    * ��. \ref EXPORT_IMIT_SIZE.
    */
    BYTE    bEncryptionParamSet[1];
    /*!< �������� ASN1 ��������� � DER ���������, ������������
    * ��������� ��������� ���������� ���� 28147-89:
    * \code
    *      encryptionParamSet
    *          OBJECT IDENTIFIER (
    *              id-Gost28147-89-TestParamSet |      -- Only for tests use
    *              id-Gost28147-89-CryptoPro-A-ParamSet |
    *              id-Gost28147-89-CryptoPro-B-ParamSet |
    *              id-Gost28147-89-CryptoPro-C-ParamSet |
    *              id-Gost28147-89-CryptoPro-D-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
    *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
    * \endcode
    */
}   CRYPT_SIMPLEBLOB_512, *PCRYPT_SIMPLEBLOB_512;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� (�. �. ���������������� ���������) CRYPT_OPAQUEBLOB ��������� ��������� �������� ����
 * ���� OPAQUEKEYLOB ��� ������ "��������� CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPImportKey
 */
typedef struct _CRYPT_OPAQUEBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*!< ������ ������������� ��� ��������� CALG_PRO_EXPORT.
                     * ��. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
                    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
                     * �� ������������ � ����������� ����� �������������.
                     * ��. \ref EXPORT_IMIT_SIZE.
                     */
    BYTE    bEncryptedInitKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bMacInitKey[EXPORT_IMIT_SIZE];
                    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
                     * �� ������������ � ����������� ����� �������������.
                     * ��. \ref EXPORT_IMIT_SIZE.
                     */
      /*�� ��������� ����*/
   BYTE    bCurrentIV[SEANCE_VECTOR_LEN];
                    /*!< ������ ������������� ���������.
                     * ��. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bChainBlock[8];
                    /*!< ���� ����������. ������������� ����� ������� �� ������ ����������.
                     *
                     */
    BYTE    bAccCiphertextLen[sizeof(DWORD)];
                    /*!< ����������� ����� ������������ ������ � ������� ����������.
                     *
                     */
    BYTE    bCommAccCiphertextLen[sizeof(DWORD)];
                    /*!< ����������� ����� ������������ ������ ����� �����������.
                     *
                     */
    BYTE    bCommCipherTextLenOnBaseKey[sizeof(DWORD)];
                    /*!< ����������� �������� �� ������� ����.
                     *
                     */
    BYTE    bCipherMode[sizeof(DWORD)];
    BYTE    bMixMode[sizeof(DWORD)];
    BYTE    bFlags[4];
    BYTE    bPaddingMode[sizeof(DWORD)];
    BYTE    bAlgId[sizeof(ALG_ID)];
    BYTE    bCommonFlags[4];
    BYTE    bCheckSum[sizeof(DWORD)];
    BYTE    bEncryptionParamSet[1];
                    /*!< �������� ASN1 ��������� � DER ���������, ������������
                     * ��������� ��������� ���������� ���� 28147-89:
                     * \code
                     *      encryptionParamSet
                     *          OBJECT IDENTIFIER (
                     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *              id-Gost28147-89-CryptoPro-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-D-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     * \endcode
                     */
}   CRYPT_OPAQUEBLOB, *PCRYPT_OPAQUEBLOB;


typedef struct _CRYPT_OPAQUEHASHBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
                     */
   BYTE    ImitVal[8];
   BYTE    bCurrKey[G28147_KEYLEN];
                    /*!< ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bChainBlock[8];
                    /*!< ���� ����������. ������������� ����� ������� �� ������ ����������.
                     *
                     */
    BYTE    bAccCiphertextLen[sizeof(DWORD)];
                    /*!< ����������� ����� ������������ ������ � ������� ����������.
                     *
                     */
    BYTE    bCommAccCiphertextLen[sizeof(DWORD)];
                    /*!< ����������� ����� ������������ ������ ����� �����������.
                     *
                     */
    BYTE    bCommCipherTextLenOnBaseKey[sizeof(DWORD)];
                    /*!< ����������� �������� �� ������� ����.
                     *
                     */
    BYTE    bHFlags[4];
    BYTE    bCheckSum[sizeof(DWORD)];
}   CRYPT_OPAQUEHASHBLOB;


/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_PUBKEYPARAM �������� ������� ������
 * �� ���� � 34.10-2001.
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBKEYPARAM {
    DWORD Magic;
                    /*!< ������� ������ �� ���� � 34.10-2001
                     * ��������������� � \ref GR3410_1_MAGIC.
                     */
    DWORD BitLen;
                    /*!< ����� ��������� ����� � �����.
                     */
} CRYPT_PUBKEYPARAM, *LPCRYPT_PUBKEYPARAM;

/* ��������� PUBLICKEYBLOB � PRIVATEKEYBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_PUBKEY_INFO_HEADER �������� ���������
 * ����� ��������� ����� ��� ����� �������� ����
 * �� ���� � 34.10-2001.
 *
 * \req_wincryptex
 * \sa _PUBLICKEYSTRUC
 * \sa CRYPT_PUBKEYPARAM
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBKEY_INFO_HEADER {
    BLOBHEADER BlobHeader;
                    /*!< ����� ��������� ��������� �����. ���������� ��� ��� � �������� �����
                     * ������������ � �������� �����. ��� �������� ������ ��������
                     * ����� ������, ���� CALG_GR3410, ���� CALG_GR3410EL. ��� ��������
                     * ��� �������� �������� � ����������. ��. \ref _PUBLICKEYSTRUC.
                     */
    CRYPT_PUBKEYPARAM KeyParam;
                    /*!< �������� ������� � ����� ������ ���� � 34.10-2001.
                     */
} CRYPT_PUBKEY_INFO_HEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� CRYPT_PUBLICKEYBLOB ��������� ��������� �������� ����
 * ���� PUBLICKEYBLOB ��� ������ "��������� CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBLICKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< ����� ��������� ��������� ����� ���� PUBLICKEYBLOB "��������� CSP".
                     */
    BYTE    bASN1GostR3410_2001_PublicKeyParameters[1/*������������*/];
                    /*!< �������� ASN1 ��������� � DER ���������, ������������
                     * ��������� ��������� �����, ��� ������� �����
                     * GostR3410-2001-PublicKeyParameters
                     * CPPK [RFC 4491] � CPALGS [RFC 4357].
                     */
    BYTE    bPublicKey[1/*������������*/];
                    /*!< �������� �������� ���� � ������� ������������� (ASN1 DER)
                     * ��� ������� ����� GostR3410-2001-PublicKey
                     * CPPK [RFC 4491].
                     * ����� ������� ����� tPublicKeyParam.KeyParam.BitLen/8.
                     */
}   CRYPT_PUBLICKEYBLOB, *PCRYPT_PUBLICKEYBLOB;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� CRYPT_PRIVATEKEYBLOB ��������� ��������� �������� ����
 * ���� PRIVATEKEYBLOB ��� ������ "��������� CSP".
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PRIVATEKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< ����� ��������� ��������� ����� ���� PRIVATEKEYBLOB "��������� CSP".
                     */
    BYTE    bExportedKeys[1/* ������ ������.*/];
	/*
	KeyTransferContent ::=
	SEQUENCE {
	    encryptedPrivateKey  GostR3410EncryptedKey,
	    privateKeyParameters PrivateKeyParameters,
	}
	KeyTransfer ::=
	SEQUENCE {
	    keyTransferContent       KeyTransferContent,
	    hmacKeyTransferContent   Gost28147HMAC
	}
	*/
}   CRYPT_PRIVATEKEYBLOB, *PCRYPT_PRIVATEKEYBLOB;

/* ����������� ��� ��������� DIVERSBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_DIVERSBLOBHEADER ��������� ����
 * ���� DIVERSBLOB ��� ��������� �������������� ������ ��������� CSP.
 *
 * \req_wincryptex
 * \sa CRYPT_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_DIVERSBLOBHEADER {
    BLOBHEADER BlobHeader;
                /*!< ����� ��������� �����, ������������������ ����.
                 */
    ALG_ID      aiDiversAlgId;
                /*!< ���������� �������� �������������� �����.
		 * ��������������� � CALG_PRO_DIVERS, CALG_RIC_DIVERS
		 * ��� CALG_PRO12_DIVERS.
		 * ��� �������� CALG_PRO_DIVERS �������������� ������������ �
		 * ������������ � ����������, ��������� � �. 7 RFC 4357.
		 * ��� �������� CALG_PRO12_DIVERS �������������� ������������
		 * � ������������ � ����������, ��������� � �. 4.5
		 * ������������ �� �������������� "������������� �����������������
		 * ����������, ��������������� ���������� ����������
		 * ���� � 34.10-2012 � ���� � 34.11-2012", ������������
		 * �� 26 "����������������� ������ ����������".
                 */
    DWORD       dwDiversMagic;
                /*!< ������� �������������� �����,
                 * ��������������� � \ref DIVERS_MAGIC.
                 */
   /*    BYTE        *pbDiversData;
                !< ��������� �� ������, �� ������� ����������������� ����.
                 */
    DWORD       cbDiversData;
                /*!< ����� ������, �� ������� ����������������� ����.
                 */
} CRYPT_DIVERSBLOBHEADER, *LPCRYPT_DIVERSBLOBHEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_DIVERSBLOB ��������� ����
 * ���� DIVERSBLOB ��� ��������� �������������� ������ ��������� CSP.
 *
 * \req_wincryptex
 * \sa CRYPT_DIVERSBLOBHEADER
 * \sa CPImportKey
 */
typedef struct _CRYPT_DIVERSBLOB {
    CRYPT_DIVERSBLOBHEADER DiversBlobHeader;
                /*!< ��������� �����, ������������������ ����.
                 */
    BYTE        bDiversData[1/*������ ���������� �����: [4..40] ������*/];
                /*!< ������, �� ������� ����������������� ����.
                 */
} CRYPT_DIVERSBLOB, *LPCRYPT_DIVERSBLOB;

/* ����������� ��� ��������� CRYPT_KDF_TREE_DIVERSBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_KDF_TREE_DIVERSBLOB_HEADER ��������� ����
 * ���� KDF_TREE_DIVERSBLOB ��� ��������� �������������� ��������� CSP,
 * ����������������� ����������� ��������� ���������� ������.
 * 
 * \req_wincryptex
 * \sa CRYPT_KDF_TREE_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_KDF_TREE_DIVERSBLOB_HEADER {
    BLOBHEADER  BlobHeader;
		/*!< ����� ��������� �����, ������������������ ����.
		*/
    ALG_ID      aiDiversAlgId;
		/*!< ���������� �������� �������������� ������.
		* ��������������� � CALG_KDF_TREE_GOSTR3411_2012_256.
		* �������������� ������������ � ������������
		* � ����������, ��������� � �. 4.5 ������������ ��
		* �������������� "����������������� ���������,
		* ������������� ���������� ���������� �����������
		* �������� ������� � ������� �����������", ������������
		* �� 26 "����������������� ������ ����������".
		*/
    DWORD	dwIterNum;
		/*!< ���������� ����� ��������������� �����.
		*/
} CRYPT_KDF_TREE_DIVERSBLOB_HEADER, *LPCRYPT_KDF_TREE_DIVERSBLOB_HEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_KDF_TREE_DIVERS_INFO �������� ���������
 * R, L, ����� Seed � Label ��� ��������� �������������� ��������� CSP,
 * ����������������� ����������� ��������� ���������� ������.
 *
 * \req_wincryptex
 * \sa CRYPT_KDF_TREE_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_KDF_TREE_DIVERS_INFO {
    DWORD       L_value;
                /*!< �������� L ��� ��������� �������������� */
    DWORD       R_value;
                /*!< �������� R ��� ��������� �������������� */
    DWORD       dwSeedLen;
                /*!< ����� �������� Seed ��� ��������� �������������� */
    DWORD       dwLabelLen;
                /*!< ����� �������� Label ��� ��������� �������������� */
} CRYPT_KDF_TREE_DIVERS_INFO, *LPCRYPT_KDF_TREE_DIVERS_INFO;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_KDF_TREE_DIVERSBLOB ��������� ����
 * ���� KDF_TREE_DIVERSBLOB ��� ��������� �������������� ��������� CSP,
 * ����������������� ����������� ��������� ���������� ������.
 *
 * \req_wincryptex
 * \sa CRYPT_KDF_TREE_DIVERSBLOB_HEADER
 * \sa CRYPT_KDF_TREE_DIVERS_INFO
 * \sa CPImportKey
 */
typedef struct _CRYPT_KDF_TREE_DIVERSBLOB {
    CRYPT_KDF_TREE_DIVERSBLOB_HEADER KdfTreeBlobHeader;
                /*!< ��������� �����, ������������������ ����.
                *  �������� ����� ��������� �����, �������� ��������������
                * � ����� ��������������� �����.
                */
    CRYPT_KDF_TREE_DIVERS_INFO KdfTreeDiversInfo;
                /*!< ���������, ���������� ����� ���������� �
                *  ��������������: ��������� R, L, ����� Seed � Label.
                */
    BYTE        bDiversData[1/*������ ���������� �����*/];
                /*!< ������ ����� KdfTreeDiversInfo.dwSeedLen +
				*  KdfTreeDiversInfo.dwLabelLen, ����������
                *  ���������� � ��������������: �������� Seed � Label
                */
} CRYPT_KDF_TREE_DIVERSBLOB, *LPCRYPT_KDF_TREE_DIVERSBLOB;

/*! \brief ������������ ����� ������� �� �������� */
#define CRYPTOAPI_SELECT_READER_MAX_APPLET_COUNT 10
/*! \brief ������������ ����� ������ � ����������� */
#define CRYPTOAPI_SELECT_READER_ICONS_NUMBER 5

/*! \brief ����� �����������/�������� */
typedef ULONGLONG HSELREADER;
/*! \brief ����� ������ */
typedef ULONGLONG HSELREADERICON;
/*! \brief ����� ������ ������������ � ������� ���������� */
typedef ULONGLONG HSELREADERLISTCONTEXT;
/*! \brief ����� �������� �������� ���������� */
typedef ULONGLONG HSELREADERINITDATA;

/*! \brief ��������� ���������� �������� ����������: ������ ������������ ������������ */
#define CRYPT_READER_WND_LIST_FIRST 1
/*! \brief ��������� ���������� �������� ����������: ������������ ������������ */
#define CRYPT_READER_WND_LIST_NEXT  2
/*! \brief ��������� ���������� �������� ����������: �������� ������������ ������������ */
#define CRYPT_READER_WND_LIST_FREE  3
/*! \brief ��������� ���������� �������� ����������: ��������� ������ ������� ������� */
#define CRYPT_READER_WND_ANSWER	    4
/*! \brief ��������� ���������� �������� ����������: ��������� ����������� �� ��������� */
#define CRYPT_READER_WND_DEFAULT    5
/*! \brief ��������� ���������� �������� ����������: �������� ��������� ����������� */
#define CRYPT_READER_WND_DELETE	    6
/*! \brief ��������� ���������� �������� ����������: ��������� ������ */
#define CRYPT_READER_WND_ICON	    7

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� �������� ���������� �� �������� ���������� 
*
* \req_wincryptex
* \sa CPSetProvParam
*/
typedef struct {
    DWORD param_type;			/*!< ��� ��������� */
    union {
	HSELREADERINITDATA context;		/*!< ��� CRYPT_READER_WND_LIST_FIRST - �������� �������� ���������� */
	HSELREADERLISTCONTEXT list_context;	/*!< ��� CRYPT_READER_WND_LIST_NEXT, CRYPT_READER_WND_LIST_FREE - ����� ������ */
	struct {
	    HSELREADERINITDATA	    context;	/*!< �������� �������� ���������� */
	    HSELREADER		    reader;	/*!< ����� ����������� */
	    unsigned int	    current_applet; /*!< ����� ������. ����� ������ ��� CRYPT_READER_WND_ANSWER */
	} reader; /*!< ��� CRYPT_READER_WND_ANSWER, CRYPT_READER_WND_DEFAULT, CRYPT_READER_WND_DELETE - ���������� � ����������� */
	struct {
	    HSELREADERINITDATA	context;    /*!< �������� �������� ���������� */
	    HSELREADERICON	hicon;	    /*!< �������� ������ */
	    DWORD	x_icon;		/*!< ����� �������� � ������ �� ����������� */
	    DWORD	y_icon;         /*!< ����� �������� � ������ �� ��������� */
            DWORD       priority;	/*!< ������������ ��������� ��������� ������������� ������ */
	} icon; /*!< ��� CRYPT_READER_WND_ICON - ���������� �� ������ */
    } info; /*!< ������������ ���������� */
} CRYPT_READER_WND_PARAM;

/*! \brief ��� ������: ������ ��� pin. �������� �������� */
#define CRYPT_PIN_PASSWD 0
/*! \brief ��� ������: ��� ���������� ������������
     ������������ ��� ����������. */
#define CRYPT_PIN_ENCRYPTION 1
/*! \brief ��� ������: �������� ���������� �� ����� �� HANDLE.
     ������������ ����� �����������. */
#define CRYPT_PIN_NK 2
/*! \brief ��� ������: ���������� */
#define CRYPT_PIN_UNKNOWN 3
/*! \brief ��� ������: ��� � �������� ���������� � ����. */
#define CRYPT_PIN_QUERY 4
/*! \brief ��� ������: �������� ������. */
#define CRYPT_PIN_CLEAR 5
/*! \brief ��� ������: ������������ ���������� �������. */
#define CRYPT_PIN_HARDWARE_PROTECTION 6
/*! \brief ��� ������: ������ ��� FKC ����������, ��� �������������� �� EKE */
#define CRYPT_PIN_FKC_EKE 	7
/*! \brief ��� ��������������: ������� ��� ������ �� ���� ����� ������ */
#define CRYPT_PIN_WND		8

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� �� ������� ����� ������ ��� ������������ ��� ����� ������
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct
{
    DWORD auth_type;			/*!< ������������� ��� ��������������, ������� ��������������� ��� �������� */
    DATA_BLOB password;			/*!<  ����� �������� ������ */
    struct
    {
	unsigned once : 1;		/*!<  1, ���� ������ �� ����������� � ����, 0, �����*/
	unsigned save : 1;		/*!<  1, ���� ��������� ��������� ������ ���������� */
    } flags;
    DATA_BLOB   reserved;		    /*!<  ����� ���������� ������ �������������� */
} CRYPT_PIN_WND_SOURCE_PARAM;

#define CRYPT_PIN_WND_PARAM_CLEAR   0 /*!< ��� ������������ ����������.  ������� ��������������� ����� ��������� �� ��������� ����������. */
#define CRYPT_PIN_WND_PARAM_INFO    1 /*!< ��� ������������ ����������.  ���������� ��������� �� ��������� ����������, ���������� ������� ����� ������, ��� ��������� � �������� ���������� ��������� ����������������. */
#define CRYPT_PIN_WND_PARAM_AUTH    2 /*!< ��� ������������ ����������.  ���������� ���������� �� ��������������. */
#define CRYPT_PIN_WND_PARAM_BOTH    (CRYPT_PIN_WND_PARAM_INFO | CRYPT_PIN_WND_PARAM_AUTH )/*!< ��� ������������ ����������.  ���������� ��������� �� ��������� ����������, ���������� ������� ����� ������ � ���������� �� ��������������. ��������� ����������� ��������� 
				       *   � �������� ���������� ��������� ���������������� �� ������������. */

/*!
* \ingroup ProCSPData
*
* \brief ��������� �������� ���������� �� ������� ����� ������
*
* \req_wincryptex
* \sa CPSetProvParam
*/
typedef struct
{
    BYTE info_type;  /*!< ��� ������������ ����������. ����� ���� ����� CRYPT_PIN_WND_PARAM_CLEAR, CRYPT_PIN_WND_PARAM_INFO, CRYPT_PIN_WND_PARAM_AUTH, CRYPT_PIN_WND_PARAM_BOTH */
    void * info;			    /*!<  ���� ��� �������� ��������� �� ��������� ����������. */
    CRYPT_PIN_WND_SOURCE_PARAM auth;	    /*!< ���� ��� �������� ��������������. */
} CRYPT_PIN_WND_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ��� ������� ������ ����������
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_PIN_NK_PARAM {
    short n; /*!< ���������� ������������ ������. */
    short k; /*!< ���������� ������ ��� ��������. */
    DWORD *parts; /*!< 32-������ ���������� �������������� ������ ����������. */
} CRYPT_PIN_NK_PARAM;

/*!
 * \brief ��������� �������� ������, pin-����, ����� ����������,
 *  HANDLE ���������� ��� ����� ������.
 */
typedef union _CRYPT_PIN_SOURCE {
    char *passwd; /*!< ������, PIN-���, ��� ����������. */
    DWORD prov; /*!< 32-������ ���������� ������������� ����������. */
    CRYPT_PIN_NK_PARAM nk_handles; /*!< �������� �� NK �� ��������������� */
    CRYPT_PIN_WND_PARAM wnd;	    /*!< ���������� �� ����������� ����*/
} CRYPT_PIN_SOURCE;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ���:
 *  1) ����� ������ ����������,
 *  2) �������� ������� ������� � ���������� (���, handle, ������), �� ����� ��������
 *     ����������� ���������� ������� ����������.
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_PIN_PARAM {
    BYTE type;
    /*!< ��� ������.
 *  CRYPT_PIN_PASSWD - ������ ��� PIN,
 *  CRYPT_PIN_ENCRYPTION - HANDLE ���������� ������������.
 *  CRYPT_PIN_QUERY - ��� � �������� ���������� � ����,
 *  CRYPT_PIN_CLEAR - �������� ������.
 *  CRYPT_PIN_NK - ������� �� ����� k �� n.
 *  CRYPT_PIN_WND - ���������� �� ����������� ���� ����� ������.
 */
     CRYPT_PIN_SOURCE dest; /*!< ������ ���������������� ���� */
} CRYPT_PIN_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��������� ���������� � ���������� ������������ �� �����.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CRYPT_NK_INFO_PARAM {
    short n; /*!< ���������� ������, �� ������� �������� ���������. */
    short k; /*!< ���������� ������, ����������� ��� ��������� ������. */
    char parts[1]; /*!< ������������������ n ASCIIZ �����. */
} CRYPT_NK_INFO_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ��������� ���������� � ������ �� ���������.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CRYPT_PASSWD_INFO_PARAM {
    unsigned min_passwd_length; /*!< ����������� ���������� ������ ������. */
    unsigned max_passwd_length; /*!< ������������ ���������� ������ ������. */
    unsigned passwd_type; /*!< ��� ������. */
} CRYPT_PASSWD_INFO_PARAM;

#define CSP_INFO_SIZE sizeof(CSP_INFO)

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� � ������ �� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PASSWD_INFO_PARAM, CRYPT_NK_INFO_PARAM
*/
typedef union _CRYPT_PIN_INFO_SOURCE {
    CRYPT_PASSWD_INFO_PARAM passwd;
    CRYPT_NK_INFO_PARAM nk_info;
    char encryption[1];
} CRYPT_PIN_INFO_SOURCE;

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� � ������ �� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PIN_INFO_SOURCE
*/
typedef struct _CRYPT_PIN_INFO {
    BYTE type; /*!< ��� ������.
 *  CRYPT_PIN_UNKNOWN - ��� ����������
 *  CRYPT_PIN_PASSWD - ������ ��� PIN,
 *  CRYPT_PIN_ENCRYPTION - HANDLE ���������� ������������.
 *  CRYPT_PIN_NK - ������� �� ����� k �� n
 *  CRYPT_PIN_HARDWARE_PROTECTION - ��� ������ ������������ ���������� �������
 */
     CRYPT_PIN_INFO_SOURCE dest; /*!< ������ ���������������� ���� */
} CRYPT_PIN_INFO;

#define PROVIDER_TYPE_FKC_MAGISTRA 1


/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��������� ���������� � ������ ���������� ��� �������������� �� EKE
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_FKC_EKE_AUTH_INFO_PARAM {
    unsigned min_passwd_length; /*!< ����������� ���������� ������ ������. */
    unsigned max_passwd_length; /*!< ������������ ���������� ������ ������. */
    unsigned count_eke; /*!< ������� ���������� �������� EKE. */
    unsigned count_dh; /*!< ������� ���������� �������� �����-��������. */
    unsigned count_sig; /*!< ������� ���������� �������� �������. */
    unsigned count_err; /*!< ������� ���������� ������. */
    unsigned count_cerr; /*!< ������� ���������� ���������������� ������. */
    char fname[1]; /*!< UTF8Z-������ �������������� �����. */
} CRYPT_FKC_EKE_AUTH_INFO_PARAM;

#define CPCAR_COUNTER_TRYES 0	/*!< ������ �������� ���������� ������� � ������� ���������*/
#define CPCAR_COUNTER_CSP_REM 1 /*!< ������ �������� ���������� ��������� �������� CSP*/
#define CPCAR_COUNTER_CAR_REM_ERR 2 /*!< ������ �������� ���������� ��������� �������� ��������*/
#define CPCAR_COUNTER_CAR_REM_CERR 3 /*!< ������ �������� ���������� ��������� �������� �������� ������*/
#define CPCAR_COUNTER_CAR_REM_AUTH 4 /*!< ������ �������� ���������� �������������� �� ��������*/

#define CPCAR_COUNTER_ROOT_NUMBER 5 /*!<  ������������ ����� ��������� ��� ���������������� �������������� */

#define CPCAR_COUNTER_CAR_REM_DH 5 /*!<  ������ �������� ���������� �������� �� � ���������� */
#define CPCAR_COUNTER_CAR_REM_SIGN 6 /*!<  ������ �������� ���������� �������� ������� � ���������� */
#define CPCAR_COUNTER_CAR_SIGN 7 /*!<  ������ �������� ����������� �������� ������� � ���������� */

#define CPCAR_COUNTER_CONTAINER_NUMBER 8 /* ������������ ����� ��������� ���������� */

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ��������� ��������������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_FKC_PIN_INFO, CRYPT_FKC_PIN_INFO_SOURCE
*/
typedef struct
{
    DWORD main_counters[CPCAR_COUNTER_CONTAINER_NUMBER];  /*!< �������� ��� �������� �������������� */
    DWORD unblocking_counters[CPCAR_COUNTER_ROOT_NUMBER];	/*!< �������� ��� �������������� ��������� �������������� */
    DWORD error;					/*!< ������, ��������� ����������� � ��������� ������������. �������� "��������� ������� �����" */
} CRYPT_WND_INFO_PARAM;

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� � ������ �� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PIN_INFO_SOURCE, CRYPT_FKC_EKE_AUTH_INFO_PARAM
*/
typedef union _CRYPT_FKC_PIN_INFO_SOURCE 
{
    CRYPT_PIN_INFO_SOURCE passwd; /*!< ������� ������. */
    CRYPT_FKC_EKE_AUTH_INFO_PARAM eke_passwd; /*!< ������ �� EKE. */
    CRYPT_WND_INFO_PARAM wnd_info; /*!< �������� ��� ����. */
} CRYPT_FKC_PIN_INFO_SOURCE;

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� � ������ �� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_FKC_PIN_INFO_SOURCE
*/
typedef struct _CRYPT_FKC_PIN_INFO {
    BYTE type;
    /*!< ��� ������.
     *  CRYPT_PIN_FKC_EKE - ������ ���������� FKC ���������� �� EKE.
     *  ������ ���� ��� � CSP.
     */
     CRYPT_FKC_PIN_INFO_SOURCE dest; /*!< ������ ���������������� ���� */
} CRYPT_FKC_PIN_INFO;


/*! \brief ��������: ������������ ������ */
#define CRYPT_AUTH_PASSWD 0xf0
/*! \brief ��������: ������������ ������ � �������� ����� ���������������� ��������� */
#define CRYPT_AUTH_QUERY 0xf1
/*! \brief ��������: ������� ������������������ ���������� ������� ���� �� ���� �������������� */
#define CRYPT_AUTH_CLEAR 0xf2
/*! \brief ��������: �������� ����� ������ �������������� ��� ������ �������������� */
#define CRYPT_AUTH_RESET_TRIES 0xf3
/*! \brief ��������: ���������� ������ �������������� �������� �� ��������� */
#define CRYPT_AUTH_RESET_ADMIN 0xf4

/*! \brief ��� ��������� ��������������: PUK. ��������� ����� ������ �������������� ��������.*/
#define CRYPT_AUTH_TYPE_PUK 1
/*! \brief ��� ��������� ��������������: ADMIN. ��������� ������ � ������ ��������, ��������, ����� ��������� �������� ����������. 
           ����� ���� ������������ ��������������� �� ��������, � ��������� ������ �� ��������� ������ ����������. */
#define CRYPT_AUTH_TYPE_ADMIN 2
/*! \brief ��� ��������� ��������������: CONT. ��������� ��������� ����������. ��������� ������ ��� ������ ����������. */
#define CRYPT_AUTH_TYPE_CONT 3
/*! \brief ��� ��������� ��������������: USER1. �������������� ��������������, �� �������� �������� �������������� ����������� ADMIN. �� ������������. */
#define CRYPT_AUTH_TYPE_USER_PIN1 4
/*! \brief ��� ��������� ��������������: USER2. �������������� ��������������, �� �������� �������� �������������� ����������� ADMIN. �� ������������. */
#define CRYPT_AUTH_TYPE_USER_PIN2 5

/*! \brief �������� ��������� ��������������: NO. ��������, ��� ���������� �������� �� ������� ��������������, � �� ���������� ����� �� ����������������. */
#define CRYPT_AUTH_ALG_NO 0
/*! \brief �������� ��������� ��������������: SELF. ��������, ��� �������������� ����������� ��������� �� ������� ���������������� ���������� �������� ��� ����������� (��������, �������������� �� ���� �� ���-����). */
#define CRYPT_AUTH_ALG_SELF 1
/*! \brief �������� ��������� ��������������: SIMPLE. ������ ������������ ���-���� ��������. */
#define CRYPT_AUTH_ALG_SIMPLE 2
/*! \brief �������� ��������� ��������������: SESPAKE. ������������ ������ �� ��������� SESPAKE � ��������� ����������� ���������� � ���������. */
#define CRYPT_AUTH_ALG_SESPAKE 3

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� �� ��������������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_AUTH_INFO
*/
typedef struct {
    BYTE auth_type; /*! \brief ��� �������������� �� ����� ������������ (CRYPT_AUTH_TYPE_PUK, CRYPT_AUTH_TYPE_CONT, ...) */
    BYTE auth_alg;  /*! \brief �������� �������������� (CRYPT_AUTH_ALG_SELF, CRYPT_AUTH_ALG_SIMPLE, ...) */
    DWORD min_length; /*! \brief ����������� ����� ������ */
    DWORD max_length; /*! \brief ������������ ����� ������ */
} CRYPT_AUTH_INFO_AUTH;

#define CRYPT_AUTH_INFO_DEF_ADMIN 1 /* \brief ����: � �������������� �������������� ���������� ������ �� ���������. 1 - ����, 0 - ���. */
#define CRYPT_AUTH_INFO_ADMIN_IS_CONT 2 /* \brief ����: ���������� �� �������� �������� ��������������� �������� (ADMIN). 2 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_ADMIN_IS_PUK 4 /* \brief ����: ���� �������������� � �� ��������� ������������������ ������, � �� �������� ��� �������� ����������� (ADMIN). 4 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_RESETS_COUNTERS 8 /* \brief ����: ������������ �������������� ����� ���.������ ������������� ���������� �������� ������ � ������ ���������������. 8 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_CAN_RESET_COUNTERS 16 /* \brief ����: ����� ������������ �������������� ����� ���.������ ����� �������� ������� ������ � ������ ���������������. 16 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_CAN_CHANGE_AUTH 32 /* \brief ����: ����� ������������ �������������� ����� ���.������ ����� �������� ���.������ ������������ ��������������. 32 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_CAN_RESET_ADMIN 64 /* \brief ����: �������������� �������������� ����� ���� ���������� ������ �� ���������. 64 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_RESTORE_CONT_AFTER_FOLDER_OPEN 128 /* \brief ����: ����� �������� ����� ���������� ��������� ��������� ������������ ��������������. 128 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_HARDWARE_RESET_ROOT_DEF 256 /* \brief ����: ��� ������ �������������� �������������� ��������� ��������� ���������� ��������. 256 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_CHANGE_WITH_VERIFY 512 /* \brief ����: ��� ��������� �������������� ���������� ������������ ����������� �������������� � ��� �� �������. 512 - ��, 0 - ���. */
#define CRYPT_AUTH_INFO_COMMON_AUTH 1024 /* \brief ����: �������������� �������������� �������� ����� ��� ����� � ������ �������� �� ������ ��������. 1024 - ��, 0 - ���. */

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� �� ��������������� � ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, PP_AUTH_INFO
*/
typedef struct {
    DWORD auth_count; /* \brief ����� �������������� � ���������. */
    DWORD flags;    /* \brief ����� ������ ��������������. ����� ���� ����������� CRYPT_AUTH_INFO_DEF_ADMIN_SET, CRYPT_AUTH_INFO_DEF_ADMIN_CAN, CRYPT_AUTH_INFO_ADMIN_IS_CONT, CRYPT_AUTH_INFO_ADMIN_IS_PUK */
    CRYPT_AUTH_INFO_AUTH auth[1]; /* \brief ������ �������������� ������� auth_count. */
} CRYPT_AUTH_INFO;


#define CRYPT_MAX_PIN_LENGTH 160

typedef struct {
    BYTE action;    /*! �������������� ��������: CRYPT_AUTH_PASSWD, CRYPT_AUTH_QUERY, CRYPT_AUTH_CLEAR, CRYPT_AUTH_RESET_TRIES. */
    BYTE changed_auth_type; /*! ��� ���������� �������������� */
    CHAR changed_pin[CRYPT_MAX_PIN_LENGTH + 1]; /*! ������ ���������� ��������������, ���� ����, LPSTR */
    BYTE verify_auth_type; /*! \brief ��� ������������� �������������� */
    CHAR verify_pin[CRYPT_MAX_PIN_LENGTH + 1]; /*! \brief �������� ������ ������������� ��������������, LPSTR */
} CRYPT_CHANGE_AUTH;

typedef struct
{
    void * hCSP;	/* ������ �� CSP, � ������� �������������� ������ */
    void * info;	/* �������������� ���������� �� ��������������� ���������� */
} PWDFKC_CONTEXT;

/*!
 * \ingroup ProCSPData
 *
 * \brief �������� ��������� "�������� ��������� ����� � �������� �����-��������".
 * ��� ��������� ��������� ���������� ���������� ���� DWORD. 
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 * \sa CRYPT_FKC_DH_CHECK
 */
typedef enum _CRYPT_FKC_DH_CHECK_VAL
{
    dh_check_disable = 1, /*!< �������� ��������� ����� �� �������������� */
    dh_check_enable = 2 /*!< �������� ��������� ����� �������������� */
} CRYPT_FKC_DH_CHECK_VAL;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ��������� ������� �������� ��������� �����.
 * �������� � ������������� �������� "�������� ��������� ����� � �������� �����-��������"
 * ��� ����������� FKC ( PP_FKC_DH_CHECK ). 
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 * \sa CRYPT_FKC_DH_CHECK_VAL
 */
typedef struct _CRYPT_FKC_DH_CHECK
{
    CRYPT_FKC_DH_CHECK_VAL checkdh; /* �������� ��������� */
    BOOL is_writable; /*!< ����� �� ���������� ��������� ����� �������� */
} CRYPT_FKC_DH_CHECK;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ��������� � ��������� �������� ����������� �����������.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_CACHE_SIZE {
    DWORD cache_size; /*!< ������ ����. */
    DWORD max_cache_size; /*!< ������������ ������ ����. */
    BOOL is_writable; /*!< ��. CACHE_RO  */
} CRYPT_CACHE_SIZE;

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� � ��������� ��������� �������� ���������� ��������� ����������.
* ��������� TContainerParamType_AuthServer, TContainerParamType_SignServer, TContainerParamType_OAuth2_AuthToken � TContainerParamType_OAuth2_IdToken 
* ���������� � ���� ����-��������������� ASCII-�����. TContainerParamType_CertificateID � ���� DWORD.
* \req_wincryptex
* \sa CPGetProvParam
* \sa CPSetProvParam
*/
typedef enum _TContainerParamType {
    TContainerParamType_Header,
    TContainerParamType_AuthServer,
    TContainerParamType_SignServer, 
    TContainerParamType_OAuth2_AuthToken, 
    TContainerParamType_OAuth2_IdToken, 
    TContainerParamType_Username,
    TContainerParamType_Password,
    TContainerParamType_Certificate,
    TContainerParamType_CertificateID
} TContainerParamType;

typedef struct _CRYPT_CONTAINER_PARAM {
    TContainerParamType param_type;
    DWORD cbData;
    BYTE pbData[1];
} CRYPT_CONTAINER_PARAM;

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� � ��������� �������� ��������� ������ ����� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam
* \sa CPSetProvParam
*/

#define ENABLE_CARRIER_TYPE_CSP 0x01   // ������� ��������������� (CSP 3.6 - CSP 4.0)
#define ENABLE_CARRIER_TYPE_FKC_NO_SM 0x02  // ��� ��� SM (������� ���, ������ ���� � �.�.)
#define ENABLE_CARRIER_TYPE_FKC_SM 0x04 // ��� � SM (SESPAKE)
#define ENABLE_ANY_CARRIER_TYPE (ENABLE_CARRIER_TYPE_CSP|ENABLE_CARRIER_TYPE_FKC_NO_SM|ENABLE_CARRIER_TYPE_FKC_SM)

#define DISABLE_EVERY_CARRIER_OPERATION 0x00  // ����������� ���� ��������� ��������� ���������
#define ENABLE_CARRIER_OPEN_ENUM 0x01   // �� ����������� ����� ��������� ����� ��������� � ����������� ����������
#define ENABLE_CARRIER_CREATE 0x02  // �� ����������� ����� ��������� ����� ��������� ����������
#define ENABLE_ANY_OPERATION (ENABLE_CARRIER_OPEN_ENUM|ENABLE_CARRIER_CREATE)

typedef struct _CRYPT_CARRIER_TYPES {
    DWORD enabled_types; /*!< ����������� ���� ���������. */
    DWORD enabled_operations; /*!< ����������� �������� ��� ����������� ���������. */
} CRYPT_CARRIER_TYPES;

/*!
* \ingroup ProCSPData
*
* \brief �����, ���������� ����� CryptGetProvParam(PP_ENUMREADERS, CRYPT_MEDIA) � CryptGetProvParam(PP_CARRIER_FLAGS)
*
* \req_wincryptex
* \sa CPGetProvParam
*/

#define CARRIER_FLAG_REMOVABLE 1                  /* ������� ������������� �������� (���������� � �����-���� � ����-�����������) */
#define CARRIER_FLAG_UNIQUE 2                     /* ������� ������� ����������� ������ (���������� � �����-���� � ����-�����������) */
#define CARRIER_FLAG_PROTECTED 4                  /* ������� ��������, ����������� ����������� �� ������ ���������� (���������� � HSM) */
#define CARRIER_FLAG_FUNCTIONAL_CARRIER 8         /* ������� ���-�������� (�������� � �������������� �������) */
#define CARRIER_FLAG_SECURE_MESSAGING 16          /* ������� ���-�������� � ���������� ����������� ������ ����������� � ��������� SESPAKE */
#define CARRIER_FLAG_ABLE_SET_KEY 32		  /* ������� ����������� ��������� ��������� ����� �� ���-�������� */
#define CARRIER_FLAG_ABLE_VISUALISE_SIGNATURE 64  /* ������� ����������� ����������� ����������� ������������� ������� (SafeTouch, ������� ������) */

/*!
* \ingroup ProCSPData
*
* \brief ���� � ����������� � �����������, �������������� �����
* ��������������� ���������������.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMREADER_INFO {
    char    szNickName[1]; /*!< NickName ����������� - NULL-��������������� ������. */
    char    szName[1]; /*!< ��� ����������� - NULL-��������������� ������. */
    BYTE   Flags; /*!< ����� �����������. */
} CRYPT_ENUMREADER_INFO;

/*!
* \ingroup ProCSPData
*
* \brief ���� � ����������� � �����������, �������������� �����
* ��������������� ���������������.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMREADER_INFO_MEDIA {
    char    szNickName[1]; /*!< NickName ����������� - NULL-��������������� ������. */
    char    szName[1]; /*!< ��� ����������� - NULL-��������������� ������. */
    char    szMedia[1]; 
    	/*!< NULL-��������������� c����� � UNIQUE-������ �������� ��� ��������, ���� UNIQUE �� ������� ��������:
         * <table><tr><th>\b szMedia</th><th>��������</th></tr>
         * <tr><td>
         * NO_MEDIA
         * </td><td>
         *      ����� �� ���������
         * </td></tr><tr><td>
         * NO_UNIQUE
         * </td><td>
         *      �������� �� ������������ UNIQUE (NB: ��� USB-Flash-��������� �� Unix �� ����� UNIQUE, � �� Windows � �����)
         * </td></tr><tr><td>
         * INVALID_MEDIA
         * </td><td>
         *      ��� ������ � ��������� �������� ������
         * </td></tr><tr><td>
         * IS_FKC
         * </td><td>
         *      ���-�������� � ��-���-����������
         * </td></tr><tr><td>
         * NO_FKC
         * </td><td>
         *      ��-���-�������� � ���-����������
         * </td></tr><tr><td>
         * GEM_35000030CFE53C70
         * </td><td>
         *      ������ UNIQUE-�����
         * </td></tr><tr><td>
         * rutoken_2a7d64bb
         * </td><td>
         *      ������ UNIQUE-�����
         * </td></tr><tr><td>
         * JACARTA_0b52002140489243
         * </td><td>
         *      ������ UNIQUE-�����
         * </td></tr><tr><td>
         * ESMART_50CF20508942
         * </td><td>
         *      ������ UNIQUE-�����
         * </td></tr><tr><td>
         * 1082C025
         * </td><td>
         *      ������ UNIQUE-�����
         * </td></tr></table>
    	 */
    BYTE   Flags; /*!< ����� �����������. */
} CRYPT_ENUMREADER_INFO_MEDIA;

/*!
* \ingroup ProCSPData
*
* \brief ���� � ����������� � ���, �������������� �����
* ��������������� ���������������.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMRANDOMS_INFO {
    char    szNickName[1]; /*!< NickName ��� - NULL-��������������� ������. */
    char    szName[1]; /*!< ��� ��� - NULL-��������������� ������. */
    BYTE    Flags; /*!< ����� ���. ������� ��� - ������� �����������������, ��������������� ��� ������������ � CRYPT_AVAILABLE. */
    DWORD   level; /*!< ������������ ������� ���. */
} CRYPT_ENUMRANDOMS_INFO;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ��� ��������� � ��������� ����������� �������� ��������� R ��� ��� 
 *  �� ���� ��������������� ��������� ��������.
 *
 * \sa CPGetHashParam
 * \sa CPSetHashParam
 */
typedef struct _CRYPT_HASH_BLOB_EX {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
    BYTE    pbData [2*SECRET_KEY_LEN];
} CRYPT_HASH_BLOB_EX, *PCRYPT_HASH_BLOB_EX;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ������� �������� �������� ������ �� ����� ����������� ����������
 *
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_KEY_PERIOD {
    LONG privateKeySeconds;		/*!< ������ �������� ��������� �����, � ��������. */
    LONG publicKeySeconds;		/*!< ������ �������� ��������� �����, � ��������. */
} CRYPT_KEY_PERIOD, *PCRYPT_KEY_PERIOD;

#define CSP_INFO_FREE_SPACE	(0)	/* ��������� ����� �� /var � bytes */
#define CSP_INFO_NUMBER_UL	(1)	/* "\\local\\number_UL" --- ���������� ���������� ������ �� */
#define CSP_INFO_NUMBER_SIGNS	(2)     /* "\\local\\number_signs" --- ���������� �������� ������� */
#define CSP_INFO_KCARDS_CHANGES	(3)     /* "\\local\\Kcard_changes" --- ���������� ���� ���� ������ "�" */
#define CSP_INFO_NUMBER_KCARDS	(4)     /* "\\local\\number_Kcard_sessions" --- ���������� ���������� � ��������� ��� ���� ������ "�" */
#define CSP_INFO_NUMBER_KEYS	(5)     /* "\\local\\number_keys" --- ���������� ����������  */
#define CSP_INFO_FUTURE_SIZE	(10)
typedef struct
{
  WORD version;		/* ������ ��������� */
  DWORD time;		/* time_t */
  DWORD keys_remaining;	/* ������� ���� */
  DWORD future[CSP_INFO_FUTURE_SIZE];
} CSP_INFO;

typedef struct DSS_AUDIT_INFO_
{
    FILETIME time;
    DWORD cbHash;
    BYTE pbHash[64];
} DSS_AUDIT_INFO, *PDSS_AUDIT_INFO;

/* ����� ���������� ����� ��� ���� 28147, ������� � ������.*/

#define CPC_FAST_CODE_DEFAULT	0
#define CPC_FAST_CODE_NO	1
#define CPC_FAST_CODE_USER	2

#ifdef UNIX
    #if defined(__GNUC__) && !defined(IOS) && (!defined (PROCESSOR_TYPE) || (PROCESSOR_TYPE == PROC_TYPE_I386))
	#define CPCAPI	__attribute__((regparm(0)))
    #else // __GNUC__
	#define CPCAPI
    #endif // __GNUC__
    #define CPC_SIZE_T	SIZE_T
#else // UNIX
    #define CPCAPI	__cdecl
    #define CPC_SIZE_T	size_t
#endif // UNIX

/*!
 * \ingroup ProCSPData
 * \brief �������� ������� ������� FPU � ������ ���� ��.
 * 
 *  ������� ������ ������������ ������ FPU (��������
 *  �������� ��������� MMX (ST) � XMM ). �� ����������
 *  ����� ��� ���������� ���������, ��� ������, 
 *  ��� �������, ������������ �������������� ��������,
 *  �������������� � �����, � �������������� ���������,
 *  �� ������� ����� ������ � ���������������� �������.
 *
 * \param buf [in] �� ����������� �����, ��������������� ����������� ��� ����������
 *  �������������� ���������.
 *
 * \param sz [in] ������ ������, ����������� ����������� ��� ����������
 *  �������������� ���������.
 *
 * \param bl_len [in] ������ ������, �������������� ��������, �����������
 * ���������� ���������.
 * 
 * \param op_type [in] ��� �������, ����������� ���������� ���������.
 * ��� ����� ���� ����� �� ������:<br>
 * <table><tr><th>
 * �������� \e op_type
 * </th><th>
 *      ��� �������
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      ������������������ ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      �������������� ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      ������� ��������� ������������ �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      ������� ����������� �� ���� � 34.11-94
 * </td></tr></table>
 *
 * \return ��������� ������� ������������ FPU.
 *
 * \retval TRUE ������ ������������ ��� ����������. 
 * � ���� ������ ��������� ������� �������, ������������
 * MMX ��� SSE, � ����� �� - ������� \ref CPC_Kernel_Fpu_End_Callback .
 * ��������� ���� ������� ���������� �������� � ������� ����������,
 * � ��� ���������������� ������� FPU ���������� ��� ��� ������� ����������,
 * ��� � ���������� �������������� ������. 
 * \retval FALSE ������ �� ��� ����������. � ���� ������
 * ��������� ������� �������, ������������ ������ ����������� �����
 * ���������� (�������������).
 * \sa CPC_FAST_CODE
 * \sa CPC_Kernel_Fpu_End_Callback
 * \sa CPSetProvParam()
 * \sa CPCSetProvParam()
 */
typedef BOOL CPCAPI CPC_Kernel_Fpu_Begin_Callback(
    /* [in] */ BYTE * buf,
    /* [in] */ CPC_SIZE_T sz,
    /* [in] */DWORD bl_len,
    /* [in] */DWORD op_type);


/*!
 * \ingroup ProCSPData
 * \brief �������� ������� ������������ FPU � ������ ���� ��.
 * 
 *  ������� ������ ������������ ������������ FPU (��������������
 *  �������� ��������� MMX (ST) � XMM ). �� ���������� ����� 
 *  ��� ���������� ���������, ��� ������, ��� �������, ��������������
 *  � ���������� �������������� ��������, � ������������� ����� ������ 
 *  ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *
 * \param buf [in] �����, ��������������� ����������� ��� ����������
 *  �������������� ���������. � ��� ������ ���� ��������� ���������
 *  ������������ ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *
 * \param sz [in] ������ ������, ����������� ����������� ��� ����������
 *  �������������� ���������.
 *
 * \param op_type [in] ��� �������, ����������� ���������� ���������.
 * ��� ����� ���� ����� �� �������:<br>
 * <table><tr><th>
 * �������� \e op_type
 * </th><th>
 *      ��� �������
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      ������������������ ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      �������������� ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      ������� ��������� ������������ �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      ������� ����������� �� ���� � 34.11-94
 * </td></tr></table>
 *
 * \return ��������� ������������ ������������ FPU.
 *
 * \retval TRUE ������������ ������������ ���� ������������. 
 * \retval FALSE ������������ �� ���� ������������. 
 *
 * \sa CPC_FAST_CODE
 * \sa CPC_Kernel_Fpu_Begin_Callback
 * \sa CPSetProvParam()
 * \sa CPCSetProvParam()
 */
typedef BOOL CPCAPI CPC_Kernel_Fpu_End_Callback(
    /* [in] */ BYTE * buf,
    /* [in] */ CPC_SIZE_T sz,
    /* [in] */ DWORD op_type);

/*!
 *  \ingroup ProCPCData
 *
 *  \brief ��������� ������������� ���������� ����������: MMX, SSE2, SSSE3, AVX.
 *
 *  �� ����������� Intel Pentium 4 � ����� ����� ������� ��������� ����������
 *  ���������� � ����������� �� ���� ������������� ���������� ���������� 
 *  MMX, SSE2, SSSE3, AVX. ��������� ������� SSE2 �������������� � ������� 
 *  ������ ���������.
 *  
 *  ����������������� �������, ������������ ����������, ������� � 
 *  ��������� ������:
 *  <table><tr><th>
 * ������������� ������
 * </th><th>
 *      ������
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      ������������������ ������� ���������� �� ���� 28147-89.
 *	��� ��� ���������� ������ ��������� ���������� MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      �������������� ������� ���������� �� ���� 28147-89.
 *	��� ��� ���������� ������ ��������� ���������� MMX, 
 *      �������� ������������� SSSE3 � AVX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      ������� ��������� ������������ �� ���� 28147-89.
 *	��� ��� ���������� ������ ��������� ���������� MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      ������� ����������� �� ���� � 34.11-94.
 *	��� ��� ���������� ��������� ���������� MMX � SSE2.
 * </td></tr><tr><td>
 * #CSP_OPERATION_MULT
 * </td><td>
 *      ������� ��������� � ���� �� ������ P (����������� � 
 *      ���������� ������� � �����-��������).
 *	��� �� ���������� ��������� ���������� MMX � SSE2.
 * </td></tr><tr><td>
 * #CSP_FAST_CODE_DISABLE_SSSE3
 * </td><td>
 *      ������ ������������� ���������� ���������� SSSE3.
 * </td></tr><tr><td>
 * #CSP_FAST_CODE_DISABLE_AVX
 * </td><td>
 *      ������ ������������� ���������� ���������� AVX.
 * </td></tr><tr><td>
 * #CSP_FAST_CODE_RT_TS
 * </td><td>
 *      ������ FPU ������ �� ����� ��������, ����������� � ������ ����
 *      ��� ������� ������������ TS-��� (Solaris, Linux).
 * </td></tr></table>
 * ������������ ������� ������������� ��� ������������ ��������� ���������� 
 * ������� ������� ����� �������� ���������� �������. ����� ��������� ������� 
 * ���������� � ����� ������� �������� �����, ��� ���������� ����� 
 * ��������������� ������� ������� MMX � SSE.
 *
 * � ����� � ������� ������������� ���������� �������� �� ���� ����������� 
 * ����������� x86 � �������� x86 �� ������������ x64 � IA64, ��� ����������� 
 * ������� ����������, ����� �� ������� ������� � ������� ����� 
 * �������� ������� �� ���������� ����������, � ���������� �������� ����, 
 * ��������� ������ � �.�. 
 *
 * ��������� ��������� �� ������������� �������� �������� ��������� 
 * ������� �����:
 * <ol type="1">
 * <li>
 * � ������� ������ SetProvParam (PP_FAST_CODE_FUNCS), 
 * � ������� ��������� ������ ���������
 * </li>
 * <li> 
 * �� ������ CPC, ��� ������������� ������������������ ������, ���� �������� 
 * ������ ��������� � ������������� ����������
 * </li>
 * <li> 
 * ��� ������������� ���������������� � ���������������� ������, 
 * ���� ��������� ����� ������������ ������ ������� � ������ �
 * '\\Crypto Pro\\Cryptography\\CurrentVersion\\Parameters\\MMXFuncs'
 * ��� �� Unix ��������:
 * "cpconfig -ini '\\config\\Parameters' -add long MMXFuncs ��������_�����",
 * ���� ���� ������� �������� ��������������� ���� UsedMask �� ���������.
 * </li>
 * <li> 
 * c ������� ������� 'csptest -speed -type ALL -mode REG'.
 * ����� ����� ������� �������� ���� � ������� ����������� ���������
 * � ��������� ���� ���� �������. 
 * </li>
 * </ol>
 * 
 * � ���������� ���� ��� ������ ������������� ������� MMX/SSE/SSSE3/AVX:
 * <ol type="1">
 * <li> 
 *  ����� ����������� ���������, ����������� �������� ����������������.
 * </li>
 * <li> 
 *  ���������, ��������� ������ �� ������� ������������� �������.
 * </li>
 * <li> 
 *  ���������, ��������������� ������������� � ������� ������� SetProvParam.
 * </li>
 * </ol>
 *
 * ������ �� ��� ��� ������ ����� ������ Crypt � CP ��������������� �� �������,
 * ���, ���� ������ ���������� ��� �������� �� ��������, ��� ��������� 
 * ����������� ���������, ���������� ����������� ��� ������ �������. 
 * ��� ������ �� ������ CPC ������ ��������� ��������� ������������� 
 * ��� ������������� ����������, ��� ������������� ��������� 
 * ������������ ��� ���������� ���������.
 *
 * ��� ��������� ���������� ����������� ������������� ��������� 
 * ������� �������� ����� ������������� ������ ����������: 
 * MMX, SSE2, SSSE3 ��� AVX.
 * ��� ��������� ������ ��������� ������� ��������� � ����� 
 * ������ ��������, �������� �� �� ������ ���������� ������������� 
 * ����� ������� ������� MMX/SSE/SSSE3/AVX,
 * �, ���� ����������� ����, ��������� ������. � ������ ����, ����� ����,
 * ����� ������� ������ �������, ������������ MMX/SSE/SSSE3/AVX, ����� 
 * ���������� ����� callback'� ������� FPU, � ������������������ ��� 
 * ����� �������������� ������ � ������ ��������� �������, ����� 
 * ���� ����� ������ callback ������� ������������ FPU. 
 * ���� ������ �� ������, ����� ����������� ������������� ��� �������.
 *
 * \note �����, ��� �� ������ ������� ������������ ������������� � 
 * ������������ \ref CPC_CONFIG_ ��������� �����������
 * ������������� ���������� ���������� ������� ���������� 
 * ���������� (�������, �� ������ 3.6.7747, ������������ 
 * ������������� ������� ���������� � ��������� \ref CPC_LOCK_FUNCS_ 
 * �� ���������� �� ����� ������������� ���������� ����������).
 *
 * \note ��������� ��������� ���������� �� ��������� �� ������ 
 * ������������ �������� ������������ ���������� � ��.
 *
 * \note ��������� ��������� ���������� �� ��������� �� ������ ���� ��:
 *  <table><tr><th>
 * ���� ��
 * </th><th>
 *      ���������
 * </th></tr><tr><td>
 * Windows 7/2008R2 SP1
 * </td><td>
 *      �� AVX
 * </td></tr><tr><td>
 * Windows ����
 * </td><td>
 *      �� SSSE3
 * </td></tr><tr><td>
 * Linux � ������ ���� 2.6.30
 * </td><td>
 *      �� AVX
 * </td></tr><tr><td>
 * Linux �����
 * </td><td>
 *      �� SSSE3
 * </td></tr><tr><td>
 * FreeBSD � ������ 8.2
 * </td><td>
 *      �� AVX
 * </td></tr><tr><td>
 * FreeBSD �����
 * </td><td>
 *      ������� ��� ��� ������������� FPU/MMX/SSE2/SSSE3/AVX
 * </td></tr><tr><td>
 * Solaris 10/11 amd64
 * </td><td>
 *      �� SSSE3
 * </td></tr><tr><td>
 * Solaris 10/11 ia32
 * </td><td>
 *      ������� ��� ��� ������������� FPU/MMX/SSE2/SSSE3/AVX
 * </td></tr></table>
 *
 * \sa CPC_CONFIG_
 */
typedef struct _CPC_FAST_CODE {
    DWORD UsesFunctions;
		/*!< ������������ ��������, ����� ���� ����� CPC_FAST_CODE_DEFAULT,
		 *   CPC_FAST_CODE_NO, CPC_FAST_CODE_USER.
		 * <table><tr><th>
		 * ��������� ��������:</th><th>�������������:
		 * </th>
		 * </tr>
		 * <tr><td>
		 * CPC_FAST_CODE_DEFAULT</td>
		 *	<td>������������ ��������� ������� �� ���������.
		 * 	</td></tr>
		 * <tr><td>
		 * CPC_FAST_CODE_NO</td>
		 *	<td>������������ ��������� ������� ������������� �������.
		 *	</td></tr>
		 * <tr><td>
		 * CPC_FAST_CODE_USER</td>
		 *	<td>������������ ��������� ������� �������, ���������� 
		 *	���������� UsedMask.
		 *	</td></tr>
		 * </table>
		 */
    CPC_Kernel_Fpu_Begin_Callback * cp_kernel_fpu_begin;
		/*!< ��������� �� ������� ������� FPU.
		 *   ����������� � ������ ����. ��������� �� ������� 
		 *   ������� FPU, ������� ����� �������� �������, 
		 *   ������������ ���������� MMX/SSE/SSSE3/AVX.
		 *   ��������������� ������ ��� UsesFunctions == CPC_FAST_CODE_USER.
		 *   ���� ����� ���� ��� ������������� � CPCSetProvParam(),
		 *   ����������� ���������� ��������.
		 *   ��. \ref CPC_Kernel_Fpu_Begin_Callback
		 *   
		 */
    CPC_Kernel_Fpu_End_Callback *cp_kernel_fpu_end;
		/*!< ��������� �� ������� ������������ FPU.
		 *   ����������� � ������ ����. ��������� �� ������� 
		 *   ������������ FPU. 
		 *   ������������ ������ ��� UsesFunctions == CPC_FAST_CODE_USER.
		 *   ���� ����� ���� ��� ������������� � CPCSetProvParam(),
		 *   ����������� ���������� ��������.
		 *   ��. \ref CPC_Kernel_Fpu_End_Callback
		 */
    DWORD  Kernel_Buf_Size;
		/*!< ������ �� ������������ ������, ������� ����� 
		 *   ������������ � ������� ������� � ������������ FPU 
		 *   ��� ���������� ���������. ������������ 
		 *   ������ ��� UsesFunctions == CPC_FAST_CODE_USER.
		 *   �������� �� ����� ��������� 2048.
		 *   ��. \ref CPC_Kernel_Fpu_Begin_Callback , 
		 *   \ref CPC_Kernel_Fpu_End_Callback
		 */
    DWORD   UsedMask;
		/*!< �����, �������� ��������� ������� �������. �������� 
		 *   ���������� ������ ��������������� ������� �������, 
		 *   ������������ ��������� ����������, ������� ������� 
		 *   �������� � ���������������� (��. ����). 
		 *   � ���������������� ������ � ��� ���������� ����� 
		 *   ��������� ��������� ���� ���� �������, 
		 *   � ������ ���� - ����, ����� ������ ��������� �� ������ P. 
		 */
} CPC_FAST_CODE;

/*! \ingroup ProCSPData
 * \defgroup ProCSPDataFast ������������� ����
 * �������� �������������� ���� �� ����� ������� (� �������������� SSE2).
 *
 * ��� ������������� � ������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS), 
 * � ��������� pbData ������������ �����, ������������ ����� 
 * ����������� �� ���������� ��� �������.
 * ��������, ����� ������� ��������� �� ���������� ���, ���������
 * �� ������ \e dwFlags.
 *
 * ���� ������� ���� CRYPT_FAST_CODE_GET_SETFN, ��� ������
 * \ref CSP_FAST_CODE_GET_SETFN ����� ���������� � 1, ���� ��������� ����� ������������
 * ������� ���, � 0 - �����. ���� ���������� ���� CRYPT_FAST_CODE_ALL_FUNCTIONS,
 * ����� ����������� ��� �������, � �� ������ ����� ����������� ��� �����
 * \ref CSP_FAST_CODE_E_ECB, \ref CSP_FAST_CODE_E_CBC, \ref CSP_FAST_CODE_E_CNT,
 * \ref CSP_FAST_CODE_E_CFB, \ref CSP_FAST_CODE_E_OFB, \ref CSP_FAST_CODE_E_CTR,
 * \ref CSP_FAST_CODE_D_ECB, \ref CSP_FAST_CODE_D_CBC, \ref CSP_FAST_CODE_D_CNT,
 * \ref CSP_FAST_CODE_D_CFB,  \ref CSP_FAST_CODE_D_OFB, \ref CSP_FAST_CODE_D_CTR, \ref CSP_FAST_CODE_MD_ECB,
 * \ref CSP_FAST_CODE_GR3411SP, \ref CSP_FAST_CODE_GR3411H, \ref CSP_FAST_CODE_GR3411HV, \ref CSP_FAST_CODE_HASH,
 * \ref CSP_FAST_CODE_HASH_2012, \ref CSP_FAST_CODE_HASH_2012HV, \ref CSP_FAST_CODE_IMIT, \ref CSP_FAST_CODE_IMIT_2015,
 * \ref CSP_FAST_CODE_MULT, � 1, ���� ��������������� ������� ���������� ������� ���, � 0 - �����.
 * � ������ ������������ ������� ������ �����  CRYPT_FAST_CODE_ALL_FUNCTIONS
 * ������������ CRYPT_FAST_CODE_ALL_USER_FUNCTIONS, � � ������ ���� �� -
 * CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS. �� ������ ���� \ref CSP_FAST_CODE_GET_FN ���������� � 1,
 * ���� ������� ��� �������� �� ���� ��������� ��������, � 0 ���� ���� �� ����
 * �� ��������� ������� �� ���������.
 * ��������� �� ��������� ������ �� ����������.
 *
 * \sa #CPGetProvParam (PP_FAST_CODE_FLAGS)
 * \{
 */

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����������� ������� ������ ������������� ������� �������.
 */
#define CSP_FAST_CODE_GET_FN	(1<<28)


/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� �����������, ����� �� ���������
 *  ��������� ������� ��� �� ������ ������.
 */
#define CSP_FAST_CODE_GET_SETFN	(1<<27)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� ECB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_ECB	(1)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CBC
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CBC	(1<<1)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CNT
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CNT	(1<<2)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CNT
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CNT	(1<<2)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CFB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CFB	(1<<3)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� ECB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_ECB	(1<<4)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CBC
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CBC	(1<<5)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CFB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CFB	(1<<6)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �����
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_MD_ECB	(1<<7)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ���������� ������� �����������.
 *  ���� ��������������� ������ � ������ ���� ��.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_GR3411SP	(1<<8)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� �����������.
 *  ���� ��������������� ������ � ������ ���� ��.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_GR3411H	(1<<9)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� �������� ����.
 *  ���� ��������������� ������ � ������ ���� ��.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_GR3411HV	(1<<10)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ���-��������������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_HASH	(1<<11)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ��������� ������������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_IMIT	(1<<12)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ���������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_MULT	(1<<13)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ��� �����������
 *  � �������� ��������� � UNIX-��������� ��������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_MULT_ATT	(1<<13)

/*!
*  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
*  ������������ ��� ���� ��� ��������, ����� ���
*  ����������� � ������� ���-�������������� �� ���� � 34.11-2012.
*  ����� 1 � ������ �������� ���� ������ �������,
*  � 0 �����.
*/
#define CSP_FAST_CODE_HASH_2012	    (1<<14)

/*!
*  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
*  ������������ ��� ���� ��� ��������, ����� ���
*  ����������� � ������� �������� ���� �� ���� � 34.11-2012.
*  ����� 1 � ������ �������� ���� ������ �������,
*  � 0 �����.
*/
#define CSP_FAST_CODE_HASH_2012HV   (1<<15)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ������������ �� SSSE3 ���. ���������, ���� ��� �� ������������.
 */
#define CSP_FAST_CODE_DISABLE_SSSE3 (1<<16)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ������������ �� AVX ���. ���������, ���� ��� �� ������������.
 */
#define CSP_FAST_CODE_DISABLE_AVX (1<<17)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  �������, ��� ��� ������� FPU ������������ TS-��� (Solaris, Linux).
 */
#define CSP_FAST_CODE_RT_TS (1<<18)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� OFB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_OFB	(1<<19)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� OFB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_OFB	(1<<19)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CTR
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CTR	(1<<20)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ���� ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CTR
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CTR	(1<<20)

/*!
*  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
*  ������������ ��� ���� ��� ��������, ����� ���
*  ����������� � ������� ��������� ������������ �� ���� � 34.13-2015.
*  ����� 1 � ������ �������� ���� ������ �������,
*  � 0 �����.
*/
#define CSP_FAST_CODE_IMIT_2015	(1<<21)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� ������������.
 */
#define CSP_FAST_CODE_ALL_ENCRYPT (CSP_FAST_CODE_E_ECB|CSP_FAST_CODE_E_CBC|CSP_FAST_CODE_E_CNT|CSP_FAST_CODE_E_CFB|CSP_FAST_CODE_E_OFB|CSP_FAST_CODE_E_CTR)


/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� �������������.
 */
#define CSP_FAST_CODE_ALL_DECRYPT (CSP_FAST_CODE_D_ECB|CSP_FAST_CODE_D_CBC|CSP_FAST_CODE_D_CNT|CSP_FAST_CODE_D_CFB|CSP_FAST_CODE_D_OFB|CSP_FAST_CODE_D_CTR)


/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� �����������.
 */
#define CSP_FAST_CODE_ALL_HASH (CSP_FAST_CODE_HASH|CSP_FAST_CODE_GR3411SP|CSP_FAST_CODE_GR3411H|CSP_FAST_CODE_GR3411HV|CSP_FAST_CODE_HASH_2012|CSP_FAST_CODE_HASH_2012HV)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� ���������.
 */
#define CSP_FAST_CODE_ALL_MULT (CSP_FAST_CODE_MULT|CSP_FAST_CODE_MULT_ATT)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� ����������.
 */
#define CSP_FAST_CODE_ALL_CRYPT (CSP_FAST_CODE_ALL_ENCRYPT|CSP_FAST_CODE_ALL_DECRYPT|CSP_FAST_CODE_MD_ECB|CSP_FAST_CODE_IMIT|CSP_FAST_CODE_IMIT_2015)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������������� ������� ����������������.
 */
#define CSP_FAST_CODE_ALL_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_ALL_HASH|CSP_FAST_CODE_ALL_MULT)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������������� �������
 *  ���������������� ������ ���� ��.
 */
#define CSP_FAST_CODE_ALL_KERNEL_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_ALL_HASH)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������������� �������
 *  ���������������� ����������������� ������.
 */
#define CSP_FAST_CODE_ALL_USER_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_HASH|CSP_FAST_CODE_HASH_2012|CSP_FAST_CODE_HASH_2012HV|CSP_FAST_CODE_ALL_MULT)


/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), ����������� ������� ����
 *  ��� ���� ������� ���������� � ������ ���� ��.
 */
#define CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS	1

/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), ����������� ������� ����
 * ��� ���� ������� ���������� � ������ ������������.
 */
#define CRYPT_FAST_CODE_ALL_USER_FUNCTIONS	2

/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), ����������� ������� ����
 * ��� ���� ������� ����������.
 */
#define CRYPT_FAST_CODE_ALL_FUNCTIONS		(CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS|CRYPT_FAST_CODE_ALL_USER_FUNCTIONS)

/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), �����������
 * ��������� ����������� ����������.
 */
#define CRYPT_FAST_CODE_GET_SETFN		8


/*!
 *  \brief ��������� �������� ��������� op_type ������� \ref CPC_Kernel_Fpu_Begin_Callback.
 *  ��������, ��� ������ ������� FPU ��������� � ������� ����������������� ����������.
 *  ����� ������ �������� �������������� ������ ������� ������������������� ����������, 
 *  ������������ ���������� MMX.
 */
#define CSP_OPERATION_CIPHER1	(CSP_FAST_CODE_E_CFB | CSP_FAST_CODE_E_CBC)

/*!
 *  \brief ��������� �������� ��������� op_type ������� \ref CPC_Kernel_Fpu_Begin_Callback.
 *  ��������, ��� ������ ������� FPU ��������� � ������� ��������������� ����������.
 *  ����� ������ �������� �������������� ������ ������� ��������������� ����������, 
 *  ������������ ���������� MMX.
 */
#define CSP_OPERATION_CIPHER2	(CSP_FAST_CODE_E_ECB | CSP_FAST_CODE_E_CNT | CSP_FAST_CODE_E_OFB | CSP_FAST_CODE_E_CTR | CSP_FAST_CODE_D_ECB | CSP_FAST_CODE_D_CBC | CSP_FAST_CODE_D_CNT | CSP_FAST_CODE_D_OFB | CSP_FAST_CODE_D_CTR | CSP_FAST_CODE_D_CFB | CSP_FAST_CODE_MD_ECB)


/*!
 *  \brief ��������� �������� ��������� op_type ������� \ref CPC_Kernel_Fpu_Begin_Callback.
 *  ��������, ��� ������ ������� FPU ��������� � ������� ��������� ������������.
 *  ����� ������ �������� �������������� ������ ������� ��������� ������������, 
 *  ������������ ���������� MMX.
 */
#define CSP_OPERATION_IMIT	(CSP_FAST_CODE_IMIT | CSP_FAST_CODE_IMIT_2015)

/*!
 *  \brief ��������� �������� ��������� op_type ������� \ref CPC_Kernel_Fpu_Begin_Callback.
 *  ��������, ��� ������ ������� FPU ��������� � ������� ���������� ����. � ������ ������
 *  ���������� ��������� �� ������ �������� ST0 - ST7, �� � XMM0 - XMM7.
 *  ����� ������ �������� �������������� ������ ������� ������������, 
 *  ������������ ���������� MMX � SSE2.
 */
#define CSP_OPERATION_HASH	(CSP_FAST_CODE_ALL_HASH)

/*!
 *  \brief ������� ����� ��� ���������/���������� ���� MMX � ������� ���������.
 *  ������ �������� �������������� ������ ������� ��������� �� ������ P, 
 *  ������������ ���������� MMX � SSE2. ����������� ������ � ���������������� ������.
 */
#define CSP_OPERATION_MULT	(CSP_FAST_CODE_ALL_MULT)

/*!
 *  \brief ������� ����� ��� ���������/���������� ���� MMX �� ���� ��������.
 *  ������ �������� ���������� ����� ���� ��������������� ������� �������,
 *  ������������ MMX � SSE2.
 */
#define CSP_OPERATION_ALL	(CSP_OPERATION_MULT | CSP_OPERATION_HASH | CSP_OPERATION_IMIT | CSP_OPERATION_CIPHER2 | CSP_OPERATION_CIPHER1)

/*!
 *  \brief ������� �����, ���������� �������������� ��������� �������. �����������, ���� 
 *  ����� ���������� ����� ������� �� ��������� ��� ������� ����������.
 */
#define CSP_OPERATION_UNDEF	(0xFFFFFFFF)


/*! \} */

typedef struct _CRYPT_LCD_QUERY_PARAM {
  const char *message;
} CRYPT_LCD_QUERY_PARAM;


//Deprecated Defines
#if !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 363) 
#undef CP_GR3410_94_PROV
#undef CP_KC1_GR3410_94_PROV
#undef CP_KC2_GR3410_94_PROV

#undef PROV_GOST_DH
#undef PROV_GOST_94_DH

#undef CALG_GR3410
#undef CALG_DH_EX_SF
#undef CALG_DH_EX_EPHEM
#undef CALG_DH_EX

#endif

#if !defined(CPCSP_USE_NON_STANDART_OIDS) && !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 36) 

#undef szOID_CP_GOST_R3410
#undef szOID_CP_DH_EX
#undef szOID_CP_GOST_R3410_94_ESDH

/* OIDs for HASH */
#undef szOID_GostR3411_94_TestParamSet
#undef szOID_GostR3411_94_CryptoPro_B_ParamSet
#undef szOID_GostR3411_94_CryptoPro_C_ParamSet
#undef szOID_GostR3411_94_CryptoPro_D_ParamSet

/* OIDs for Crypt */
#undef szOID_Gost28147_89_TestParamSet
#undef szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet
#undef szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet
#undef szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet

/* OID for Signature 1024*/
#undef szOID_GostR3410_94_CryptoPro_A_ParamSet
#undef szOID_GostR3410_94_CryptoPro_B_ParamSet
#undef szOID_GostR3410_94_CryptoPro_C_ParamSet
#undef szOID_GostR3410_94_CryptoPro_D_ParamSet

/* OID for Signature 512*/
#undef szOID_GostR3410_94_TestParamSet

/* OID for DH 1024*/
#undef szOID_GostR3410_94_CryptoPro_XchA_ParamSet
#undef szOID_GostR3410_94_CryptoPro_XchB_ParamSet
#undef szOID_GostR3410_94_CryptoPro_XchC_ParamSet

/* OID for EC signature */
#undef szOID_GostR3410_2001_TestParamSet

#endif



/*! \defgroup ProCSPEx �������������� ��������� � �����������
 *\ingroup ProCSP
 * ������ ������ �������� ����������� ��������������� � ����������,
 * ������������ � ���������������� "��������� CSP".
 *
 * \{
 */

/*! \page DP1 �������������� ���������� ����������������
 *
 * <table>
 * <tr><th>�������������</th><th>�������� ��������������</th></tr>
 * <tr><td>CALG_GR3411</td><td>������������� ��������� ����������� �� ���� � 34.11-94.</td></tr>
 * <tr><td>CALG_GR3411_2012_256</td><td>������������� ��������� ����������� � ������������ � ���� � 34.11-2012, ����� ������ 256 ���.</td></tr>
 * <tr><td>CALG_GR3411_2012_512</td><td>������������� ��������� ����������� � ������������ � ���� � 34.11-2012, ����� ������ 512 ���.</td></tr>
 * <tr><td>CALG_G28147_MAC</td><td>������������� ��������� ����������� �� ���� 28147-89.</td></tr>
 * <tr><td>CALG_G28147_IMIT </td><td>�� �� �����, ��� � CALG_G28147_MAC (���������� ������).</td></tr>
 * <tr><td> CALG_GR3410 </td><td> ������������� ��������� ��� �� ���� � 34.10-94. </td></tr>
 * <tr><td> CALG_GR3410EL </td><td> ������������� ��������� ��� �� ���� � 34.10-2001.</td></tr>
 * <tr><td> CALG_GR3410_12_256 </td><td> ������������� ��������� ��� �� ���� � 34.10-2012 (256 ���).</td></tr>
 * <tr><td> CALG_GR3410_12_512 </td><td> ������������� ��������� ��� �� ���� � 34.10-2012 (512 ���).</td></tr>
 * <tr><td> CALG_GR3411_HMAC </td><td> ������������� ��������� ��������� ����������� �� ���� ��������� ���� � 34.11-94 � ����������� ����� CALG_G28147.</td></tr>
 * <tr><td> CALG_GR3411_2012_256_HMAC </td><td> ������������� ��������� ��������� ����������� �� ���� ��������� ���� � 34.11-2012 � ����������� ����� CALG_G28147, ����� ������ 256 ���.</td></tr>
 * <tr><td> CALG_GR3411_2012_512_HMAC </td><td> ������������� ��������� ��������� ����������� �� ���� ��������� ���� � 34.11-2012 � ����������� ����� CALG_G28147, ����� ������ 512 ���.</td></tr>
 * <tr><td>CALG_G28147</td><td>������������� ��������� ���������� �� ���� 28147-89. </td></tr>
 * <tr><td>CALG_SYMMETRIC_512</td><td>������������� ��������� ��������� ����� ������ ����� �� �����-�������� � ������ ������ 512 ���.</td></tr>
 * <tr><td>CALG_DH_EX_SF </td><td>������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. </td></tr>
 * <tr><td>CALG_DH_EX_EPHEM </td><td>������������� CALG_DH_EX ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ��������� ����. �������� ���� ���������� �� ���� � 34.10 94.</td></tr>
 * <tr><td>CALG_DH_EX </td><td>������������� CALG_DH_EX ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. �������� ���� ���������� �� ���� � 34.10 94. </td></tr>
 * <tr><td>CALG_DH_EL_SF </td><td>������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. �������� ���� ���������� �� ���� � 34.10 2001.</td></tr>
 * <tr><td>CALG_DH_EL_EPHEM</td><td> ������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ��������� ����. �������� ���� ���������� �� ���� � 34.10 2001.</td></tr>
 * <tr><td>CALG_DH_GR3410_12_256_SF</td><td>������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. �������� ���� ���������� �� ���� � 34.10 2012 (256 ���).</td></tr>
 * <tr><td>CALG_DH_GR3410_12_256_EPHEM</td><td> ������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ��������� ����. �������� ���� ���������� �� ���� � 34.10 2012 (256 ���).</td></tr>
 * <tr><td>CALG_DH_GR3410_12_512_SF</td><td>������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. �������� ���� ���������� �� ���� � 34.10 2012 (512 ���).</td></tr>
 * <tr><td>CALG_DH_GR3410_12_512_EPHEM</td><td> ������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ��������� ����. �������� ���� ���������� �� ���� � 34.10 2012 (512 ���).</td></tr>
 * <tr><td>CALG_PRO_AGREEDKEY_DH</td><td>������������� ��������� ��������� ����� ������ ����� �� �����-��������. </td></tr>
 * <tr><td>CALG_PRO_EXPORT </td><td> ������������� ��������� ����������� �������� �����.</td></tr>
 * <tr><td>CALG_PRO12_EXPORT </td><td> ������������� ��������� ����������� �������� ����� �� ������������� ��26 (���������� ��� ������������� � ������� ���� � 34.10-2012).</td></tr>
 * <tr><td>CALG_SIMPLE_EXPORT </td><td>������������� ��������� �������� �������� �����. </td></tr>
 * <tr><td> CALG_TLS1PRF</td><td>������������� ��������� "������������ �������" (PRF) ��������� TLS 1.0 �� ������ ��������� ����������� � ������������ � ���� � 34.11-94.</td></tr>
 * <tr><td> �ALG_TLS1PRF_2012_256</td><td>������������� ��������� "������������ �������" (PRF) ��������� TLS 1.0 �� ������ ��������� ����������� � ������������ � ���� � 34.11-2012.</td></tr>
 * <tr><td> CALG_TLS1_MASTER_HASH</td><td>������������� ��������� ��������� ������� MASTER_HASH ��������� TLS 1.0 �� ������ ��������� ����������� � ������������ � ���� � 34.11-94.</td></tr>
 * <tr><td> CALG_TLS1_MASTER_HASH_2012_256</td><td>������������� ��������� ��������� ������� MASTER_HASH ��������� TLS 1.0 �� ������ ��������� ����������� � ������������ � ���� � 34.11-2012.</td></tr>
 * <tr><td> CALG_TLS1_MAC_KEY</td><td>������������� ��������� ��������� ����� ����������� ��������� TLS 1.0. </td></tr>
 * <tr><td> CALG_TLS1_ENC_KEY </td><td> ������������� ��������� ��������� ����� ���������� ��������� TLS 1.0.</td></tr>
 * <tr><td> CALG_PBKDF2_94_256</td><td>������������� ��������� ��������� ����� �� ������ �� ������ ��������� ����������� � ���������� � ���� � 34.11-94, ����� ������ 256 ���.</td></tr>
 * <tr><td> CALG_PBKDF2_2012_256</td><td>������������� ��������� ��������� ����� �� ������ �� ������ ��������� ����������� � ���������� � ���� � 34.11-2012, ����� ������ 256 ���.</td></tr>
 * <tr><td> CALG_PBKDF2_2012_512</td><td>������������� ��������� ��������� ����� �� ������ �� ������ ��������� ����������� � ���������� � ���� � 34.11-2012, ����� ������ 512 ���.</td></tr>
 * <tr><td> CALG_PRO_DIVERS</td><td>������������� ��������� ��������� �������������� ����� �� RFC 4357.</td></tr>
 * <tr><td> CALG_PRO12_DIVERS</td><td>������������� ��������� ��������� �������������� ����� �� ������������� ��26.</td></tr>
 * <tr><td> CALG_RIC_DIVERS</td><td>������������� ��������� ��� �������������� �����. </td></tr>
 *</table>
 */

/*! \page DP2 ������ ����������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>CRYPT_PROMIX_MODE </td><td>������� ������� ����������/������������� �� ���� 28147-89 � ��������������� ����� ����� ������ 1 �� �������������� ���������� </td></tr>
 * <tr><td>CRYPT_SIMPLEMIX_MODE </td><td>������� ������� ����������/������������� �� ���� 28147-89 ��� �������������� ����� � �������� ��������� ����������</td></tr>
 *</table>
*/

/*! \page DP3 ��������� ����������������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>PP_ENUMOIDS_EX</td><td>�������� �������� ��������������� ��������, ������������ � ����������������</td></tr>
 * <tr><td>PP_HASHOID</td><td>�������� �/��� ������������� �������� � ���������� OID ���� ������ ������� ����������� ���� � 34.11-94 ��� ������������ ������������������ ���������</td></tr>
 * <tr><td>PP_CIPHEROID</td><td>�������� �/��� ������������� �������� � ���������� OID ���� ������ ��������� ���������� ���� 28147-89 ��� ������������ ������������������ ��������� </td></tr>
 * <tr><td>PP_SIGNATUREOID</td><td>�������� �/��� ������������� �������� � ���������� OID ���������� �������� ������� - � ����������� �� ���� ���������� </td></tr>
 * <tr><td>PP_DHOID</td><td>�������� �/��� ������������� �������� � ���������� OID ���������� ��������� �����-�������� � ����������� �� ���� ���������� </td></tr>
 * <tr><td>PP_CHECKPUBLIC </td><td>���� �������� ��������� �����. ���� ���� ����������, �������������� �������� �������������� ������� ��������� ����� </td></tr>
 * <tr><td>PP_RANDOM</td><td>�������� �/��� ������������� ���� ���� SIMPLEBLOB ��� ������������� ��� � �������� ����������</td></tr>
 * <tr><td>PP_DRVCONTAINER </td><td>�������� ��������� (handle) ���������� � ��������</td></tr>
 * <tr><td>PP_MUTEX_ARG</td><td>�������������� ������������� ������� ���������������� � ���������� ����������</td></tr>
 * <tr><td>PP_ENUM_HASHOID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � �������� ����������� </td></tr>
 * <tr><td>PP_ENUM_CIPHEROID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � �������� ����������  </td></tr>
 * <tr><td>PP_ENUM_SIGNATUREOID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � �������� �������� �������, - PP_ENUM_SIGNATUREOID_256_2001, PP_ENUM_SIGNATUREOID_256_2012 ��� PP_ENUM_SIGNATUREOID_512 � ����������� �� ���� ���������� </td></tr>
 * <tr><td>PP_ENUM_DHOID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � ���������� �����-��������, � ����������� �� ���� ���������� </td></tr>
 *</table>
*/

/*! \page DP4 ��������� �������������� �������� ������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>DIVERSKEYBLOB</td><td>��� ��������� ����� ��� �������������� ������ � �������
    ������� CPImportKey � ������ CALG_PRO_EXPORT</td></tr>
 *</table>
*/

/*! \page DP5 �������������� ��������� ������� �����������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>HP_HASHSTARTVECT</td><td>��������� ������ ������� �����������, ��������������� �����������</td></tr>
 * <tr><td>HP_OID</td><td>������ ���� ������ ������� �����������</td></tr>
 *</table>
*/

/*! \page DP6 �������������� ��������� ������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>KP_IV </td><td>��������� ������ ������������� ��������� ���������� ���� 28147-89</td></tr>
 * <tr><td>KP_MIXMODE</td><td>���������� ������������� �������������� ����� ����� ��������� 1�� ���������� � ������� ����������/������������� � ���������� ������������ ��������� ���� 28147-89 </td></tr>
 * <tr><td>KP_OID</td><td>������ ���� ������ ������� �����������</td></tr>
 * <tr><td>KP_HASHOID</td><td>������������� ���� ������ ������� ����������� ���� � 34.11-94</td></tr>
 * <tr><td>KP_CIPHEROID</td><td>������������� ���� ������ ��������� ���������� ���� 28147-89</td></tr>
 * <tr><td>KP_SIGNATUREOID</td><td>������������� ���������� �������� �������</td></tr>
 * <tr><td>KP_DHOID</td><td>������������� ���������� ��������� �����-��������</td></tr>
 *</table>
*/

/*! \page DP8 ��������� �������������� ����������������� ���������� ����������
 * <table>
 * <tr><th>��������</th><th>������</th><th>�������� ���������</th></tr>
 * <tr><td>szOID_CP_GOST_28147</td><td>"1.2.643.2.2.21"</td><td>�������� ���������� ���� 28147-89</td></tr>
 * <tr><td>szOID_CP_GOST_R3411</td><td>"1.2.643.2.2.9"</td><td>������� ����������� ���� � 34.11-94</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_256</td><td>"1.2.643.7.1.1.2.2"</td><td>������� ����������� ���� � 34.11-2012, ����� ������ 256 ���</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_512</td><td>"1.2.643.7.1.1.2.3"</td><td>������� ����������� ���� � 34.11-2012, ����� ������ 512 ���</td></tr>
 * <tr><td>szOID_CP_GOST_R3410</td><td>"1.2.643.2.2.20"</td><td>�������� ���� � 34.10-94, ������������ ��� ��������/������� ������</td></tr>
 * <tr><td>szOID_CP_GOST_R3410EL</td><td>"1.2.643.2.2.19"</td><td>�������� ���� � 34.10-2001, ������������ ��� ��������/������� ������</td></tr>
 * <tr><td>szOID_CP_GOST_R3410_12_256</td><td>"1.2.643.7.1.1.1.1"</td><td>�������� ���� � 34.10-2012 ��� ������ ����� 256 ���, ������������ ��� ��������/������� ������</td></tr>
 * <tr><td>szOID_CP_GOST_R3410_12_512</td><td>"1.2.643.7.1.1.1.2"</td><td>�������� ���� � 34.10-2012 ��� ������ ����� 512 ���, ������������ ��� ��������/������� ������</td></tr>
 * <tr><td>szOID_CP_DH_EX</td><td>"1.2.643.2.2.99"</td><td>�������� �����-�������� �� ���� ������������� �������</td></tr>
 * <tr><td>szOID_CP_DH_EL</td><td>"1.2.643.2.2.98"</td><td>�������� �����-�������� �� ���� ������������� ������</td></tr>
 * <tr><td>szOID_CP_DH_12_256</td><td>"1.2.643.7.1.1.6.1"</td><td>�������� �����-�������� �� ���� ������������� ������ ��� ������ ����� 256 ���</td></tr>
 * <tr><td>szOID_CP_DH_12_512</td><td>"1.2.643.7.1.1.6.2"</td><td>�������� �����-�������� �� ���� ������������� ������ ��� ������ ����� 512 ���</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_R3410</td><td>"1.2.643.2.2.4"</td><td>�������� �������� ������� ���� � 34.10-94</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_R3410EL</td><td>"1.2.643.2.2.3"</td><td>�������� �������� ������� ���� � 34.10-2001</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_256_R3410</td><td>"1.2.643.7.1.1.3.2"</td><td>�������� �������� ������� ���� � 34.10-2012 ��� ������ ����� 256 ���</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_12_512_R3410</td><td>"1.2.643.7.1.1.3.3"</td><td>�������� �������� ������� ���� � 34.10-2012 ��� ������ ����� 512 ���</td></tr>
 * <tr><td>szOID_KP_TLS_PROXY</td><td>"1.2.643.2.2.34.1"</td><td>����� TLS-�������</td></tr>
 * <tr><td>szOID_KP_RA_CLIENT_AUTH</td><td>"1.2.643.2.2.34.2"</td><td>������������� ������������ �� ������ �����������</td></tr>
 * <tr><td>szOID_KP_WEB_CONTENT_SIGNING</td><td>"1.2.643.2.2.34.3"</td><td>������� ����������� ������� ��������</td></tr>
 *</table>
*/

/*! \ingroup ProCSPEx
 * \page CP_PARAM_OIDS �������������� ����������������� ���������� ����������
 * <table>
 * <tr><th>��������</th><th>������</th><th>�������� ���������</th></tr>
 * <tr><td>szOID_GostR3411_94_TestParamSet</td><td>"1.2.643.2.2.30.0"</td><td>�������� ���� ������</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoProParamSet</td><td>"1.2.643.2.2.30.1"</td><td>���� ������ ������� ����������� �� ���������, ������� "�����-�"</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.30.2"</td><td>���� ������ ������� �����������, ������� 1</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.30.3"</td><td>���� ������ ������� �����������, ������� 2</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.30.4"</td><td>���� ������ ������� �����������, ������� 3</td></tr>
 * <tr><td>szOID_Gost28147_89_TestParamSet</td><td>"1.2.643.2.2.31.0"</td><td>�������� ���� ������ ��������� ����������</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.31.1"</td><td>���� ������ ��������� ���������� �� ���������, ������� "�����-�"</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.31.2"</td><td>���� ������ ��������� ����������, ������� 1</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.31.3"</td><td>���� ������ ��������� ����������, ������� 2</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.31.4"</td><td>���� ������ ��������� ����������, ������� 3</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet</td><td>"1.2.643.2.2.31.5" </td><td>���� ������, ������� ����� ���������</tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet</td><td>"1.2.643.2.2.31.6" </td><td>���� ������, ������������ ��� ���������� � ������������</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_A_ParamSet</td><td>"1.2.643.2.2.31.12" </td><td>���� ������ ��������� ����������, ������� ��26 2</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_B_ParamSet</td><td>"1.2.643.2.2.31.13" </td><td>���� ������ ��������� ����������, ������� ��26 1</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_C_ParamSet</td><td>"1.2.643.2.2.31.14" </td><td>���� ������ ��������� ����������, ������� ��26 3</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_D_ParamSet</td><td>"1.2.643.2.2.31.15" </td><td>���� ������ ��������� ����������, ������� ��26 4</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_E_ParamSet</td><td>"1.2.643.2.2.31.16" </td><td>���� ������ ��������� ����������, ������� ��26 5</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_F_ParamSet</td><td>"1.2.643.2.2.31.17" </td><td>���� ������ ��������� ����������, ������� ��26 6</td></tr>
 * <tr><td>szOID_Gost28147_89_TC26_Z_ParamSet</td><td>"1.2.643.7.1.2.5.1.1" </td><td>���� ������ ��������� ����������, ������� ��26 Z</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.32.2"</td><td>��������� P, Q, A �������� ������� ���� � 34.10-94, ������� "�����-�". ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.32.3"</td><td>��������� P, Q, A �������� ������� ���� � 34.10-94, ������� 1. ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.32.4"</td><td>��������� P, Q, A �������� ������� ���� � 34.10-94, ������� 2. ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.32.5"</td><td>��������� P, Q, A �������� ������� ���� � 34.10-94, ������� 3. ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_XchA_ParamSet</td><td>"1.2.643.2.2.33.1" </td><td>��������� P, Q, A ��������� �����-�������� �� ���� ���������������� �������, ������� 1</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_XchB_ParamSet</td><td>"1.2.643.2.2.33.2" </td><td>��������� P, Q, A ��������� �����-�������� �� ���� ���������������� �������, ������� 2</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_XchC_ParamSet</td><td>"1.2.643.2.2.33.3" </td><td>��������� P, Q, A ��������� �����-�������� �� ���� ���������������� �������, ������� 3</td></tr>
 * <tr><td>szOID_GostR3410_2001_TestParamSet</td><td>"1.2.643.2.2.35.0"</td><td>�������� ��������� a, b, p, q, (x,y) ��������� ���� � 34.10-2001 </td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.35.1"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� ���������������� </td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.35.2"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� ����� ���������</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.35.3"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� 1</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_XchA_ParamSet</td><td>"1.2.643.2.2.36.0"</td><td> ��������� a, b, p, q, (x,y) ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� ����������������. ������������ �� �� ���������, ��� � � ��������������� szOID_GostR3410_2001_CryptoPro_A_ParamSet</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_XchB_ParamSet</td><td>"1.2.643.2.2.36.1"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� 1</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_256_paramSetA</td><td>"1.2.643.7.1.2.1.1.1"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2012 256 ���, ����� A</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_512_paramSetA</td><td>"1.2.643.7.1.2.1.2.1"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2012 512 ��� �� ���������</td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_512_paramSetB</td><td>"1.2.643.7.1.2.1.2.2"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2012 512 ���, ����� B </td></tr>
 * <tr><td>szOID_tc26_gost_3410_12_512_paramSetC</td><td>"1.2.643.7.1.2.1.2.3"</td><td>��������� a, b, p, q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2012 512 ���, ����� C </td></tr>
 *</table>
 *
*/

/*! \} */

/*! 
 * \ingroup ProCSPData
 *
 * \brief ���� � ��������������� ���������������� � �����������.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CONTAINER_EXTENSION {
    BOOL bCritical; /*!< ���� ������������ ����������. */
    DWORD cbExtension; /*!< ����� ������ � pbExtension. */
    BYTE pbExtension[1]; /*!< ������. */
    char sOid[1]; /*!< ������ � OID-�� ���������� (������������� ���������). */
} CONTAINER_EXTENSION;

//������ ��� ����������� � wincrypt.h
//Use NO_REDIFINE_CERT_FIND_STR to disable redefine
#if defined ( CERT_FIND_SUBJECT_STR ) && !defined ( NO_REDIFINE_CERT_FIND_STR )
#   undef CERT_FIND_SUBJECT_STR
#   undef CERT_FIND_ISSUER_STR
#   ifdef _UNICODE
#	define CERT_FIND_SUBJECT_STR	CERT_FIND_SUBJECT_STR_W
#	define CERT_FIND_ISSUER_STR	CERT_FIND_ISSUER_STR_W
#   else
#	define CERT_FIND_SUBJECT_STR	CERT_FIND_SUBJECT_STR_A
#	define CERT_FIND_ISSUER_STR	CERT_FIND_ISSUER_STR_A
#   endif // !UNICODE
#endif /*defined ( CERT_FIND_SUBJECT_STR ) && !defined ( NO_REDIFINE_CERT_FIND_STR )*/

#if !defined(_DDK_DRIVER_)

typedef struct _CPESS_CERT_ID {
    CRYPT_HASH_BLOB CertHash;
    CERT_ISSUER_SERIAL_NUMBER IssuerSerial;
} CPESS_CERT_ID, *PCPESS_CERT_ID;

typedef struct _CPESS_CERT_IDV2 {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB CertHash;
    CERT_ISSUER_SERIAL_NUMBER IssuerSerial;
} CPESS_CERT_IDV2, *PCPESS_CERT_IDV2,
  CPOTHER_CERT_ID, *PCPOTHER_CERT_ID;

typedef struct _CPCMSG_SIGNING_CERTIFICATE {
    DWORD cCert;
    CPESS_CERT_ID* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_SIGNING_CERTIFICATE, *PCPCMSG_SIGNING_CERTIFICATE;

typedef struct _CPCMSG_SIGNING_CERTIFICATEV2 {
    DWORD cCert;
    CPESS_CERT_IDV2* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_SIGNING_CERTIFICATEV2, *PCPCMSG_SIGNING_CERTIFICATEV2;

typedef struct _CPCMSG_OTHER_SIGNING_CERTIFICATE {
    DWORD cCert;
    CPOTHER_CERT_ID* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_OTHER_SIGNING_CERTIFICATE, *PCPCMSG_OTHER_SIGNING_CERTIFICATE; 

typedef struct _CPCERT_PRIVATEKEY_USAGE_PERIOD {
    FILETIME *pNotBefore;
    FILETIME *pNotAfter;
} CPCERT_PRIVATEKEY_USAGE_PERIOD, *PCPCERT_PRIVATEKEY_USAGE_PERIOD;

typedef struct _GOST_PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE {
    BOOL useCertificate;
    BOOL useContainer;
} GOST_PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE, *PGOST_PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE,
  PRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE, *PPRIVATE_KEY_TIME_VALIDITY_CONTROL_MODE;
/*! \endcond */

#define CPPRIVATEKEY_USAGE_PERIOD_CERT_CHAIN_POLICY_SKIP_END_CERT_FLAG	    (0x00010000)
#define CPTIMESTAMP_SIGNING_CERT_CHAIN_POLICY_IGNORE_NOT_CRITICAL_EKU_FLAG  (0x00020000)
#define CPTIMESTAMP_SIGNING_CERT_CHAIN_POLICY_IGNORE_NOT_ONE_EKU_FLAG	    (0x00040000)

typedef struct _CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize; 
    FILETIME* pPrivateKeyUsedTime; 
} CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA,
CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA,
CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA;

#define CPCERT_TRUST_PRIVATE_KEY_IS_NOT_TIME_VALID	    (0x00000001)
#define CPCERT_TRUST_PRIVATE_KEY_IS_NOT_TIME_VALID_FOR_CRL  (0x00000002)
#define CPCERT_TRUST_IS_NOT_CRITICAL_EKU		    (0x00000004)
#define CPCERT_TRUST_IS_NOT_ONE_EKU			    (0x00000008)
#define CPCERT_TRUST_IS_NOT_VALID_FOR_USAGE		    (CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
							 // (0x00000010)
#define CPCERT_TRUST_IS_NOT_VALID_BY_KEYUSAGE		    (0x00000020)
#define CPCERT_TRUST_IS_NOT_VALID_FOR_OCSP_SIGNING	    (0x00000040)

typedef struct _CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize; 
    DWORD dwError; 
    LONG lChainIndex; 
    LONG lElementIndex; 
} CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS,
CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS,
CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    BOOL fNoCheck;
    BOOL* rgCertIdStatus;
} CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS;

#ifndef OCSP_REQUEST_V1

typedef struct _OCSP_CERT_ID {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;  // Normally SHA1
    CRYPT_HASH_BLOB             IssuerNameHash; // Hash of encoded name
    CRYPT_HASH_BLOB             IssuerKeyHash;  // Hash of PublicKey bits
    CRYPT_INTEGER_BLOB          SerialNumber;
} OCSP_CERT_ID, *POCSP_CERT_ID;
#define OCSP_REQUEST_V1     0
#endif

typedef BOOL CALLBACK IsOCSPAuthorized_Callback(
    /* [in] */ PCCERT_CONTEXT pOCSPCertContext);

typedef struct _CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    FILETIME* pPrivateKeyUsedTime;
    DWORD cCertId;
    POCSP_CERT_ID rgCertId;
    IsOCSPAuthorized_Callback* pfnIsOCSPAuthorized;
} CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA;

/*! \cond ca  */

/*!
 *  \brief ��������� ���������� ����������� IssuerSignTool
 *  (�������� ����������� ������� � �� �������� �����������)
 *
 * \req_wincryptex
 */
typedef struct _CPCERT_ISSUER_SIGN_TOOL {
    LPWSTR pwszSignTool; /*!< ������������ �������� ����������� ������� ��������. */
    LPWSTR pwszCATool; /*!< ������������ �������� �� ��������. */
    LPWSTR pwszSignToolCert; /*!< ��������� ���������� �� �������� ����������� ������� ��������. */
    LPWSTR pwszCAToolCert; /*!< ��������� ���������� �� �������� �� ��������. */
} CPCERT_ISSUER_SIGN_TOOL, *PCPCERT_ISSUER_SIGN_TOOL;

/*! \endcond */
/*! \cond csp  */

#endif /*!defined(_DDK_DRIVER_)*/

#ifdef __cplusplus
}
#endif // __cplusplus

/*****************************************************
		    CRYPT_PACKET 
******************************************************/
/*! \ingroup ProCSPData
 * \defgroup CryptPacket  ���������� � ����������� ������
 *
 * ����� - ��������� �������� ������, ���������� �� ������� ���������� 
 * CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt().
 * ����� ������� �� �����:
 * <table><tr><th>
 * ���� 
 * </th><th>
 *      ��������
 * </th></tr><tr><td>
 * ������������� ������ (DIVERSBLOB)
 * </td><td>
 *      ������������ ����, ���������� ���� �������������� ����� ���������� � ����������� �� ��������� CALG_PRO_DIVERS.
 *      ������� ��������� ���� - ������������� ����  CP_CHP_STARTMIX.
 * </td></tr><tr><td>
 * ��������� ������ (HEADER)
 * </td><td>
 *      ������������ ���� ����� �� ����� 255 ����. �� ���������, ���������� ���-�������� hHash.
 * </td></tr><tr><td>
 * ������ ������������� (IV)
 * </td><td>
 *      ������������ ����, ���������� ������ ������������� ���������� ������. �� ���������, ���������� �����������.
 * </td></tr><tr><td>
 * ���� ������ (PAYLOAD)
 * </td><td>
 *      ������������ ����, ��������� � ����������.
 * </td></tr><tr><td>
 * ������� (TRAILER)
 * </td><td>
 *      ������������ ���� ����� �� ����� 254 ����. �� ���������, ���������� ���-�������� hHash.
 * </td></tr><tr><td>
 * �������� ������� ����������� ������ (HASH)
 * </td><td>
 *      ������������ ����, ����� ���� �����������. 
 * </td></tr>
 * </table> 
 *
 * ��� ���������� ������� �������������� ������ ����������: CRYPT_MODE_CNT, CRYPT_MODE_CFB, CRYPT_MODE_CBCSTRICT.
 * �� ���� ������� ���������� ����� ���� ������������ �����: CRYPT_PROMIX_MODE, CRYPT_SIMPLEMIX_MODE.
 *
 * � �������� ������ ���������� ����� ������� ������� ����������.
 *
 * � ������ CBC ����� ����� ��������� ������ ������ ���� ������ 8, ����� ������ ���� ������� 8 ����� 
 * ������� ���������� �������� IOVEC, � ��������� ������ ������������ ������ NTE_BAD_DATA. 
 * ������ �������������� � ����������� ������� �����, ������� � ������ CBC ������������.
 *
 * ����� CP_CHP_IV_RANDOM, CP_CHP_IV_USER, CP_CHP_HASH_PACKET ������������� ��� ��������� 
 * ������� � ������� � ��������� ���������� ������� ���������� �������, � ��������� ������� �������.
 *
 * ����� CP_CHP_IV_CHAIN, CP_CHP_HASH_CHAIN, CP_CHP_HASH_NONE  ������������� ��� ��������� ������� � �������,
 * ������������� �������� ���� ������� � ���������� ������������������.
 *
 * � ��������� ������� ��������� ������� ������������� ������� ��������� �������:
 * <table><tr><th>
 * �������� ������
 * </th><th>
 *      ������� � ����������� ������
 * </th></tr><tr><td>
 * CRYPT_SIMPLEMIX_MODE ��������� � CP_CHP_IV_RANDOM, 
 * CRYPT_SIMPLEMIX_MODE ��������� � CP_CHP_IV_USER
 * </td><td>
 *	��������� ������� ����� ����������� � ������������� ������ Final=FALSE.
 *	����� ������, �������������� �� ����� �����, ��������� 4�. 
 * </td></tr><tr><td>
 * CRYPT_PROMIX_MODE ��������� � CP_CHP_IV_RANDOM, 
 * CRYPT_PROMIX_MODE ��������� � CP_CHP_IV_USER
 * </td><td>
 *	��������� ������� ������ ����������� � ������������� ������ Final=TRUE.
 *	����� ������, �������������� �� ����� �����,  ��������� 4� ���� ������ ������� < 4096.
 * </td></tr><tr><td>
 * CRYPT_SIMPLEMIX_MODE ��������� � CP_CHP_IV_CHAIN
 * </td><td>
 *	��������� ������ � ������ Final=TRUE �������� ���������� ��������� ������� �������.
 * 	��������� ������ � ������ Final=FALSE �������� ����������� ��������� ������� �������.
 *	�� ����� ����� ��������������� ����� ���� ���������� ��������� ������� �������.
 *	����� ������, �������������� �� ����� �����, ��������� 4�.
 * </td></tr><tr><td>
 * CRYPT_PROMIX_MODE ��������� � CP_CHP_IV_CHAIN
 * </td><td>
 *	��������� ������ � ������ Final=TRUE �������� ���������� ��������� ������� �������.
 * 	��������� ������ � ������ Final=FALSE �������� ����������� ��������� ������� �������.
 *	�� ����� ����� ����� �������������� ������� ����� �� ����� 128000�. 
 *	���������� ������� ���������� 4096.
 * </td></tr>
 * </table>
 * 
 * �� ���� ������� ������ ������� ����������� ����� ���������� ��������� ������ 
 * ����������� ��� ��������� ���������� ������. 
 * ��� ����, � ������ CP_CHP_HASH_CHAIN � CP_CHP_HASH_NONE ������ ������ ��� ����������� ����������� ������, 
 * � ������ CP_CHP_HASH_PACKET ������ ���������������.
 *
 * ��� ������������� ������ � ������ ��� ��������� � ������, ����������� � ������������  
 * �������� HASH, ������������� � ������� ������, � ����� ������������ ���������, ������� CPDecrypt() 
 * ���������� ������ (FALSE), ������� CPCDecrypt() � GetLastError() ���������� NTE_BAD_HASH, 
 * ������ ������� ����������� ��������� CPDecrypt(), CPCDecrypt() �� ����������������. 
 * � ���� ������ ���������� ����� �������� ������������ �������� HASH
 * ������� CPGetHashParam() � ������ ������� ������� � ���������� ��������������� ������
 * (��������: �����, �������������� � ������ CP_CHP_HASH_CHAIN, ������ ���� ������; 
 * �����, �������������� � ������ CP_CHP_HASH_PACKET ����� ���� ���������). 
 * � ������ ����������� ��������� ������ ���������� ������ ������� (������� �����) ������ ������� �����������.
 *
 * �� ������� ���������� ������� ���������� � ����������� ����� ����� ���� ����������� ��� �������, 
 * ������������ ���������� pbData � ������ cbData, ��� � �������� IOVEC �����/������, 
 * ������������ ���������� pbData �� ������� ������� �������� \ref CSP_iovec � ������ ��������� ������� cbData.
 * ����� ������������� ��������� ����� ������������� �����/������ ������������ ������ CP_CRYPT_DATA_IOVEC, 
 * � ��������� ������ ���� ����� CP_CRYPT_DATA_IOVEC �������� ���������� �������� ���������.
 *
 * � ������ �������� ��������� �������� ��������� ����� ���������� � ����������� ������ ��������������� 
 * ������� ������, ��������������� � hKey � hHash. �������������� �������������� �� ��������� CALG_PRO_DIVERS 
 * � �������������� ����� CRYPT_DIVERSBLOB, ����������� � ������������� ������. 
 * ���� ������������ ������������� ������ � ����� ������� �����-������, 
 * ���� �������������� ������ ������������ � ������ ���������� ������� �������.
 * ��������� ������������� �������������� ������ �������� ������������� ���� CP_CHP_STARTMIX.
 * ������������������� �������� ������ ����������� ��� ������������� ��� ��������� ����������� �������.
 * �������������� ������ �� �������� � ��������� �������� ������� ������.
 *
 * � ������ �������� ��������� �������� SIMD ������������ ��������� �� 16 ������� ��� ������������� 
 * ���������� ���������, �������������� ���������� SSSE3, AVX.
 * ��� ������ �������������� �� ������  � ����� ��������� ��� ���������� � 
 * � ����� ��������� ��� ������� ����������.
 * ������ ������ ���� ��������� � ������� �������� CSP_Multipacket. 
 * ��������� ������������� �������������� ��������� �������� ������������� ���� CP_CHP_MULTIPACKET.
 * ������ ����� ���� ������������ ��� �������� �������, ��� � �������� IOVEC �����/������.
 * ���������, ����� ��� ������ ���� �����������, ��� ������� ������������ ������ CP_CRYPT_DATA_IOVEC.
 * � �������������� ������ ������������� ��������������� �������������� �����, 
 * ������������ ������ CP_CHP_STARTMIX, �� �����������.
 * ��. \ref CryptMultipacket.
 *
 *
 * ���� CP_CRYPT_NOKEYWLOCK ������������ ��� ����������� ����������\������������� ������� �
 * ������������� ������, ��� ���� ���� ����������\������������� ����������� ������ �� ������.
 * ��� ����������� ������� ������ ������ ���������� ������� ������� ����������� ������
 * HCRYPTMODULE � ������� ������� CPCGetProvParam() � ������ PP_CREATE_THREAD_CSP; ������ ������ � ����������
 * ������� ���������� �������� CPCEncrypt() � CPCDecrypt() � �������� ������� ���������.
 *
 * ������������� ����� CP_CRYPT_NOKEYWLOCK ����������� ������ ��������� � ������ CP_CRYPT_HASH_PACKET, ��� �������� ��������� Final == TRUE;
 * ������������� ����� ��� ����������\������������� �� ����� � ������� �������������� (KP_MIXMODE), ��������
 * �� CRYPT_SIMPLEMIX_MODE, � ����� ��������� � ������ CP_CHP_IV_CHAIN �� �����������.
 *
 * ������
 * \code
 * CPCGetProvParam(hCSP, hProv, PP_CREATE_THREAD_CSP, NULL, &dwThreadCSPData, 0);
 *
 * pbThreadCSPData = (BYTE*)malloc(dwThreadCSPData);
 *
 * CPCGetProvParam(hCSP, hProv, PP_CREATE_THREAD_CSP, pbThreadCSPData, &dwThreadCSPData, 0);
 *
 * hThreadCSP = (HCRYPTMODULE)pbThreadCSPData;
 *
 * CPCEncrypt(hThreadCSP, hProv, hKey, hHash, TRUE, CP_CHP(CP_CHP_HASH_ENCRYPT | CP_CHP_IV_RANDOM | CP_CHP_STARTMIX |
 * CP_CHP_HASH_PACKET | CP_CRYPT_NOKEYWLOCK, HEADER_BYTE_SIZE, TRAILER_BYTE_SIZE, HASH_DWORD_SIZE), pbThreadPacketData, &cbThreadPacketData, cbThreadPacketData);
 * \endcode
 *
 * ���������:
 *
 *   1. � ������ hHash=0, �������� ������� ����������� �� ��������������.
 *
 *   2.	������������� ������ � ���� IOVEC �������� ����������� �� �������������, ������������� �������.
 *      ������� �����, ��� IOVEC ������������ ������, � �������� ��������� ������ ���������� �� ������.
 *
 *   3.	������������ ���������� ��������� IOVEC ������� �� ����������. 
 * ����� ���������� ������ ������������� ����������� ������������ 16 ��������� IOVEC.
 *
 *   4. ���� ����� �������� IOVEC >= 0.
 *
 *
 * ��������� ������ � ������� ��������� ����� ������ ������������ 
 * ���������� ������ ��������� dwFlags, 
 * ������������� ��������� OR; �������� ������ ��������, �� ��� 
 * ��������� �������� ����� ���������. ��� ������������ ������ 
 * ������������� ������������ ������ CP_CHP().
 *
 * \sa #CPEncrypt (CP_CRYPT_HASH_PACKET)
 * \sa #CPDecrypt (CP_CRYPT_HASH_PACKET)
 * \sa #CP_CHP()
 * \{
 */

/*!
 *  \brief ���� - ������� �������� ��������� ������, ������ ���� ����������, ���� ������������ ��������� ������,
 *  � ��������� ������ dwFlags ������ ���� ����� ����, ��� ������������� ��������� �������� ������ ������. 
 */
#define CP_CRYPT_HASH_PACKET		(0x80)
/*!
 *  \brief ���� ���������� ������� ��������� ������ ������ - ����������� (�����������) ����� ����������.
 */
#define CP_CHP_HASH_ENCRYPT		(0x00)
/*!
 *  \brief ���� ���������� ������� ��������� ������ ������ - ���������� ����� ����������� (�����������).
 */
#define CP_CHP_ENCRYPT_HASH		(0x10)
/*!
 *  \brief ���� - ������� ��������������� ������ ������. �������� pbData ������ ��������� �� ������ �������� 
 *  CSP_MultiPacket_ENC/CSP_Multipacket_DEC, � ��������� cbData/reserved ��������� ����� �������� � ������� (�� ������ ��������� 16).
 *  � ������ �� �������� CSP_MultiPacket_ENC/CSP_Multipacket_DEC �� ������ CPEncrypt()/CPDecrypt() �������������� � 
 *  ���� dwResult ������ ���� �������� �������� 1. � ������ ������, ��������� � ��������� �������� ������������ ������ 
 *  ��� ���������� ������� (������ NTE_BAD_HASH), ����� ������ �� ������� � ���� dwResult ����� 0 ������ � ��� �������, 
 *  ��������� ������� ����������� � �������� ��������� �������� ������������ (�������� ������� �����������).
 */
#define CP_CHP_MULTIPACKET		(0x20)
/*!
*  \brief ���� - ������� ������ � ����������� ����� ������ �� ������. 
*    ��������, ��� ������� ���������� �� ������ ����������, �������������� ������ NTE_BAD_FLAGS.
*/
#define CP_CRYPT_NOKEYWLOCK		(0x40)
/*!
 *  \brief ���� ����������� ������� ������������� (IV). ���� ����������, IV ������� �� ���������� ������ � ����������. 
 *	 ���� �� ����������, IV ,���� ������������ � ������, ������� �� ���������� ������, �� �� ����������.
 */
#define CP_CHP_IV_HEADER		(0x08)
/*!
 *  \brief ���� �������������� ����� ���������� � ����������� �� ��������� CALG_PRO_DIVERS. 
 *  ���� ������������ ������������� ������ � ����� ������, ���� �������������� ������ ������������ 
 *  � ������� ������ � ��� ������.
 *  ���� ������������ ������������� ������ � ����� ������� �����-������, 
 *  ���� �������������� ������ ������������ � ������ ���������� ������� �������. 
 *  ��� ��������� ������������ (���� CP_CHP_MULTIPACKET ����������) ���� �������������� ������ 
 *  ������������ � ������� ������� ������, � ���� ������ ��� ������ ������������ ������������� 
 *  �� ������������������� ������ ���������� � �����������.
 */
#define CP_CHP_STARTMIX			(0x04)
/*!
 *  \brief ����� ���������� IV. ������������ ����� ���� �� 2 ��������� ���. 
 *  ������� �������� ���� ������������� CP_CHP_IV_CHAIN.
 *  ��������� �������� ������������� CP_CHP_IV_USER, CP_CHP_IV_RANDOM.
 *  ����� ���� ���������� ������ ���� �� ������ CP_CHP_IV_CHAIN, CP_CHP_IV_USER, CP_CHP_IV_RANDOM.
 */
#define CP_CHP_IV_MASK			(0x300) 
/*!
 *  \brief  ���� ���� ����������, IV ������������ �������� CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) 
 *  (CPCEncrypt()) � ��������� � �����. ������� CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt())
 *  ��������� IV �� ������. 
 */
#define CP_CHP_IV_RANDOM		(0x100)
/*!
 *  \brief  ���� ���� ����������, ���������� ������������� IV � �����, 
 *  ������� CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()), 
 *  CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()) ��������� IV �� ������. 
 */
#define CP_CHP_IV_USER			(0x200)
/*!
 *  \brief  ���� ���� ����������, ������� CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()), 
 *  CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) �������� IV ������ �� ��������� �����.
 */
#define CP_CHP_IV_CHAIN			(0x000)
/*!
 *  \brief ����� ���������� ��������� ���-������� ������. ������������ ����� ���� �� 2 ��������� ���. 
 *  ������� �������� ���� ������������� CP_CHP_HASH_NONE.
 *  ��������� �������� ������������� CP_CHP_HASH_CHAIN, CP_CHP_HASH_PACKET.
 *  ����� ���� ���������� ������ ���� �� ������ CP_CHP_HASH_NONE, CP_CHP_HASH_CHAIN, CP_CHP_HASH_PACKET.
 */
 #define CP_CHP_HASH_MASK		(0xC00)
/*!
 *  \brief  ���� ���� ����������, ������� ����������� ������������� �� ���� ����� �������. 
 *  � ����� �������� ���-������� �� ���������.
 */
#define CP_CHP_HASH_NONE		(0x000)
/*!
 *  \brief  ���� ���� ����������, ������� ����������� �������������� �� ����� �������, 
 *  ������� �������� ���-������� ��������������� � ����� ��������� 
 *  CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_HASH_CHAIN...,...) (CPCEncrypt()).
 *  ������� CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) ����������
 *  ������������ �������� ���-������� �� ���������, ���������� �� ������,
 *  � � ������ ������������ ���������� ������ NTE_BAD_HASH.
 */
#define CP_CHP_HASH_CHAIN		(0x400)
/*!
 *  \brief  ���� ���� ����������, ������� ����������� �������������� �� �����, 
 *  �������� ���-������� ��������������� � ����� ��������� 
 *  CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_HASH_CHAIN...,...) (CPCEncrypt()).
 *  ������� CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) ����������
 *  ������������ �������� ���-������� �� ���������, ���������� �� ������,
 *  � � ������ ������������ ���������� ������ NTE_BAD_HASH.
 */
#define CP_CHP_HASH_PACKET		(0x800)
/*!
 *  \brief ����� ������� �������� ���-������� � ������� ������ (4 ������), ���������������� � �����.
 *  ��������� ��������: 1 (��� �����������) �� 1 �� 8 (��� ���-������� �� ���� �34.11-94 � HMAC).
 */
#define CP_CHP_HASH_SIZE_MASK		(0xF000)
/*!
 *  \brief ����� ������� �������� � ������, �������� 0 - 254 �������� ����� ��������, 
 *  ��������  255 ��������: ����� �������� 0, �������� ���-������� � ������ ���������.
 */
#define CP_CHP_TRAILER_MASK		(0xFF0000)

#define CP_CHP_ENCRYPTED_TRAILER	(CP_CHP_TRAILER_MASK>>CP_CHP_TRAILER_SHIFT)

/*!
 *  \brief ����� ������� ��������� � ������, ������ ����� ���������� �������� 0 - 255. 
 */
#define CP_CHP_HEADER_MASK		(0xFF000000)

/*! \brief ������ ��� ������������ ��������� dwFlags (������) �������
 *  CPEncrypt() � CPDecrypt()
 *
 *  ����� (dwFlags) ����������� �� ������ ���������� ������:
 *  - ������ ������� ���������� ���-������� � ��������� �������������;
 *  - ������� ���������;
 *  - ������� "������";
 *  - ������� �������� ���-�������.
 */
#define CP_CHP(Flags,HeaderByteSize,TrailerByteSize,HashDWordSize) (\
            (Flags)|CP_CRYPT_HASH_PACKET|\
            (((HeaderByteSize)<<CP_CHP_HEADER_SHIFT)&CP_CHP_HEADER_MASK)|\
            (((TrailerByteSize)<<CP_CHP_TRAILER_SHIFT)&CP_CHP_TRAILER_MASK)|\
            (((HashDWordSize)<<CP_CHP_HASH_SIZE_SHIFT)&CP_CHP_HASH_SIZE_MASK)\
        )
/*! \} */

/*! \ingroup ProCSPData
 * \defgroup PacketMacros ��������������� ������� �������� ��������� ������
 *
 *  � �������� ������� ����������� ����������:
 *  - �������� f ������������ dwFlags;
 *  - �������� d ������������ ��������� �� �����, ���������� �����;
 *  - �������� l ������������ ����� ������.
 *
 * \{
 */

/*!
 *  \brief ����� ���� ��� ����� CP_CHP_HASH_SIZE_MASK. 
 */
#define CP_CHP_HASH_SIZE_SHIFT		(12)
/*!
 *  \brief ����� ���� ��� ����� CP_CHP_TRAILER_MASK. 
 */
#define CP_CHP_TRAILER_SHIFT		(16)
/*!
 *  \brief ����� ���� ��� ����� CP_CHP_HEADER_MASK. 
 */
#define CP_CHP_HEADER_SHIFT		(24)
/* 
    Aplication Packet (A-Packet, �-�����)
    ��������� �-������
    IV
    IV ������������ � �-������ ������ �����, ����� �� ��������� ��� ����������,
    �.�. IV ���� RANDOM ��� USER ������������ � �-������.
    ���� CP_CHP_IV_HEADER ����������, IV ������ � ������ ������ � ������ � ���� ������ IV ����������.
    ���� CP_CHP_IV_HEADER �� ����������, IV �� ������ � ������ ������ � ������ �������������� � �-������.
    IV ���� RANDOM ��������������� � �-����� � ����������� �� ���� ��������� Encrypt()/Decrypt().
    IV ���� USER ��������������� � �-����� �����������, ����������� �� ���� ��������� Encrypt()/Decrypt().
    IV ���� CHAIN ��������������� ����������� �� ���� �������� SetKeyParam(...,KP_IV,...), 
    � �-����� IV ���� CHAIN �� ������.

*/
/*!
 *  \brief ������ ���� IV � ������. 
 */
#define CP_CHP_IV_SIZE(f) (((f)&CP_CHP_IV_MASK)?(SEANCE_VECTOR_LEN):(0))

/*internal
 *  \brief ����� ��������� �� ���������.
 *      p - ���������
 *      w - ��������
 */
#define _CP_CHP_ADD_(p,w) \
	    ((void *)(((char *)p) + (w)))
#define _CP_CHP_SUB_(p,w) \
	    ((void *)(((char *)p) - (w)))


/*internal
 *  \brief �������� ������ ������.
 *	d - ��������� �� �����
 *      l - ����� ������
 *      p - �������������� ��������� �� ���� ������
 *      w - ����� ����
 */
#define _CP_CHP_SAFE_CHECK_(d,l,p,w)					\
	    (NULL != (d) && (size_t)(w) <= (size_t)(l) &&		\
	     (void *)(d) <= (void *)(p) &&					\
	     _CP_CHP_ADD_((p),(w)) <= _CP_CHP_ADD_((d),(l))		\
		? (p)							\
		: NULL							\
	    )

/*!
 *  \brief ��������� �� ���� IV � ������. 
 */
#define CP_CHP_IV_DATA(f,d,l) _CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d),					\
		    (((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)),	\
		CP_CHP_IV_SIZE(f)					\
	    )

/*  
    HEADER
    � ������ ������ ������� IV � ���������� ����� � IV.
    ����� ������� ������ ����������� 
    HashData(...,CP_CHP_HEADER_DATA(dwFlags,pbData,dwDataLen),CP_CHP_HEADER_SIZE(dwFlags));
*/
/*!
 *  \brief ��������� �� ���� ��������� � ������, ���� ��������� ������������. 
 */
#define CP_CHP_HEADER_DATA(f,d,l) _CP_CHP_SAFE_CHECK_((d),(l),		\
					(d), CP_CHP_PUREHEADER_SIZE(f))
/*!
 *  \brief ������ ���� ��������� ������. 
 */
#define CP_CHP_PUREHEADER_SIZE(f)					\
			(((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)
/*!
 *  \brief ������ ����������� ���� ��������� ������ � ���� IV (���� IV ����������). 
 */
#define CP_CHP_HEADER_SIZE(f)	    (CP_CHP_PUREHEADER_SIZE(f) +	\
					(((f)&CP_CHP_IV_HEADER)		\
					? CP_CHP_IV_SIZE(f)		\
					: 0))

/*!
 *  \brief ��������� ������ ���� ��������� ������ � ���� IV. 
 */
#define CP_CHP_REALHEADER_SIZE(f)   (CP_CHP_PUREHEADER_SIZE(f) +		\
					CP_CHP_IV_SIZE(f))
/*  
    HASH
    �������� ���� ������������ � �-������ ������ ��� ����� CHAIN � PACKET.
    ��� ���� ���� PACKET ���� CHAIN ������� Encrypt() ��������� � ������������� �������� ���� � �����, 
    ������� Decrypt() ��������� �������� ���� � ���������� ��� �� ��������� �� ������, 
    � ������ ������������ ������������ ������ NTE_BAD_HASH (CRYPT_E_HASH_VALUE). 
    ���������� ���� ����� �������� �������� ���� �� ����� ������� ������� GetHashParam(...,HP_HASHVAL,...).
    ��� ���� NONE �������������� �����������, ��� �������� � �-������� ����������.
    �������� ���� ����� ������������, ���� ���� CP_CHP_TRAILER_MASK ����������� � 0xff.
*/

/*!
 *  \brief ������ ���� �������� ���-�������. 
 */
#define CP_CHP_HASH_SIZE(f)						\
		(sizeof(DWORD)*						\
		    (((f)&CP_CHP_HASH_MASK)				\
		    ?((f&CP_CHP_HASH_SIZE_MASK)>>CP_CHP_HASH_SIZE_SHIFT)\
		    :0))
/*!
 *  \brief ��������� �� ���� �������� ���-������� � ������, ���� ���� ������������. 
 */
#define CP_CHP_HASH_DATA(f,d,l)	_CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d), (l)-CP_CHP_HASH_SIZE(f)),		\
		CP_CHP_HASH_SIZE(f)					\
	    )

/*!
 *  \brief ����� ����������� ���� ������(� ������, ����� ���� IV ����������). 
 */
#define CP_CHP_HASH_LEN(f,l) (l-CP_CHP_HASH_SIZE(f))
/*!
 *  \brief ����� ������� ����������� ���� (� ������, ����� ���� IV �� ����������). 
 */
#define CP_CHP_HASH_LEN_1(f)  CP_CHP_PUREHEADER_SIZE(f)


/*!
 *  \brief ������ ���� ��������. 
 */
#define CP_CHP_TRAILER_SIZE(f)						\
		    ((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(0)						\
		    :(((f)&CP_CHP_TRAILER_MASK)>>CP_CHP_TRAILER_SHIFT))	\
/*!
 *  \brief ��������� �� ���� �������� � ������, ���� ���� ������������. 
 */
#define CP_CHP_TRAILER_DATA(f,d,l)  _CP_CHP_SAFE_CHECK_((d),(l),	\
		_CP_CHP_SUB_(CP_CHP_HASH_DATA((f),(d),(l)),		\
					CP_CHP_TRAILER_SIZE(f)),	\
		CP_CHP_TRAILER_SIZE(f)					\
	    )

/*!
 *  \brief ������ ���� ������. 
 */
#define CP_CHP_PAYLOAD_SIZE(f,l) ((l) -					\
				    CP_CHP_REALHEADER_SIZE(f) -		\
				    CP_CHP_TRAILER_SIZE(f) -		\
				    CP_CHP_HASH_SIZE(f))

/*!
 *  \brief ������ ���������� ���� ������. 
 */
#define CP_CHP_CIPHER_SIZE(f,l) (					\
		(l) -							\
		CP_CHP_REALHEADER_SIZE(f) -				\
		CP_CHP_TRAILER_SIZE(f) -				\
		((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(0)						\
		    :(CP_CHP_HASH_SIZE(f)))				\
	    )
/*!
 *  \brief ��������� �� ��������� ���� ������. 
 */
#define CP_CHP_CIPHER_DATA(f,d,l)   _CP_CHP_SAFE_CHECK_((d),(l),	\
		_CP_CHP_ADD_((d), CP_CHP_REALHEADER_SIZE(f)),		\
		CP_CHP_CIPHER_SIZE(f,l)					\
	    )

/*!
 *  \brief ��������� �� ������ ���������� ���� ������ (� ������, ����� ���� IV �� ����������). 
 */
#define CP_CHP_HASH_DATA_2(f,d,l)   CP_CHP_CIPHER_DATA((f),(d),(l))

/*!
 *  \brief ����� ������� ����������� ���� ������ (� ������, ����� ���� IV �� ����������). 
 */
#define CP_CHP_HASH_LEN_2(f,l)  (					\
		CP_CHP_CIPHER_SIZE(f,l) + CP_CHP_TRAILER_SIZE(f) -	\
		((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(CP_CHP_HASH_SIZE(f))				\
		    :(0))						\
	    )

/*! \} */


/*! \ingroup ProCSPData
 * \defgroup CryptIOvec  ������ ����� ������
 *
 * ���� ��� ������ ������� ���������� CPEncrypt(),
 * CPCEncrypt(), CPDecrypt() ��� CPCDecrypt() � ��������� dwFlags
 * ����������� ����� CP_CRYPT_HASH_PACKET �  CP_CRYPT_DATA_IOVEC,
 * ��� ��� ������ ������� ����������� CPHashData() � CPCHashData()
 * ���������� ���� CP_HASH_DATA_IOVEC, ��
 * �������������� ������ ������������ � ����� ������� �����-������ --
 * �������� �������� #CSP_iovec.
 * ������������������ �������� � ������� ������ ���������������
 * ������������������ ���������� ������ � ������.
 */

#if !defined(UNIX)
    ///*
    // * WinSock 2 extension -- WSABUF and QOS struct, include qos.h
    // * to pull in FLOWSPEC and related definitions
    // */
    //
    //typedef struct _WSABUF {
    //    u_long      len;     /* the length of the buffer */
    //    char FAR *  buf;     /* the pointer to the buffer */
    //} WSABUF, FAR * LPWSABUF;
    //
    //������ ���������� � IDL (�� C:\WINDDK\6001.18001\inc\api\ws2def.h)
    //typedef struct _WSABUF {
    //	ULONG len;     /* the length of the buffer */
    //	__field_bcount(len) CHAR FAR *buf; /* the pointer to the buffer */
    //} WSABUF, FAR * LPWSABUF;
    
    #ifndef RPC_CSP_iovec
    #define RPC_CSP_iovec

	//typedef struct _WSABUF {
	//	ULONG len;     /* the length of the buffer */
	//	[size_is (len)] CHAR FAR *buf; /* the pointer to the buffer */
	//} WSABUF, FAR * LPWSABUF;

	typedef CHAR *CSPiov_ptr_type;
	typedef ULONG CSPiov_len_type;

		// TODO: ��� ��� ���������, ���� �����, ����� ������ 
		// ������������ ��������� ��������
	    /*! \ingroup CryptIOvec
	    *
	    * \brief C�������� ���������� ������������� ��������� ������ 
	    *	      �� ������� ����������.
	    *
	    * \note �� ������ ���������� ������������ �� ���� Windows CSP_iovec 
	    * �������� �������� ��� WSABUF, 
	    * ������� ��� ������������� CSP_iovec ��������� 
	    * "#include <Winsock2.h>".
	    *
	    * \note �� ������ ���������� ������������ � POSIX 
	    * (Linux/Solaris/AIX/FreeBSD) �������� CSP_iovec �������� �������� 
	    * ��� struct iovec, ������� ��� ������������� CSP_iovec ��������� 
	    * "#include <sys/uio.h>".
	    */
	    typedef struct CSP_iovec_ {
		CSPiov_len_type CSPiov_len; /*!< ����� ��������� ������ � ������. */
		CSPiov_ptr_type CSPiov_ptr; /*!< ��������� �� �������� ������. */
	    } CSP_iovec;
	#if !defined(CSP_LITE)
		// �� ������ ���������� ���������� ��������� ��
		// ������, �������������� �����������, ���������� 
		// ������������� ������� ���� � ������������
	    #define CSP_iovec	    WSABUF
	    #define CSPiov_len	    len
	    #define CSPiov_ptr	    buf
	#endif 

	/*! \ingroup CryptIOvec
	 *
	 * \brief ����������� ���������� ����� ���������� � 
	 *        ������������� ������ �������� ����� ������.
	 * 
	 */
	#define CSP_UIO_MAXIOV 		(1024-16)

	/*! \ingroup CryptIOvec
	 *
	 * \brief ����������� ���������� ����� ���������� ��� 
	 *        ������������� ���������� ������ ���� ��� � 
	 *        �������� ������������ ������������.
	 * 
	 */
    	#define CSP_KERNEL_UIO_MAXIOV	(1024-16)

    #endif /* RPC_CSP_iovec */
#else
    // Gnu lib
    //   #define UIO_MAXIOV      1024
    //                                                                               
    //   /* Structure for scatter/gather I/O.  */
    //   struct iovec
    //     {
    //        void *iov_base;     /* Pointer to data.  */
    //        size_t iov_len;     /* Length of data.  */                                    };
    //     };

    #if defined(SOLARIS) && !defined(_XPG4_2) && !defined(CSP_LITE)
        #include <sys/types.h>
    	typedef caddr_t CSPiov_ptr_type;
	#if defined(_LP64)
	    typedef size_t CSPiov_len_type;
	#else
	    typedef long CSPiov_len_type;
	#endif
    #else
	typedef void* CSPiov_ptr_type;
	typedef size_t CSPiov_len_type;
    #endif

	    // TODO: ��� ��� ���������, ���� �����, ����� ������ 
	    // ������������ ��������� ��������
	typedef struct CSP_iovec_ {
	    CSPiov_ptr_type CSPiov_ptr; /*!<��������� �� �������� ������.*/
	    CSPiov_len_type CSPiov_len; /*!<����� ��������� ������ � ������.*/
	} CSP_iovec;
    #if !defined(CSP_LITE)
	    // �� ������ ���������� ���������� ��������� �� ��� 
	    // ��������� �������������� � ����������� �/� ��.
	    // ������, �������������� �����������, ���������� 
	    // ������������� ������� ���� � ������������ ��� �����
	    // ����� ����������� ������������ "��������" ���� � ������ ������������.
	#define CSP_iovec	    struct iovec
	#define CSPiov_ptr	    iov_base
	#define CSPiov_len	    iov_len
    #endif 
#ifdef ANDROID
#	define IOV_MAX 16
#endif

    #define CSP_UIO_MAXIOV 		(IOV_MAX-2)
    #define CSP_KERNEL_UIO_MAXIOV	(1024-16)
#endif

/*! \ingroup CryptIOvec
 *
 * \brief �������� �� ������������������� ���� �����.
 * 
 */
#define CSP_UIOV_MAXBAD_LEN ((CSPiov_len_type)0x7fffFFFF)

/*! \ingroup CryptIOvec
 *
 * \brief ������ ���������� ��������� �� �������� ������ � ������� n � ������� ����� ������.
 *
 * ���������:
 * - p - ��������� �� ������ ������� � ������� �������� CSP_iovec;
 * - n - ����� ��������� � ������� ����� ������.
 */
#define IOVEC_PTR(p,n) (((CSP_iovec*)p)[n].CSPiov_ptr)
/*! \ingroup CryptIOvec
 *
 * \brief ������ ���������� ����� ��������� ������ � ������� n � ������� ����� ������.
 *
 * ���������:
 * - p - ��������� �� ������ ������� � ������� �������� CSP_iovec;
 * - n - ����� ��������� � ������� ����� ������.
 */
#define IOVEC_LEN(p,n) (((CSP_iovec*)p)[n].CSPiov_len)
/*! \ingroup CryptIOvec
 *
 *  \brief ���� - ������� ������������� ������ � ����� ������� �����/������. 
 *  ��� ������� CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt() ����
 *  ������ ���� ����������, ���� ������������ ������������� ������ � ����� ������� �����/������,
 *  � ��������� ������ ����� �������������� �������. ��. \ref CryptPacket
 */
#define CP_CRYPT_DATA_IOVEC		(0x2)
/*! \ingroup CryptIOvec
 *
 *  \brief ���� ��������� dwFlags - ������� ������������� ������ � ����� ������� �����/������ 
 *  ��� ������� CPHashData() � CPCHashData(). ������ ���� ����������, ���� ������������ 
 *  ������������� ������ � ����� ������� �����/������, � ��������� ������ ������ �������������� �������. 
 */
#define CP_HASH_DATA_IOVEC		CP_CRYPT_DATA_IOVEC

#define CP_CRYPT_SET_TESTER_STATUS	(0x2)
#define CP_CRYPT_SELFTEST_FORCE_FAIL 	(0x4)
#define CP_CRYPT_SELFTEST_FORCE_SUCCESS	(0x8)

#define CP_CRYPT_SELFTEST_THROW		(0x100000)
#if defined IGNORE_CPCSP_6005
#define CP_CRYPT_SELFTEST_REAL_THROW	(0x200000)
#endif	/* IGNORE_CPCSP_6005 */
#define CP_CRYPT_SELFTEST_THROW_SHIFT	(8)
#define CP_CRYPT_SELFTEST_THROW_MASK	(0x00FF00)
#define CP_CRYPT_SELFTEST_THROW_ILL	(0x000400)
#define CP_CRYPT_SELFTEST_THROW_TRAP	(0x000500)
#define CP_CRYPT_SELFTEST_THROW_ABRT	(0x000600)
#define CP_CRYPT_SELFTEST_THROW_FPE	(0x000800)
#define CP_CRYPT_SELFTEST_THROW_BUS	(0x000A00)
#define CP_CRYPT_SELFTEST_THROW_SEGV	(0x000B00)
#define CP_CRYPT_SELFTEST_THROW_SYS	(0x000C00)
#define CP_CRYPT_SELFTEST_THROW_USR1	(0x001E00)

#define CP_REUSABLE_HMAC		(0x4)
#define CP_MULTI_HASH_FLAG		(0x8)

#define MIN_MULTI_HASH_COUNT		(0x01)
#define MAX_MULTI_HASH_COUNT		(0x40)

#define CP_CRYPT_GETUPPERKEY		(0x200)

/*! \ingroup ProCSPData
 * \defgroup CryptMultipacket  �������������� ��������� 
 * ������� CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt()
 * ��������� �������������� ��������� �� ���������� SIMD ��� ������������� 
 * ���������� ���������, �������������� ���������� SSSE3, AVX.
 */

/*! \ingroup CryptMultipacket
 *  \brief ������������ ������ ��� �������������; �������� CSP_Multipacket_ENC � CSP_Multipacket_DEC.
 *  
 */
typedef struct CSP_Multipacket_ {
    BYTE*	    pbData;	/*!< ��������� �� �������� �����, ��������� �� IOVEC. */
    DWORD	    cbData;	/*!< ����� ��������� ������; ����� ����� ��������� IOVEC (��� ������������� - ����� ��������� IOVEC). */
    DWORD	    dwBufLen;	/*!< ����� ������ ��������� ������, ����� ��������� IOVEC (��� ������������� ���� �� ������������). */
    DWORD	    dwResult;	/*!< ��������� ��������� ������.  */
} CSP_Multipacket;

/*! \ingroup CryptMultipacket
*  \brief ��������� ��� �������� ���������� ��� ���������� � ������ �������������� ���������
* (������������� ����� CP_CHP_MULTIPACKET). ����������� ��������� �������� �������� CSP_Multipacket_ENC.
* ������ ��������� ������� ����� ��� �������� �����, ���� ��� IOVEC, ���� �
* ��������� dwFlags ����������� ����� CP_CRYPT_HASH_PACKET, CP_CHP_MULTIPACKET �
* CP_CRYPT_DATA_IOVEC.
*
*/
typedef  struct CSP_Multipacket_ENC_ {
	BYTE*	    pbEncData; /*!< ��������� �� �������� �����, ��������� �� IOVEC. */
	DWORD	    cbEncDataLen; /*!< ����� ��������� ������; ����� ����� ��������� IOVEC */
	DWORD	    dwEncBufLen; /*!< ����� ������ ��������� ������, ����� ��������� IOVEC */
	DWORD	    dwEncResult; /*!< ��������� ��������� ������.  */
} CSP_Multipacket_ENC;


/*! \ingroup CryptMultipacket
*  \brief ��������� ��� �������� ���������� ��� ������������� � ������ �������������� ���������
* (������������� ����� CP_CHP_MULTIPACKET). ����������� ��������� �������� �������� CSP_Multipacket_DEC.
* ������ ��������� ������� ����� ��� �������� �����, ���� ��� IOVEC, ���� �
* ��������� dwFlags ����������� ����� CP_CRYPT_HASH_PACKET, CP_CHP_MULTIPACKET �
* CP_CRYPT_DATA_IOVEC.
*
*/
typedef  struct CSP_Multipacket_DEC_ {
	BYTE*	    pbDecData; /*!< ��������� �� �������� �����, ��������� �� IOVEC. */
	DWORD	    dwDecDataLen; /*!< ����� ��������� ������, ����� ��������� IOVEC */
	DWORD	    reserved; /*!< ����� ������ ��������� ������, ����� ��������� IOVEC */
	DWORD	    dwDecResult; /*!< ��������� ��������� ������.  */
} CSP_Multipacket_DEC;

#define MultiPacket_PTR(p,n) (((CSP_Multipacket*)p)[n].pbData)

/*! \ingroup CryptMultipacket
* \brief ������ ���������� ��������� �� ��������� ����� � ������� n � ������� �������.
*
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_ENC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_ENC_PTR(p,n) (((CSP_Multipacket_ENC*)p)[n].pbEncData)
/*! \ingroup CryptMultipacket
* \brief ������ ���������� ��������� �� ���������������� ����� � ������� n � ������� �������.
*
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_DEC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_DEC_PTR(p,n) (((CSP_Multipacket_DEC*)p)[n].pbDecData)


#define MultiPacket_LEN(p,n) (((CSP_Multipacket*)p)[n].cbData)

/*! \ingroup CryptMultipacket
* \brief ������ ���������� ����� ���������� ������ � ������� n � ������� ������� 
* ���� ����� ����� � ������������� ���������� ������ �������� �����-������
*
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_ENC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_ENC_LEN(p,n) (((CSP_Multipacket_ENC*)p)[n].cbEncDataLen)

/*! \ingroup CryptMultipacket
* \brief ������ ���������� ����� ����������������� ������ � ������� n � ������� ������� ���� ����� ��������� ������� �����-������.
*
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_DEC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_DEC_LEN(p,n) (((CSP_Multipacket_DEC*)p)[n].dwDecDataLen)

#define MultiPacket_BUFLEN(p,n) (((CSP_Multipacket*)p)[n].dwBufLen)

/*! \ingroup CryptMultipacket
* \brief ������ ���������� ����� ������ ���������� ��������� ������ � ������� n � ������� ������� ���� ����� ��������� ������� �����-������.
*
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_ENC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_ENC_BUFLEN(p,n) (((CSP_Multipacket_ENC*)p)[n].dwEncBufLen)

#define MultiPacket_RES(p,n) (((CSP_Multipacket*)p)[n].dwResult)

/*! \ingroup CryptMultipacket
* \brief ������ ���������� ��������� ��������� ������ � ������� n � ������� �������.
* ��� ������� CPEncrypt(), CPCEncrypt()
* ����� �� ������� � ��� ���� ��������������� �������.
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_ENC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_ENC_RES(p,n) (((CSP_Multipacket_ENC*)p)[n].dwEncResult)

/*! \ingroup CryptMultipacket
* \brief ������ ���������� ��������� ��������� ������ � ������� n � ������� �������.
* ��� ������� CPDecrypt(), CPCDecrypt()
* ����� �� ������� � ��� ���� ��������������� �������.
* ����� ������ ������� CPDecrypt(), CPCDecrypt() �������� ���� �
* ������ ���� ���������������, ��� ����� � ������� n ��������� ���������,
* �������� ��� ������� ������ ������� � ����������� ���������;
* �������� ������� � ������ ���� ��������������� � ���, ��� �������� ��� ������� �� �������.
* ���������:
* - p - ��������� �� ������ ������� � ������� �������� CSP_Multipacket_DEC;
* - n - ����� ��������� � ������� �������.
*/
#define MultiPacket_DEC_RES(p,n) (((CSP_Multipacket_DEC*)p)[n].dwDecResult)

#endif /* _WINCRYPTEX_H_INCLUDED */
/** \endcond */
