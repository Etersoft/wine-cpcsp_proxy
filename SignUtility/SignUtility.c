/*
* Copyright(C) 2000-2014
*
* Этот файл содержит информацию, являющуюся
* собственностью компании Крипто Про.
*
* Любая часть этого файла не может быть скопирована,
* исправлена, переведена на другие языки,
* локализована или модифицирована любым способом,
* откомпилирована, передана по сети с или на
* любую компьютерную систему без предварительного
* заключения соглашения с компанией Крипто Про.
*
* Программный код, содержащийся в этом файле, предназначен
* исключительно для целей обучения и не может быть использован
* для защиты информации.
*
* Компания Крипто-Про не несет никакой
* ответственности за функционирование этого кода.
*/

#include <stdio.h>
#include <errno.h>
#include <locale.h>

#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#   include <tchar.h>
#   pragma comment(lib, "shell32.lib")
#else
#   include <stdlib.h>
#   include <stdarg.h>
#   include <unistd.h>
#   include <fcntl.h>
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#   include "reader/tchar.h"
#endif

#include <WinCryptEx.h>


#define UNUSED(x)	    (void)(x)
#define LANGUAGE 1033



void HandleError(TCHAR *format, ...); 
void PrintHelp(void);
TCHAR* GetCmdOption(int, TCHAR **, TCHAR *);
BOOL CmdOptionExists(int, TCHAR **, TCHAR *);
void DoSign(TCHAR *, TCHAR *, TCHAR *, BOOL, BOOL);
void DoVerify(TCHAR *, TCHAR *, BOOL);
BOOL FindCertByName(TCHAR *, BOOL, PCCERT_CONTEXT *);
BOOL GetFileData(TCHAR *, DWORD *, BYTE *);
BOOL SaveDataToFile(TCHAR *, DWORD, BYTE *);
char* GetHashOidByKeyOid(char *);
BOOL VerifyCertificateChain(PCCERT_CONTEXT);
TCHAR* GetFileExtension(TCHAR *);
BOOL CheckFileExtension(TCHAR *);
BOOL ShowPreview(TCHAR *);
void PrintCertInfo(PCCERT_CONTEXT); 


int _tmain(int argc, TCHAR **argv) 
{

    // Params ==========================================================
    BOOL  bHelp		    = FALSE;
    BOOL  bSign		    = FALSE;
    BOOL  bVerify	    = FALSE;
    BOOL  bLocalMachine	    = FALSE;
    BOOL  bSilent	    = FALSE;

    TCHAR *szFile	    = NULL;
    TCHAR *szSignatureFile  = NULL;
    TCHAR *szCertName	    = NULL;

    setlocale(LC_ALL,"rus");

    // Parse params ====================================================
    bSign = CmdOptionExists(argc, argv, _TEXT("-sign"));
    bVerify = CmdOptionExists(argc, argv, _TEXT("-verify"));
    bLocalMachine = CmdOptionExists(argc, argv, _TEXT("-machine"));
    bSilent = CmdOptionExists(argc, argv, _TEXT("-silent"));

    szFile = GetCmdOption(argc, argv, _TEXT("-file"));
    szSignatureFile = GetCmdOption(argc, argv, _TEXT("-signature"));
    szCertName = GetCmdOption(argc, argv, _TEXT("-cert"));

    // Check params ====================================================

    // Check that bSign = TRUE or bVerify = TRUE,
    // but not both.
    if (bSign == bVerify) {
	bHelp = TRUE;
	goto Finish;
    }

    // Check that all need for sign parameters exists.
    if (bSign && (szFile == NULL || szSignatureFile == NULL || szCertName == NULL)) {
	    bHelp = TRUE;
	    goto Finish;
    }

    // Check that all need for verify parameters exists.
    if (bVerify && (szFile == NULL || szSignatureFile == NULL)) {
	bHelp = TRUE;
	goto Finish;
    }

    // Do work ==========================================================
    if (bSign) {
	DoSign(szFile, szSignatureFile, szCertName, bLocalMachine, bSilent);
    }

    if (bVerify) {
	DoVerify(szFile, szSignatureFile, bSilent);
    }

    return 0;
Finish:

    if (bHelp) {
	PrintHelp();
    }

    return 1;
}

void PrintHelp() {
    _tprintf(_TEXT("Usage: SignUtility <command> [options]\n\n"));
    _tprintf(_TEXT("Commands:\n"));
    _tprintf(_TEXT(" -sign:\t\tSign data from input file.\n"));
    _tprintf(_TEXT(" -verify:\tVerify signature for input file.\n"));
    _tprintf(_TEXT("Options:\n"));
    _tprintf(_TEXT(" -file:\t\tInput file for sign or verify.\n"));
    _tprintf(_TEXT(" -signature:\tFor -sign path to file where signature will be saved.\n"));
    _tprintf(_TEXT(" \t\tFor -verify path to file with signature.\n"));
    _tprintf(_TEXT(" -cert:\t\tName of certificate (need only for sign).\n"));
}

TCHAR* 
GetCmdOption(IN int argc,
	     IN TCHAR **argv,
	     IN TCHAR *option) 
{
    int i;
    for(i = 1; i < argc; i++) {
	if (_tcscmp(argv[i], option) == 0 && 
	    i + 1 != argc) {
		return argv[i + 1];
	}
    }
    return NULL;
}

BOOL 
CmdOptionExists(IN int argc,
		IN TCHAR **argv,
		IN TCHAR *option) 
{
    int i;
    for(i = 1; i < argc; i++) {
	if (_tcscmp(argv[i], option) == 0) {
	    return TRUE;
	}
    }
    return FALSE;
}

void 
DoSign(IN TCHAR *szFile,
       IN TCHAR *szSignatureFile,
       IN TCHAR *szCertName,
       IN BOOL bLocalMachine,
       IN BOOL bSilent) 
{

    PCCERT_CONTEXT pCertCtx = NULL;

    DWORD dwDataSize = 0;
    BYTE *pbData = NULL;

    CRYPT_SIGN_MESSAGE_PARA stSignMessagePara;
    DWORD MessageSizeArray[1];
    const BYTE *MessageArray[1];

    DWORD dwSignatureSize = 0;
    BYTE *pbSignatureData = NULL;


    // Check file extension
    if (!CheckFileExtension(szFile)) {
	HandleError(_TEXT("File '%s' extension is not allowed. Allowed extensions: pdf, odt, txt, xml.\n"), szFile);
    }

    // Get file data
    if (!GetFileData(szFile, &dwDataSize, NULL)) {
	HandleError(_TEXT("Can't read file '%s'.\n"), szFile);
    }

    pbData = (BYTE*)malloc(dwDataSize * sizeof(BYTE));

    if (pbData == NULL) {
	SetLastError(ERROR_OUTOFMEMORY);
	HandleError(_TEXT("Can't allocate memory for file '%s' data.\n"), szFile);
    }

    if (!GetFileData(szFile, &dwDataSize, pbData)) {
	HandleError(_TEXT("Can't read file '%s'.\n"), szFile);
    }

    // Preview file and get user's answer
    if (!bSilent) {
	 if (!ShowPreview(szFile)) {
	    HandleError(_TEXT("Aborting by user.\n"));
	}
    }

    // Find certificate
    if (!FindCertByName(szCertName, bLocalMachine, &pCertCtx)) {
	HandleError(_TEXT("Can't find certificate '%s'.\n"), szCertName);
    }
    else {
	_tprintf(_TEXT("Certificate:\n"));
	PrintCertInfo(pCertCtx);
    }

    // Verify certificate chain
    if (!VerifyCertificateChain(pCertCtx)) {
	HandleError(_TEXT("Verifying '%s' certificate chain failed.\n"), szCertName);
    }

    // Fill CRYPT_SIGN_MESSAGE_PARA structure
    ZeroMemory(&stSignMessagePara, sizeof(CRYPT_SIGN_MESSAGE_PARA));
    stSignMessagePara.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    stSignMessagePara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    stSignMessagePara.pSigningCert = pCertCtx;
    stSignMessagePara.HashAlgorithm.pszObjId = GetHashOidByKeyOid(pCertCtx->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);	
    stSignMessagePara.rgpMsgCert = &pCertCtx;
    stSignMessagePara.cMsgCert = 1;

    MessageArray[0] = pbData;
    MessageSizeArray[0] = dwDataSize;


    if (!CryptSignMessage(
	&stSignMessagePara, 
	TRUE, 
	1, 
	MessageArray, 
	MessageSizeArray, 
	NULL, 
	&dwSignatureSize)) {
	    HandleError(_TEXT("Can't sign file '%s'.\n"), szFile);
    }

    pbSignatureData = (BYTE*)malloc(dwSignatureSize * sizeof(BYTE));

    if (pbSignatureData == NULL) {
	SetLastError(ERROR_OUTOFMEMORY);
	HandleError(_TEXT("Can't allocate memory for signature data.\n"));
    }

    if (!CryptSignMessage(
	&stSignMessagePara, 
	TRUE, 
	1, 
	MessageArray, 
	MessageSizeArray, 
	pbSignatureData, 
	&dwSignatureSize)) {
	    HandleError(_TEXT("Can't sign file '%s'.\n"), szFile);
    }
    else {
	_tprintf(_TEXT("File '%s' successfully signed.\n"), szFile);    
    }

    // Save result to file
    if (!SaveDataToFile(szSignatureFile, dwSignatureSize, pbSignatureData)) {
	HandleError(_TEXT("Can't save signature data to file '%s'.\n"), szSignatureFile);
    }
    else {
	_tprintf(_TEXT("Signature saved to file '%s'.\n"), szSignatureFile);
    }


    if (pCertCtx) {
	CertFreeCertificateContext(pCertCtx);
    }

    if (pbData) {
	free(pbData);
    }

    if (pbSignatureData) {
	free(pbSignatureData);
    }

}

void 
DoVerify(IN TCHAR *szFile,
	 IN TCHAR *szSignatureFile,
	 IN BOOL bSilent) 
{

    DWORD dwDataSize = 0;
    BYTE *pbData = NULL;

    DWORD dwSignatureSize = 0;
    BYTE *pbSignatureData = NULL;

    CRYPT_VERIFY_MESSAGE_PARA stVerifyMessagePara;
    DWORD MessageSizeArray[1];
    const BYTE *MessageArray[1];

    PCCERT_CONTEXT pSignerCertCtx = NULL;

    // Check file extension
    if (!CheckFileExtension(szFile)) {
	HandleError(_TEXT("File '%s' extension is not allowed. Allowed extensions: pdf, odt, txt, xml.\n"), szFile);
    }

    // Get file data
    if (!GetFileData(szFile, &dwDataSize, NULL)) {
	HandleError(_TEXT("Can't read file '%s'.\n"), szFile);
    }

    pbData = (BYTE*)malloc(dwDataSize * sizeof(BYTE));

    if (pbData == NULL) {
	SetLastError(ERROR_OUTOFMEMORY);
	HandleError(_TEXT("Can't allocate memory for file '%s' data.\n"), szFile);
    }

    if (!GetFileData(szFile, &dwDataSize, pbData)) {
	HandleError(_TEXT("Can't read file '%s'.\n"), szFile);
    }

    // Preview file and get user's answer
    if (!bSilent) {
	 if (!ShowPreview(szFile)) {
	    HandleError(_TEXT("Aborting by user.\n"));
	}
    }
   

    // Get signature data
    if (!GetFileData(szSignatureFile, &dwSignatureSize, NULL)) {
	HandleError(_TEXT("Can't read file '%s'.\n"), szSignatureFile);
    }

    pbSignatureData = (BYTE*)malloc(dwSignatureSize * sizeof(BYTE));

    if (pbSignatureData == NULL) {
	SetLastError(ERROR_OUTOFMEMORY);
	HandleError(_TEXT("Can't allocate memory for file '%s' data.\n"), szSignatureFile);
    }

    if (!GetFileData(szSignatureFile, &dwSignatureSize, pbSignatureData)) {
	HandleError(_TEXT("Can't read file '%s'.\n"), szSignatureFile);
    }

    // Fill structure
    ZeroMemory(&stVerifyMessagePara, sizeof(CRYPT_VERIFY_MESSAGE_PARA));
    stVerifyMessagePara.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    stVerifyMessagePara.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    stVerifyMessagePara.pfnGetSignerCertificate = NULL;
    stVerifyMessagePara.pvGetArg = NULL;

    MessageArray[0] = pbData;
    MessageSizeArray[0] = dwDataSize;

    if (!CryptVerifyDetachedMessageSignature(
	&stVerifyMessagePara, 
	0, 
	pbSignatureData, 
	dwSignatureSize, 
	1, 
	MessageArray, 
	MessageSizeArray, 
	&pSignerCertCtx)) {
	    HandleError(_TEXT("Verify file's '%s' signature failed.\n"), szFile);
    }
    else {
	_tprintf(_TEXT("Certificate:\n"));
	PrintCertInfo(pSignerCertCtx);

	// Verify certificate chain
	if (!VerifyCertificateChain(pSignerCertCtx)) {
	    HandleError(_TEXT("Verifying certificate chain failed.\n"));
	}
	else {
	    _tprintf(_TEXT("Signature '%s' for file '%s' successfully verified.\n"), szSignatureFile, szFile);
	}
    }

    if (pbData) {
	free(pbData);
    }

    if (pbSignatureData) {
	free(pbSignatureData);
    }
}

BOOL 
FindCertByName(IN TCHAR *szCertName, 
	       IN BOOL bLocalMachine, 
	       OUT PCCERT_CONTEXT *ppCertCtx) 
{

    BOOL bResult = FALSE;
    HCERTSTORE hCertStore = 0;


    hCertStore = CertOpenStore(
	CERT_STORE_PROV_SYSTEM, 
	0,			    
	0,			   
	(bLocalMachine ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER) |
	CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, 
	L"MY"	    
	);

    if (!hCertStore) {
	goto Finish;
    }

    *ppCertCtx = CertFindCertificateInStore( 
	hCertStore,
	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
	0,
	CERT_FIND_SUBJECT_STR,
	(void*)szCertName,
	NULL
	);

    if (*ppCertCtx == NULL) {
	goto Finish;
    }

    bResult = TRUE;

Finish:

    if (hCertStore) {
	CertCloseStore(hCertStore, 0);
    }

    return bResult;
}

BOOL 
GetFileData(IN TCHAR *szFile, 
	    OUT DWORD *pdwDataSize, 
	    OUT BYTE *pbData)
{
    BOOL bResult = FALSE;
    FILE *pFile = NULL;
    DWORD dwFileSize = 0;

    // Open file
    pFile = _tfopen(szFile, _TEXT("rb"));
    if (pFile == NULL) {
	switch(errno) {
	    case EACCES:
		SetLastError(ERROR_ACCESS_DENIED);
		break;
	    case ENOENT:
		SetLastError(ERROR_FILE_NOT_FOUND);
		break;
	    default:
		SetLastError(ERROR_FUNCTION_FAILED);
	}
	goto Finish;
    }

    // Get file size
    fseek(pFile, 0, SEEK_END);
    dwFileSize = ftell(pFile);

    if (pbData == NULL) {
	*pdwDataSize = dwFileSize;
	bResult = TRUE;
	goto Finish;
    }

    if (*pdwDataSize < dwFileSize) {
	*pdwDataSize = dwFileSize;
	SetLastError (ERROR_MORE_DATA);
	bResult = FALSE;
	goto Finish;
    }

    *pdwDataSize = dwFileSize;

    fseek(pFile, 0, SEEK_SET);
    fread(pbData, *pdwDataSize, 1, pFile);

    bResult = TRUE;
Finish:
    if (pFile) {
	fclose(pFile);
    }
    return bResult;
}

BOOL 
SaveDataToFile(IN TCHAR *szFile, 
	       IN DWORD dwDataSize, 
	       IN BYTE *pbData)
{
    BOOL bResult = FALSE;
    FILE *pFile = NULL;

    // Create file
    pFile = _tfopen(szFile, _TEXT("wb"));
    if (pFile == NULL) {
	switch(errno) {
	    case EACCES:
		SetLastError(ERROR_ACCESS_DENIED);
		break;
	    case ENOENT:
		SetLastError(ERROR_FILE_NOT_FOUND);
		break;
	    default:
		SetLastError(ERROR_FUNCTION_FAILED);
	}
	goto Finish;
    }

    fwrite(pbData, dwDataSize, 1, pFile);

    bResult = TRUE;
Finish:
    return bResult;
}

char* 
GetHashOidByKeyOid(IN char *szKeyOid) {

    if (strcmp(szKeyOid, szOID_CP_GOST_R3410EL) == 0) {
	return szOID_CP_GOST_R3411;
    }
    else if (strcmp(szKeyOid, szOID_CP_GOST_R3410_12_256) == 0) {
	return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(szKeyOid, szOID_CP_GOST_R3410_12_512) == 0) {
	return szOID_CP_GOST_R3411_12_512;
    }

    return NULL;
}

void
HandleError(TCHAR *format, ...) 
{
    DWORD dwError = GetLastError();
    LPVOID pMessageBuffer = NULL;

    va_list args;

    va_start(args, format);

    // Print own message
    _vtprintf(format, args);

    // Get system message
    if (!FormatMessage (
	FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
	| FORMAT_MESSAGE_IGNORE_INSERTS,
	NULL, dwError, 
	LANGUAGE,
	(LPTSTR)&pMessageBuffer, 
	0, NULL)) {
	    pMessageBuffer = NULL;
    }

    // Print system message
    if (pMessageBuffer) { 
	_tprintf (_TEXT("\nError message: %s"), (LPTSTR)pMessageBuffer);
    };

    va_end(args);

    // Print message code
    _tprintf(_TEXT("ErrorCode: 0x%08x\n"), dwError);
    _tprintf (_TEXT("Program is terminating.\n"));

    exit(dwError);
}


BOOL 
VerifyCertificateChain(PCCERT_CONTEXT pCertCtx) {

    CERT_CHAIN_POLICY_PARA	PolicyPara;
    CERT_CHAIN_POLICY_STATUS	PolicyStatus;

    CERT_CHAIN_PARA		ChainPara;
    PCCERT_CHAIN_CONTEXT	pChainContext = NULL;
    BOOL			bResult = FALSE;

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);

    if (!CertGetCertificateChain(
	NULL,
	pCertCtx,
	NULL,
	NULL,
	&ChainPara,
	CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
	NULL,
	&pChainContext)) {
	    goto Finish;
    }


    ZeroMemory(&PolicyPara, sizeof(PolicyPara));
    PolicyPara.cbSize = sizeof(PolicyPara);

    ZeroMemory(&PolicyStatus, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if (!CertVerifyCertificateChainPolicy(
	CERT_CHAIN_POLICY_BASE,
	pChainContext,
	&PolicyPara,
	&PolicyStatus)) {
	    goto Finish;
    }


    if (PolicyStatus.dwError) {
	SetLastError(PolicyStatus.dwError);
	goto Finish;
    }


    bResult = TRUE;
Finish:

    if (pChainContext) {
	CertFreeCertificateChain(pChainContext);
    }

    return bResult;
}

TCHAR* 
GetFileExtension(TCHAR *szFile) {
    TCHAR *szDot = _tcsrchr(szFile, _TEXT('.'));
    if (!szDot || szDot == szFile) return _TEXT("");
    return szDot + 1;
}

BOOL 
CheckFileExtension(TCHAR * szFile) {

    BOOL bResult = FALSE;
    int i;
    TCHAR *aAllowedExtensions[] = {
	_TEXT("odt"), _TEXT("xml"), _TEXT("txt"), _TEXT("pdf")
    };
    int cExtensions = sizeof(aAllowedExtensions) / sizeof(TCHAR *);
    TCHAR *szFileExtension = GetFileExtension(szFile);

    if ((szFileExtension == NULL) || _tcslen(szFileExtension) == 0) {
	goto Finish;
    }

    for (i = 0; i < cExtensions; i++) {
	if (!_tcsicmp(szFileExtension, aAllowedExtensions[i])) {
	    bResult = TRUE;
	    goto Finish;
	}
    }

Finish:

    if (!bResult) {
	SetLastError(ERROR_CAN_NOT_COMPLETE);
    }

    return bResult;
}


BOOL 
ShowPreview(TCHAR *szFile) {

    BOOL bResult = FALSE;
    TCHAR   szAnswer[50];

#if defined _WIN32
    ShellExecute(NULL, NULL, szFile, NULL, NULL, SW_SHOW);

    _tprintf(_TEXT("Is file correct? Yes/No\n"));
    _tcscanf(_TEXT("%s"), szAnswer);
#elif defined UNIX
    pid_t pid;
    int fd;
    pid = fork();

    if (pid == 0) {

	fd = open("/dev/null", O_WRONLY);

	dup2(fd, 1);   
	dup2(fd, 2); 

	close(fd);   
	execl("/usr/bin/xdg-open", "xdg-open", szFile, (char *)0);
    }

    printf("Is file correct? Yes/No\n");
    scanf("%s", szAnswer);
#endif

    if (_tcsicmp(szAnswer, _TEXT("Yes"))) {
	goto Finish;
    }

    bResult = TRUE;

Finish:

    return bResult;
}

void 
PrintCertInfo(PCCERT_CONTEXT pCertCtx) 
{
    TCHAR	szNameString[256];
    SYSTEMTIME	ExpireDate;

    // Name
    if (CertGetNameString(
	pCertCtx,
	CERT_NAME_SIMPLE_DISPLAY_TYPE,
	0,
	NULL,
	szNameString,
	128)) {
	    _tprintf(_TEXT("\tIssued for:\t%s \n"), szNameString);
    }


    // Issuer name
    if (CertGetNameString(
	pCertCtx,
	CERT_NAME_SIMPLE_DISPLAY_TYPE,
	CERT_NAME_ISSUER_FLAG,
	NULL,
	szNameString,
	128)) {
	    _tprintf(_TEXT("\tIssued by:\t%s \n"), szNameString);
    }


    // Expiry date
    FileTimeToSystemTime(&pCertCtx->pCertInfo->NotAfter, &ExpireDate);
    _tprintf(_TEXT("\tExpires:\t%02d.%02d.%04d %02d:%02d:%02d\n"),
	ExpireDate.wDay, ExpireDate.wMonth, ExpireDate.wYear,
	ExpireDate.wHour, ExpireDate.wMinute, ExpireDate.wSecond);
}
