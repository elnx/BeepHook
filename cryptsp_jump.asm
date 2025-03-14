
;
; created by AheadLibEx
; Author:i1tao
; Blog:https://www.cnblogs.com/0xc5
; Github:https://github.com/i1tao/AheadLibEx
;
;
; �� .asm �ļ���ӵ�����
; �Ҽ������ļ�-����-����
; ������:�Զ������ɹ���
; ���������ų�:��
;
; Ȼ����������������
; ������: ml64 /Fo $(IntDir)%(fileName).obj /c /Cp %(fileName).asm
; ���: $(IntDir)%(fileName).obj;%(Outputs)
; ���Ӷ���: ��
;
; Add the .asm file into your project.
; Right click file -> Properties -> General
; Item Type : Custom Build Tool
; Excluded From Build : No
;
; In "Custom Build Tool" Properties
; Command Line :ml64 /Fo $(IntDir)%(fileName).obj /c /Cp %(fileName).asm
; Outputs:$(IntDir)%(fileName).obj;%(Outputs)
; Link Objects:Yes

.DATA
EXTERN pfnAheadLibEx_CheckSignatureInFile:dq;
EXTERN pfnAheadLibEx_CryptAcquireContextA:dq;
EXTERN pfnAheadLibEx_CryptAcquireContextW:dq;
EXTERN pfnAheadLibEx_CryptContextAddRef:dq;
EXTERN pfnAheadLibEx_CryptCreateHash:dq;
EXTERN pfnAheadLibEx_CryptDecrypt:dq;
EXTERN pfnAheadLibEx_CryptDeriveKey:dq;
EXTERN pfnAheadLibEx_CryptDestroyHash:dq;
EXTERN pfnAheadLibEx_CryptDestroyKey:dq;
EXTERN pfnAheadLibEx_CryptDuplicateHash:dq;
EXTERN pfnAheadLibEx_CryptDuplicateKey:dq;
EXTERN pfnAheadLibEx_CryptEncrypt:dq;
EXTERN pfnAheadLibEx_CryptEnumProviderTypesA:dq;
EXTERN pfnAheadLibEx_CryptEnumProviderTypesW:dq;
EXTERN pfnAheadLibEx_CryptEnumProvidersA:dq;
EXTERN pfnAheadLibEx_CryptEnumProvidersW:dq;
EXTERN pfnAheadLibEx_CryptExportKey:dq;
EXTERN pfnAheadLibEx_CryptGenKey:dq;
EXTERN pfnAheadLibEx_CryptGenRandom:dq;
EXTERN pfnAheadLibEx_CryptGetDefaultProviderA:dq;
EXTERN pfnAheadLibEx_CryptGetDefaultProviderW:dq;
EXTERN pfnAheadLibEx_CryptGetHashParam:dq;
EXTERN pfnAheadLibEx_CryptGetKeyParam:dq;
EXTERN pfnAheadLibEx_CryptGetProvParam:dq;
EXTERN pfnAheadLibEx_CryptGetUserKey:dq;
EXTERN pfnAheadLibEx_CryptHashData:dq;
EXTERN pfnAheadLibEx_CryptHashSessionKey:dq;
EXTERN pfnAheadLibEx_CryptImportKey:dq;
EXTERN pfnAheadLibEx_CryptReleaseContext:dq;
EXTERN pfnAheadLibEx_CryptSetHashParam:dq;
EXTERN pfnAheadLibEx_CryptSetKeyParam:dq;
EXTERN pfnAheadLibEx_CryptSetProvParam:dq;
EXTERN pfnAheadLibEx_CryptSetProviderA:dq;
EXTERN pfnAheadLibEx_CryptSetProviderExA:dq;
EXTERN pfnAheadLibEx_CryptSetProviderExW:dq;
EXTERN pfnAheadLibEx_CryptSetProviderW:dq;
EXTERN pfnAheadLibEx_CryptSignHashA:dq;
EXTERN pfnAheadLibEx_CryptSignHashW:dq;
EXTERN pfnAheadLibEx_CryptVerifySignatureA:dq;
EXTERN pfnAheadLibEx_CryptVerifySignatureW:dq;
EXTERN pfnAheadLibEx_SystemFunction006:dq;
EXTERN pfnAheadLibEx_SystemFunction007:dq;
EXTERN pfnAheadLibEx_SystemFunction008:dq;
EXTERN pfnAheadLibEx_SystemFunction009:dq;
EXTERN pfnAheadLibEx_SystemFunction010:dq;
EXTERN pfnAheadLibEx_SystemFunction011:dq;
EXTERN pfnAheadLibEx_SystemFunction012:dq;
EXTERN pfnAheadLibEx_SystemFunction013:dq;
EXTERN pfnAheadLibEx_SystemFunction014:dq;
EXTERN pfnAheadLibEx_SystemFunction015:dq;
EXTERN pfnAheadLibEx_SystemFunction016:dq;
EXTERN pfnAheadLibEx_SystemFunction018:dq;
EXTERN pfnAheadLibEx_SystemFunction020:dq;
EXTERN pfnAheadLibEx_SystemFunction021:dq;
EXTERN pfnAheadLibEx_SystemFunction022:dq;
EXTERN pfnAheadLibEx_SystemFunction023:dq;
EXTERN pfnAheadLibEx_SystemFunction024:dq;
EXTERN pfnAheadLibEx_SystemFunction025:dq;
EXTERN pfnAheadLibEx_SystemFunction026:dq;
EXTERN pfnAheadLibEx_SystemFunction027:dq;
EXTERN pfnAheadLibEx_SystemFunction030:dq;
EXTERN pfnAheadLibEx_SystemFunction031:dq;
EXTERN pfnAheadLibEx_SystemFunction032:dq;
EXTERN pfnAheadLibEx_SystemFunction033:dq;
EXTERN pfnAheadLibEx_SystemFunction035:dq;

.CODE
AheadLibEx_CheckSignatureInFile PROC
	jmp pfnAheadLibEx_CheckSignatureInFile
AheadLibEx_CheckSignatureInFile ENDP

AheadLibEx_CryptAcquireContextA PROC
	jmp pfnAheadLibEx_CryptAcquireContextA
AheadLibEx_CryptAcquireContextA ENDP

AheadLibEx_CryptAcquireContextW PROC
	jmp pfnAheadLibEx_CryptAcquireContextW
AheadLibEx_CryptAcquireContextW ENDP

AheadLibEx_CryptContextAddRef PROC
	jmp pfnAheadLibEx_CryptContextAddRef
AheadLibEx_CryptContextAddRef ENDP

AheadLibEx_CryptCreateHash PROC
	jmp pfnAheadLibEx_CryptCreateHash
AheadLibEx_CryptCreateHash ENDP

AheadLibEx_CryptDecrypt PROC
	jmp pfnAheadLibEx_CryptDecrypt
AheadLibEx_CryptDecrypt ENDP

AheadLibEx_CryptDeriveKey PROC
	jmp pfnAheadLibEx_CryptDeriveKey
AheadLibEx_CryptDeriveKey ENDP

AheadLibEx_CryptDestroyHash PROC
	jmp pfnAheadLibEx_CryptDestroyHash
AheadLibEx_CryptDestroyHash ENDP

AheadLibEx_CryptDestroyKey PROC
	jmp pfnAheadLibEx_CryptDestroyKey
AheadLibEx_CryptDestroyKey ENDP

AheadLibEx_CryptDuplicateHash PROC
	jmp pfnAheadLibEx_CryptDuplicateHash
AheadLibEx_CryptDuplicateHash ENDP

AheadLibEx_CryptDuplicateKey PROC
	jmp pfnAheadLibEx_CryptDuplicateKey
AheadLibEx_CryptDuplicateKey ENDP

AheadLibEx_CryptEncrypt PROC
	jmp pfnAheadLibEx_CryptEncrypt
AheadLibEx_CryptEncrypt ENDP

AheadLibEx_CryptEnumProviderTypesA PROC
	jmp pfnAheadLibEx_CryptEnumProviderTypesA
AheadLibEx_CryptEnumProviderTypesA ENDP

AheadLibEx_CryptEnumProviderTypesW PROC
	jmp pfnAheadLibEx_CryptEnumProviderTypesW
AheadLibEx_CryptEnumProviderTypesW ENDP

AheadLibEx_CryptEnumProvidersA PROC
	jmp pfnAheadLibEx_CryptEnumProvidersA
AheadLibEx_CryptEnumProvidersA ENDP

AheadLibEx_CryptEnumProvidersW PROC
	jmp pfnAheadLibEx_CryptEnumProvidersW
AheadLibEx_CryptEnumProvidersW ENDP

AheadLibEx_CryptExportKey PROC
	jmp pfnAheadLibEx_CryptExportKey
AheadLibEx_CryptExportKey ENDP

AheadLibEx_CryptGenKey PROC
	jmp pfnAheadLibEx_CryptGenKey
AheadLibEx_CryptGenKey ENDP

AheadLibEx_CryptGenRandom PROC
	jmp pfnAheadLibEx_CryptGenRandom
AheadLibEx_CryptGenRandom ENDP

AheadLibEx_CryptGetDefaultProviderA PROC
	jmp pfnAheadLibEx_CryptGetDefaultProviderA
AheadLibEx_CryptGetDefaultProviderA ENDP

AheadLibEx_CryptGetDefaultProviderW PROC
	jmp pfnAheadLibEx_CryptGetDefaultProviderW
AheadLibEx_CryptGetDefaultProviderW ENDP

AheadLibEx_CryptGetHashParam PROC
	jmp pfnAheadLibEx_CryptGetHashParam
AheadLibEx_CryptGetHashParam ENDP

AheadLibEx_CryptGetKeyParam PROC
	jmp pfnAheadLibEx_CryptGetKeyParam
AheadLibEx_CryptGetKeyParam ENDP

AheadLibEx_CryptGetProvParam PROC
	jmp pfnAheadLibEx_CryptGetProvParam
AheadLibEx_CryptGetProvParam ENDP

AheadLibEx_CryptGetUserKey PROC
	jmp pfnAheadLibEx_CryptGetUserKey
AheadLibEx_CryptGetUserKey ENDP

AheadLibEx_CryptHashData PROC
	jmp pfnAheadLibEx_CryptHashData
AheadLibEx_CryptHashData ENDP

AheadLibEx_CryptHashSessionKey PROC
	jmp pfnAheadLibEx_CryptHashSessionKey
AheadLibEx_CryptHashSessionKey ENDP

AheadLibEx_CryptImportKey PROC
	jmp pfnAheadLibEx_CryptImportKey
AheadLibEx_CryptImportKey ENDP

AheadLibEx_CryptReleaseContext PROC
	jmp pfnAheadLibEx_CryptReleaseContext
AheadLibEx_CryptReleaseContext ENDP

AheadLibEx_CryptSetHashParam PROC
	jmp pfnAheadLibEx_CryptSetHashParam
AheadLibEx_CryptSetHashParam ENDP

AheadLibEx_CryptSetKeyParam PROC
	jmp pfnAheadLibEx_CryptSetKeyParam
AheadLibEx_CryptSetKeyParam ENDP

AheadLibEx_CryptSetProvParam PROC
	jmp pfnAheadLibEx_CryptSetProvParam
AheadLibEx_CryptSetProvParam ENDP

AheadLibEx_CryptSetProviderA PROC
	jmp pfnAheadLibEx_CryptSetProviderA
AheadLibEx_CryptSetProviderA ENDP

AheadLibEx_CryptSetProviderExA PROC
	jmp pfnAheadLibEx_CryptSetProviderExA
AheadLibEx_CryptSetProviderExA ENDP

AheadLibEx_CryptSetProviderExW PROC
	jmp pfnAheadLibEx_CryptSetProviderExW
AheadLibEx_CryptSetProviderExW ENDP

AheadLibEx_CryptSetProviderW PROC
	jmp pfnAheadLibEx_CryptSetProviderW
AheadLibEx_CryptSetProviderW ENDP

AheadLibEx_CryptSignHashA PROC
	jmp pfnAheadLibEx_CryptSignHashA
AheadLibEx_CryptSignHashA ENDP

AheadLibEx_CryptSignHashW PROC
	jmp pfnAheadLibEx_CryptSignHashW
AheadLibEx_CryptSignHashW ENDP

AheadLibEx_CryptVerifySignatureA PROC
	jmp pfnAheadLibEx_CryptVerifySignatureA
AheadLibEx_CryptVerifySignatureA ENDP

AheadLibEx_CryptVerifySignatureW PROC
	jmp pfnAheadLibEx_CryptVerifySignatureW
AheadLibEx_CryptVerifySignatureW ENDP

AheadLibEx_SystemFunction006 PROC
	jmp pfnAheadLibEx_SystemFunction006
AheadLibEx_SystemFunction006 ENDP

AheadLibEx_SystemFunction007 PROC
	jmp pfnAheadLibEx_SystemFunction007
AheadLibEx_SystemFunction007 ENDP

AheadLibEx_SystemFunction008 PROC
	jmp pfnAheadLibEx_SystemFunction008
AheadLibEx_SystemFunction008 ENDP

AheadLibEx_SystemFunction009 PROC
	jmp pfnAheadLibEx_SystemFunction009
AheadLibEx_SystemFunction009 ENDP

AheadLibEx_SystemFunction010 PROC
	jmp pfnAheadLibEx_SystemFunction010
AheadLibEx_SystemFunction010 ENDP

AheadLibEx_SystemFunction011 PROC
	jmp pfnAheadLibEx_SystemFunction011
AheadLibEx_SystemFunction011 ENDP

AheadLibEx_SystemFunction012 PROC
	jmp pfnAheadLibEx_SystemFunction012
AheadLibEx_SystemFunction012 ENDP

AheadLibEx_SystemFunction013 PROC
	jmp pfnAheadLibEx_SystemFunction013
AheadLibEx_SystemFunction013 ENDP

AheadLibEx_SystemFunction014 PROC
	jmp pfnAheadLibEx_SystemFunction014
AheadLibEx_SystemFunction014 ENDP

AheadLibEx_SystemFunction015 PROC
	jmp pfnAheadLibEx_SystemFunction015
AheadLibEx_SystemFunction015 ENDP

AheadLibEx_SystemFunction016 PROC
	jmp pfnAheadLibEx_SystemFunction016
AheadLibEx_SystemFunction016 ENDP

AheadLibEx_SystemFunction018 PROC
	jmp pfnAheadLibEx_SystemFunction018
AheadLibEx_SystemFunction018 ENDP

AheadLibEx_SystemFunction020 PROC
	jmp pfnAheadLibEx_SystemFunction020
AheadLibEx_SystemFunction020 ENDP

AheadLibEx_SystemFunction021 PROC
	jmp pfnAheadLibEx_SystemFunction021
AheadLibEx_SystemFunction021 ENDP

AheadLibEx_SystemFunction022 PROC
	jmp pfnAheadLibEx_SystemFunction022
AheadLibEx_SystemFunction022 ENDP

AheadLibEx_SystemFunction023 PROC
	jmp pfnAheadLibEx_SystemFunction023
AheadLibEx_SystemFunction023 ENDP

AheadLibEx_SystemFunction024 PROC
	jmp pfnAheadLibEx_SystemFunction024
AheadLibEx_SystemFunction024 ENDP

AheadLibEx_SystemFunction025 PROC
	jmp pfnAheadLibEx_SystemFunction025
AheadLibEx_SystemFunction025 ENDP

AheadLibEx_SystemFunction026 PROC
	jmp pfnAheadLibEx_SystemFunction026
AheadLibEx_SystemFunction026 ENDP

AheadLibEx_SystemFunction027 PROC
	jmp pfnAheadLibEx_SystemFunction027
AheadLibEx_SystemFunction027 ENDP

AheadLibEx_SystemFunction030 PROC
	jmp pfnAheadLibEx_SystemFunction030
AheadLibEx_SystemFunction030 ENDP

AheadLibEx_SystemFunction031 PROC
	jmp pfnAheadLibEx_SystemFunction031
AheadLibEx_SystemFunction031 ENDP

AheadLibEx_SystemFunction032 PROC
	jmp pfnAheadLibEx_SystemFunction032
AheadLibEx_SystemFunction032 ENDP

AheadLibEx_SystemFunction033 PROC
	jmp pfnAheadLibEx_SystemFunction033
AheadLibEx_SystemFunction033 ENDP

AheadLibEx_SystemFunction035 PROC
	jmp pfnAheadLibEx_SystemFunction035
AheadLibEx_SystemFunction035 ENDP


END
