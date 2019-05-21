call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.Cmd" /x86 /xp /Release
set NO_WARN=-D_X86_ -D__i386__ -Dinline=__inline -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_CRT_OBSOLETE_NO_WARNINGS

cl %NO_WARN% -W3 -O2 -I. SignUtility.c crypt32.lib advapi32.lib
