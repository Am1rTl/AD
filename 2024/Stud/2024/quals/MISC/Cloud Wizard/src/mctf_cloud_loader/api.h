#pragma once

typedef struct {
    void(__stdcall* KERNEL32_ExitProcess)(UINT);
    HMODULE(__stdcall* KERNEL32_LoadLibraryA)(LPCSTR);
    FARPROC(__stdcall* KERNEL32_GetProcAddress)(HMODULE, LPCSTR);
    LPVOID(__stdcall* KERNEL32_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    NTSTATUS(__stdcall* NTDLL_RtlDecompressBuffer)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
    void* (__stdcall* NTDLL_memcpy_s)(void*, size_t, const void*, size_t);
    HANDLE(__stdcall* CRYPT32_CryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
} API;

typedef struct _UNICODE_STRING {
    unsigned short length;
    unsigned short maxLength;
    unsigned char Reserved[4];
    wchar_t* buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOL Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, * PMY_PEB_LDR_DATA;

typedef struct _PEB {
    unsigned char InheritedAddressSpace;
    unsigned char ReadImageFileExecOptions;
    unsigned char BeginDebugged;
    unsigned char Reserved[5];
    VOID* Mutant;
    VOID* ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
} PEB, * PPEB;

enum HASH_CONSTS {
    KERNEL32_VirtualAlloc = 0x13C66F8A,
    KERNEL32_LoadLibraryA = 0xA97F1DF9,
    KERNEL32_GetProcAddress = 0xD8C0B5A5,
    KERNEL32_ExitProcess = 0xE74A77C1,
    NTDLL_RtlDecompressBuffer = 0xAB635A8A,
    NTDLL_memcpy_s = 0x1182BB20,
    CRYPT32_CryptUnprotectData = 0xFC71F850,
};

#define ROR(x,y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))


void ResolveApi(API* api);