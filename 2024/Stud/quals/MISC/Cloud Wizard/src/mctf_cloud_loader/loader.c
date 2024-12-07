#include <windows.h>
#include "api.h"
#include "loader.h"

typedef struct {
    WORD   offset : 12;
    WORD   type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

FARPROC LoadPE(PUCHAR pModuleBase, const API* api) {
    if (((PIMAGE_DOS_HEADER)pModuleBase)->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS  pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PUCHAR uiBaseAddress = (PUCHAR)api->KERNEL32_VirtualAlloc(0, pNTHeader->OptionalHeader.SizeOfImage, 4096, 64);
    if (!uiBaseAddress)
        return NULL;

    PIMAGE_SECTION_HEADER pSections = ((ULONG_PTR) &pNTHeader->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i) {
        api->NTDLL_memcpy_s(uiBaseAddress + pSections[i].VirtualAddress, pNTHeader->OptionalHeader.SizeOfImage, pModuleBase + pSections[i].PointerToRawData, pSections[i].SizeOfRawData);
    }

    if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(uiBaseAddress + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress > 0) {
            PUCHAR ptr = uiBaseAddress + reloc->VirtualAddress;
            IMAGE_RELOC* relInfo = (IMAGE_RELOC*)(((size_t)reloc) + sizeof(IMAGE_BASE_RELOCATION));

            for (int x = 0; x < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC); x++, relInfo++) {
                switch (relInfo->type) {
                case IMAGE_REL_BASED_DIR64:
                    *((ULONG_PTR*)(ptr + relInfo->offset)) += (ULONG)uiBaseAddress;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *((DWORD*)(ptr + relInfo->offset)) += (DWORD)uiBaseAddress;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *((WORD*)(ptr + relInfo->offset)) += HIWORD(uiBaseAddress);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *((WORD*)(ptr + relInfo->offset)) += LOWORD(uiBaseAddress);
                    break;
                default:
                    break;
                }
            }
            reloc = (IMAGE_BASE_RELOCATION*)((PUCHAR)reloc + reloc->SizeOfBlock);
        }
    }

    IMAGE_IMPORT_DESCRIPTOR* imp_desc = (IMAGE_IMPORT_DESCRIPTOR*)(uiBaseAddress + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (int x = 0; imp_desc[x].Name; ++x) {
        FARPROC* addr;
        HMODULE handle = api->KERNEL32_LoadLibraryA((LPCSTR)(uiBaseAddress + imp_desc[x].Name));

        IMAGE_THUNK_DATA* lookupTable = (IMAGE_THUNK_DATA*)(uiBaseAddress + imp_desc[x].OriginalFirstThunk);
        IMAGE_THUNK_DATA* addressTable = (IMAGE_THUNK_DATA*)(uiBaseAddress + imp_desc[x].FirstThunk);
        for (int i = 0; lookupTable[i].u1.AddressOfData != 0; ++i) {
            DWORD_PTR lookupAddr = lookupTable[i].u1.AddressOfData;

            if ((lookupAddr & IMAGE_ORDINAL_FLAG) == 0) {
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*)(uiBaseAddress + lookupAddr);
                const char* functionName = (char*)&(image_import->Name);
                addr = (FARPROC*)api->KERNEL32_GetProcAddress(handle, functionName);
            }
            else {
                UINT functionOrdinal = (UINT)IMAGE_ORDINAL(addressTable[i].u1.Ordinal);
                addr = (FARPROC*)api->KERNEL32_GetProcAddress(handle, functionOrdinal);
            }
            addressTable[i].u1.Function = (DWORD_PTR)addr;
        }
    }

    FARPROC entry_point = (FARPROC)(uiBaseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint);
    return entry_point;
}
