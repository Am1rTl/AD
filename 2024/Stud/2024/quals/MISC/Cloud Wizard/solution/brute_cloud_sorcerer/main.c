#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

#define STATUS_SUCCESS      0
#define NUMBER_OF_THREADS   8
#define NUMBER_OF_ROUNDS    50
#define OUTPUT_INTERVAL     100000

int _fltused = 0;


struct Payload {
  ULONG uncompressed_len;
  ULONG data_len;
  ULONG encrypted_key_len;
  BYTE data;
};

struct Task {
    HANDLE h_thread;
    LPCRITICAL_SECTION lock;
    struct Payload * payload;
    DWORD key_min;
    DWORD key_max;
    DWORD worker_number;
    DWORD cursor_offset_Y;
};

typedef NTSTATUS WINAPI OB_COMPRESSED_RtlDecompressBuffer(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG  UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG  CompressedBufferSize,
    PULONG FinalUncompressedSize
);

static OB_COMPRESSED_RtlDecompressBuffer *pfnRtlDecompressBuffer = NULL;

static void my_printf(const WCHAR* format, ...) {
    va_list args;
    WCHAR buffer[1024];
    va_start(args, format);
    wvsprintfW(buffer, format, args);
    DWORD written = 0;
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buffer, lstrlenW(buffer), &written, NULL);
    va_end(args);
}

VOID WritePayload(const WCHAR* filename, const BYTE* data, const ULONG data_len) {
    HANDLE hFile = CreateFileW(
            filename,
            GENERIC_WRITE,
            FILE_SHARE_WRITE,
            NULL,
            CREATE_ALWAYS,
            0,
            NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        my_printf(L"Can't open file!\n");
        TerminateProcess(GetCurrentProcess(), -1);
    }

    DWORD num_written = 0;
    WriteFile(hFile, (LPVOID)data, data_len, &num_written, NULL);
    CloseHandle(hFile);
}

struct Payload* ReadPayload(const LPWSTR filename, DWORD* total_size) {
    HANDLE hFile = CreateFileW(
        filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0u,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        my_printf(L"Can't open file!\n");
        TerminateProcess(GetCurrentProcess(), -1);
    }

    *total_size = GetFileSize(hFile, NULL);
    struct Payload* payload = (PVOID)VirtualAlloc(0, *total_size, MEM_COMMIT, PAGE_READWRITE);
    DWORD num_read = 0;
    ReadFile(hFile, (LPVOID)payload, *total_size, &num_read, NULL);
    CloseHandle(hFile);

    return payload;
}

void BruteforceThread(void * arg) {
    struct Task* task = (struct Task*)arg;
    struct Payload* payload = task->payload;

    PUCHAR plain = (PUCHAR)VirtualAlloc(0, payload->data_len, MEM_COMMIT, PAGE_READWRITE);
	PUCHAR uncompressed = (PUCHAR)VirtualAlloc(0, payload->uncompressed_len, MEM_COMMIT, PAGE_READWRITE);

    const BYTE *encrypted = &payload->data + payload->encrypted_key_len;

    DWORD tid = GetCurrentThreadId();
    const COORD thread_coord = { 0, task->cursor_offset_Y };
    const COORD end_coord = { 0, task->cursor_offset_Y + NUMBER_OF_THREADS - task->worker_number };

    DWORD prev_key = task->key_min;
    DWORD prev_time = GetTickCount();
    DWORD current_time = 0;

    for (DWORD key = task->key_min; key < task->key_max; ++key) {
        if ((key - task->key_min) % OUTPUT_INTERVAL == 0) {
            current_time = GetTickCount();
            float speed = (key - prev_key) / ((current_time - prev_time) / 1000 + 1) + 1;
            int remaining = (task->key_max - key) / speed;
            EnterCriticalSection(task->lock);
            SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), thread_coord);
            my_printf(L"[%04d] 0x%08X-0x%08X %10ds\n", tid, task->key_min, task->key_max, remaining);
            SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), end_coord);
            LeaveCriticalSection(task->lock);
            prev_time = current_time;
            prev_key = key;
        }

        for (size_t i = 0; i < payload->data_len; ++i) {
            plain[i] = encrypted[i] ^ ((BYTE*)&key)[(i + 1) % 4];
        }

        ULONG final_size = 0;
        NTSTATUS status = pfnRtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, uncompressed, payload->uncompressed_len, plain, payload->data_len, &final_size);
        if (status == STATUS_SUCCESS && uncompressed[0] == 0x4D && uncompressed[1] == 0x5A && uncompressed[2] == 0x90) {
            EnterCriticalSection(task->lock);
            SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), thread_coord);
            my_printf(L"[%04d] SUCCESS! Key %X                 \n", tid, key);
            WritePayload(L"decrypted.bin", uncompressed, payload->uncompressed_len);
            SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), end_coord);
            TerminateProcess(GetCurrentProcess(), 0);
            LeaveCriticalSection(task->lock);
            break;
        }

    }
    VirtualFree(uncompressed, 0, MEM_RELEASE);
    VirtualFree(plain, 0, MEM_RELEASE);
    VirtualFree(payload, 0, MEM_RELEASE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), &argc);

    if (argc < 2) {
        my_printf(L"Usage: program [encrypted payload file name]\n");
        TerminateProcess(GetCurrentProcess(), 0);
    }

    if(!pfnRtlDecompressBuffer) {
        HMODULE hNtDll = LoadLibraryA("ntdll.dll");
        pfnRtlDecompressBuffer = (OB_COMPRESSED_RtlDecompressBuffer *)GetProcAddress(hNtDll, "RtlDecompressBuffer");
        if (!pfnRtlDecompressBuffer) {
            my_printf(L"Can't load RtlDecompressBuffer!\n");
            TerminateProcess(GetCurrentProcess(), -1);
        }
    }

    DWORD payload_total_len = 0;
    struct Payload* payload = ReadPayload(argv[1], &payload_total_len);
    my_printf(L"payload->encrypted_key_len: %d\n", payload->encrypted_key_len);
    my_printf(L"payload->data_len: %d\n\n", payload->data_len);
        
    CRITICAL_SECTION lock = { 0 };
    InitializeCriticalSection(&lock);
    
    struct Task tasks[NUMBER_OF_THREADS];
    for (size_t round = 0; round < NUMBER_OF_ROUNDS; ++round) {
        my_printf(L"ROUND %d/%d\n", round + 1, NUMBER_OF_ROUNDS);
        const size_t round_min = (0xFFFFFFFF / NUMBER_OF_ROUNDS) * round;
        const size_t round_max = (0xFFFFFFFF / NUMBER_OF_ROUNDS) * (round + 1);

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);

        for (size_t i = 0; i < (sizeof(tasks) / sizeof(struct Task)); ++i) {
            tasks[i].key_min = round_min + ((round_max - round_min) / NUMBER_OF_THREADS) * i;
            tasks[i].key_max = round_min + ((round_max - round_min) / NUMBER_OF_THREADS) * (i + 1);
            tasks[i].worker_number = i;
            tasks[i].cursor_offset_Y = csbi.dwCursorPosition.Y + i;
            tasks[i].lock = &lock;
            struct Payload * payload_copy = (PVOID)VirtualAlloc(0, payload_total_len, MEM_COMMIT, PAGE_READWRITE);
            size_t copied = 0;
            WriteProcessMemory(GetCurrentProcess(), payload_copy, payload, payload_total_len, &copied);
            tasks[i].payload = payload_copy;
            DWORD tid;
            tasks[i].h_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)BruteforceThread, &tasks[i], 0, &tid);
            Sleep(500);
        }

        for (int i = 0; i < (sizeof(tasks) / sizeof(struct Task)); ++i) {
            WaitForSingleObject(tasks[i].h_thread, INFINITE);
            VirtualFree(tasks[i].payload, 0, MEM_RELEASE);
        }
        my_printf(L"\n\n");
    }

    DeleteCriticalSection(&lock);

    return 0;
}
