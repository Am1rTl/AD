// gcc -s -Lcrypt32 -static -static-libgcc -O3 -o packer.exe .\packer.c
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (WINAPI *RtlGetCompressionWorkSpaceSize_t)(
  USHORT                 CompressionFormatAndEngine,
  PULONG                 CompressBufferWorkSpaceSize,
  PULONG                 CompressFragmentWorkSpaceSize);

typedef NTSTATUS (WINAPI *RtlCompressBuffer_t)(
  USHORT                 CompressionFormatAndEngine,
  PUCHAR                 UncompressedBuffer,
  ULONG                  UncompressedBufferSize,
  PUCHAR                 CompressedBuffer,
  ULONG                  CompressedBufferSize,
  ULONG                  UncompressedChunkSize,
  PULONG                 FinalCompressedSize,
  PVOID                  WorkSpace);

typedef struct _UNICODE_STRING {
  unsigned short length;
  unsigned short maxLength;
  unsigned char Reserved[4];
  wchar_t *buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct __unaligned __declspec(align(1)) {
  unsigned int uncompressed_len;
  unsigned int data_len;
  unsigned int data_offset;
  BYTE data;
} Payload, *PPayload;

void ReadFileContent(const char *filepath, char *content, size_t *content_len) {
  HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("No such file: %s\n", filepath);
    exit(0);
  }

  GetFileSize(hFile, &content_len);
  content = VirtualAlloc(NULL, content_len, MEM_COMMIT, PAGE_READWRITE);
  DWORD num_read = 0;
  ReadFile(hFile, content, content_len, &num_read, NULL);
  CloseHandle(hFile);
}

void WriteFileContent(const char *filepath, char *content, size_t *content_len) {
  HANDLE hFile = CreateFileA(filepath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("Can't create file: %s\n", filepath);
    exit(0);
  }

  DWORD num_written = 0;
  WriteFile(hFile, content, content_len, &num_written, NULL);
  CloseHandle(hFile);
}

int main(const int argc, const char *argv[]) {
  if (argc < 3) {
    printf("%s [plain filepath] [encrypted filepath]\n", argv[0]);
    exit(0);
  }

  char * content;
  size_t content_len = 0;
  ReadFileContent(argv[1], content, &content_len);

  Payload * payload = NULL;
  size_t payload_len = 0;
  CompressAndEncrypt(content, content_len, payload, &payload_len);

  WriteFileContent(argv[2], payload, payload_len);
}

unsigned int GenerateRandInt(const unsigned int min, const unsigned int max) {
  HCRYPTPROV hProvider;
  unsigned int rand_value = 0;
  if (CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) != 0) {
    if (CryptGenRandom(hProvider, 4, &rand_value) != 0) {
      printf("Can't generate random key\n");
      return 1;
    }
    CryptReleaseContext(hProvider, 0);
    rand_value %= (max - min);
    rand_value += min;
  }
}

NTSTATUS Lznt1Compress(
  PUCHAR UncompressedBuffer,
  ULONG UncompressedBufferSize,
  PUCHAR CompressedBuffer,
  ULONG CompressedBufferSize,
  PULONG FinalCompressedSize
) {
  HMODULE hNtdll = LoadLibrary("ntdll.dll");
  if (hNtdll == NULL) {
      printf("Failed to load ntdll.dll\n");
      return 1;
  }

  RtlCompressBuffer_t RtlCompressBuffer = (RtlCompressBuffer_t)GetProcAddress(hNtdll, "RtlCompressBuffer");
  if (RtlCompressBuffer == NULL) {
      printf("Failed to get RtlCompressBuffer address\n");
      FreeLibrary(hNtdll);
      return 1;
  }

  RtlGetCompressionWorkSpaceSize_t RtlGetCompressionWorkSpaceSize = (RtlGetCompressionWorkSpaceSize_t)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");
  if (RtlGetCompressionWorkSpaceSize == NULL) {
      printf("Failed to get RtlGetCompressionWorkSpaceSize address\n");
      FreeLibrary(hNtdll);
      return 1;
  }

  ULONG wspace, fspace;
  RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &wspace, &fspace);

  char * WorkSpace = VirtualAlloc(NULL, wspace, MEM_COMMIT, PAGE_READWRITE);

  NTSTATUS status = RtlCompressBuffer(
    COMPRESSION_FORMAT_LZNT1,
    UncompressedBuffer,
    UncompressedBufferSize,
    CompressedBuffer,
    CompressedBufferSize,
    4096,
    FinalCompressedSize,
    WorkSpace);

  VirtualFree(WorkSpace, 0, MEM_RELEASE);
  return status;
}

int CompressAndEncrypt(unsigned char *src, const size_t src_len, Payload *dst, size_t *dst_len) {
  unsigned char * compressed_buffer = VirtualAlloc(NULL, src_len, MEM_COMMIT, PAGE_READWRITE);
  ULONG final_compressed_size = 0;
	NTSTATUS status = Lznt1Compress(src, src_len, compressed_buffer, src_len, &final_compressed_size);

  int rand_offset = GenerateRandInt(16, 160);
  dst_len = src_len + rand_offset + 3 * sizeof(unsigned int);
  Payload *payload = VirtualAlloc(NULL, dst_len, MEM_COMMIT, PAGE_READWRITE);
  payload->uncompressed_len = src_len;
  payload->data_len = final_compressed_size;
  payload->data_offset = rand_offset;

  int rand_key = GenerateRandInt(0, 0x1FFFFFFF);
  DATA_BLOB plain_key = {sizeof(rand_key) &rand_key};
  DATA_BLOB encrypted_key = {payload->data_offset &payload->data};
  CryptProtectData(&plain_key, NULL, NULL, NULL, NULL, 4, &encrypted_key);

  char *encrypted = &payload->data + payload->data_offset;
  for (unsigned int k = 0; k < payload->data_len; ++k) {
    encrypted[k] = compressed_buffer[k] ^ plain_key.pbData[(k + 1) % 4];
  }

  return 0;
}
