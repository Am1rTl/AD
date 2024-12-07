
Задача основана на образцах из статьи https://securelist.ru/cloudsorcerer-new-apt-cloud-actor/109861/

Для решения дано 4 файла:
- `dbgsrv.exe` - легитимный файл, есть цифровая подпись Microsoft.
- `dbgeng.dll` - "вредоносная" DLL, фактически переписанный загрузчик, который использовался злоумышленниками. Используется для Sideloading'а (за счет dbgsrv.exe).
- `user.cfg` - зашифрованная полезная нагрузка, выводит окно с флагом. Файл был максимально уменьшен до 2 кб, чтобы перебор был крайне быстрым.
- `g.exe` - вспомогательная утилита для получения значения GetTickCount и его зашифрования с помощью DPAPI. Использовалась злоумышленниками для создания зашифрованной полезной нагрузки.

Из анализа библиотеки-загрузчика (dbgeng.dll) можно получить структуру зашифрованного файла:
```C
struct Payload {
    unsigned int uncompressed_len;
    unsigned int compressed_len;
    unsigned int encrypted_key_len;
    char data[compressed_len];
};
```

Загрузчик пытается расшифровать основной ключ (первые `encrypted_key_len` байтов массива `data`) с использованием DPAPI - `CryptUnprotectData` и флага `CRYPTPROTECT_LOCAL_MACHINE`. Из-за использования DPAPI данные (основной ключ) могут быть расшифрованы только на том компьютере, где были зашифрованы.

Однако, если посмотреть на дальнейшее шифрование на расшифрованном ключе, обнаруживается, что это простой циклический XOR с ключом размера 4 байта:
```C
plain[k] = encrypted[k] ^ key.pbData[(k + 1) % 4];
```

После расшифрования выполняется вызов `RtlDecompressBuffer` с режимом LZNT1.

Полученное содержимое (PE-файл с присутствующими сигнатурами `MZ` и `PE`) загружается с помощью встроенного Reflective-загрузчика.

Таким образом, восстановив несложный алгоритм, понимаем что нужно написать переборщик для 4 байтов ключа.

Изучив файл файл g.exe понимаем, что ключ генерировался с использованием функции `GetTickCount`. 
Функция возвращает количество миллисекунд, прошедших с момента запуска системы (до 49,7 дней). 
В условии задачи написано "стоило только на пару дней запустить наш новый сервер",
получается нужно перебирать значения в диапазоне около 2-го дня, что в разы облегчает задачу.

Алгоритм перебора может быть реализован следующим образом (смотреть исходники для более полного примера):
```C
struct Payload* payload = ReadPayload(L"encrypted.bin");

PUCHAR plain = (PUCHAR)VirtualAlloc(0, payload->compressed_len, MEM_COMMIT, PAGE_READWRITE);
PUCHAR uncompressed = (PUCHAR)VirtualAlloc(0, payload->uncompressed_len, MEM_COMMIT, PAGE_READWRITE);
const BYTE *encrypted = &payload->data + payload->encrypted_key_len;
    
for (DWORD key = 0; key < 3*24*3600*1000; ++key) {
	for (size_t i = 0; i < payload->data_len; ++i) {
		plain[i] = encrypted[i] ^ ((BYTE*)&key)[(i + 1) % 4];
	}

	ULONG final_size = 0;
	NTSTATUS status = pfnRtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, uncompressed, payload->uncompressed_len, plain, payload->data_len, &final_size);
	if (status == STATUS_SUCCESS && uncompressed[0] == 0x4D && uncompressed[1] == 0x5A) {
		printf(L"SUCCESS! 0x%X\n", key);
		WritePayload(L"decrypted.bin", uncompressed, payload->uncompressed_len);
		break;
	}
}
```
Флаг: `MCTF{APTs_d0_n0t_us3_weak_3ncrypt1on}`