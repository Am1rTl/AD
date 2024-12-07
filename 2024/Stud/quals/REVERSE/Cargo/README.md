# Reverse | Hard | Cargo

## Description
![](description.jpeg)

## Writeup

Посмотрим на псевдокод, сгенерированный IDA Pro:

```cpp
// main.main
void __fastcall main_main()
{
    __int64 v0; // r14
    char v1; // al
    void *retaddr; // [rsp+0h] [rbp+0h] BYREF

    while ( (unsigned __int64)&retaddr <= *(_QWORD *)(v0 + 16) )
        runtime_morestack_noctxt();
    if ( os_Args.len != 2 )
        os_Exit(1LL);
    if ( os_Args.len <= 1uLL )
        runtime_panicIndex();
    if ( strings_Map(mapping, *(string *)(*(_QWORD *)&os_Args + 16LL)).len == 50 && (runtime_memequal(), v1) )
        os_Exit(0LL);
    else
        os_Exit(1LL);
}
```

Анализ приведенного выше псевдокода:

1. В первом аргументе должен быть флаг (аргумент должен быть один).
2. Функция `strings_Map` перемешивает флаг с помощью функции `mapping`, также известной как `main_main_func1`.
3. Перемешанный флаг сравнивается с эталонным значением (`p8xsi8dlba61rb9q0obhpr8qhbhuojrjqrjqshr1uoqjrpmu6g`).
4. Результат сравнения возвращается в виде exit code (ноль означает, что флаг верен, любое другое значение говорит об
   обратном).

```cpp
// main.main.func1
int32 __golang main_main_func1(int32 r)
{
    __int64 v1; // r14
    retval_40E380 v2; // kr00_16
    void *retaddr; // [rsp+0h] [rbp+0h] BYREF
    int32 ra; // [rsp+8h] [rbp+8h]
    int32 rb; // [rsp+8h] [rbp+8h]

    while ( (unsigned __int64)&retaddr <= *(_QWORD *)(v1 + 16) )
    {
        rb = r;
        runtime_morestack_noctxt();
        r = rb;
    }
    ra = r;
    v2 = runtime_mapaccess2_fast32(
             (internal_abi_MapType *)&RTYPE_map_int32_int32_0,
             (runtime_hmap *)main_lookupTable,
             r);
    if ( v2._r1 )
        return *(_DWORD *)v2._r0;
    else
        return ra;
}
```

В этой функции можно заметить переменную `main_lookupTable` типа `runtime_hmap*`, которая является таблицей подстановок
и инициализируется в функции `main_map_init_0`, давайте перейдем к ней.

```cpp
// main.map.init.0
void __golang main_map_init_0()
{
    __int64 v0; // r14
    runtime_hmap *v1; // rax
    __int64 v2; // rcx
    runtime_hmap **v3; // r11
    int v4; // [rsp+0h] [rbp-1Ch]
    __int64 v5; // [rsp+4h] [rbp-18h]
    runtime_hmap *v6; // [rsp+Ch] [rbp-10h]
    void *retaddr; // [rsp+1Ch] [rbp+0h] BYREF

    while ( (unsigned __int64)&retaddr <= *(_QWORD *)(v0 + 16) )
        runtime_morestack_noctxt();
    v1 = runtime_makemap((internal_abi_MapType *)&RTYPE_map_int32_int32_0, 39LL, 0LL);
    v6 = v1;
    v2 = 0LL;
    while ( v2 < 39 )
    {
        v5 = v2;
        v4 = dword_49596C[v2];
        *(_DWORD *)runtime_mapassign_fast32((internal_abi_MapType *)&RTYPE_map_int32_int32_0, v1, dword_4958D0[v2]) = v4;
        v2 = v5 + 1;
        v1 = v6;
    }
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
        runtime_gcWriteBarrier2();
        *v3 = v1;
        v3[1] = (runtime_hmap *)main_lookupTable;
    }
    main_lookupTable = (map_int32_int32)v1;
}
```

```
.rodata:00000000004958CE                 db    0
.rodata:00000000004958CF                 db    0
.rodata:00000000004958D0 ; _DWORD dword_4958D0[39]
.rodata:00000000004958D0 dword_4958D0    dd 76h, 6Ah, 74h, 7Dh, 79h, 7Ah, 69h, 68h, 6Eh, 63h, 6Dh
.rodata:00000000004958D0                                         ; DATA XREF: main_map_init_0+41↑o
.rodata:00000000004958FC                 dd 61h, 6Ch, 5Fh, 30h, 66h, 32h, 33h, 31h, 39h, 72h, 36h
.rodata:0000000000495928                 dd 6Bh, 73h, 64h, 71h, 75h, 37h, 70h, 38h, 62h, 34h, 7Bh
.rodata:0000000000495954                 dd 65h, 6Fh, 67h, 78h, 35h, 77h
.rodata:000000000049596C ; _DWORD dword_49596C[45]
.rodata:000000000049596C dword_49596C    dd 77h, 35h, 78h, 67h, 6Fh, 65h, 7Bh, 34h, 62h, 38h, 70h
.rodata:000000000049596C                                         ; DATA XREF: main_map_init_0+33↑o
.rodata:0000000000495998                 dd 37h, 75h, 71h, 64h, 73h, 6Bh, 36h, 72h, 39h, 31h, 33h
.rodata:00000000004959C4                 dd 32h, 66h, 30h, 5Fh, 6Ch, 61h, 6Dh, 63h, 6Eh, 68h, 69h
.rodata:00000000004959F0                 dd 7Ah, 79h, 7Dh, 74h, 6Ah, 76h, 6 dup(0)
.rodata:0000000000495A20 jpt_407B19      dq offset loc_407B1C    ; DATA XREF: runtime_printanycustomtype+52↑o
.rodata:0000000000495A20                                         ; runtime_printanycustomtype+59↑r
```

В функции есть два массива, один массив ключей, другой массив значений, оба используются для инициализации переменной
`main_lookupTable`. Экспортируем массивы и пишем программу, которая из перемешанного флага сделает нам исходный флаг.

```go
package main

import (
    "fmt"
    "slices"
    "strings"
)

const mappedFlag = "p8xsi8dlba61rb9q0obhpr8qhbhuojrjqrjqshr1uoqjrpmu6g"

func main() {
    keys := []rune{
        118, 106, 116, 125, 121, 122, 105, 104, 110, 99, 109, 97, 108, 95, 48, 102, 50, 51, 49, 57,
        114, 54, 107, 115, 100, 113, 117, 55, 112, 56, 98, 52, 123, 101, 111, 103, 120, 53, 119,
    }

    values := []rune{
        119, 53, 120, 103, 111, 101, 123, 52, 98, 56, 112, 55, 117, 113, 100, 115, 107, 54, 114, 57,
        49, 51, 50, 102, 48, 95, 108, 97, 109, 99, 110, 104, 105, 122, 121, 125, 116, 106, 118,
    }

    flag := strings.Map(
        func(r rune) rune {
            if slices.Contains(values, r) {
                return keys[slices.Index(values, r)]
            }

            return r
        },
        mappedFlag,
    )

    fmt.Println(flag)
}
```

## Author
По вопросам, связанным с таском, обращаться к [@pavloff_dev](https://t.me/pavloff_dev).

## Flag
```
mctf{c0un73r1n9_dyn4m1c_4n4ly515_15_f41rly_51mpl3}
```
