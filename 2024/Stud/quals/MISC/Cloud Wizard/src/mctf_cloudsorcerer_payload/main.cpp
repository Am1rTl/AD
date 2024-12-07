#pragma comment(lib, "User32.lib")

#include "windows.h"

#define TITLE L"Hello world!"
#define FLAG  L"PLACEFLAGHERE\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow) {
    MessageBoxW(NULL, FLAG, TITLE, MB_OK);
    return WM_QUIT;
}