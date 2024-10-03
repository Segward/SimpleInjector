#pragma once
#include <iostream>
#include <cstring>
#include <Windows.h>
#include <TlHelp32.h>

class Routine {

public:

    Routine(const char* processName, const char* dllPath);
    BOOL CreateRemoteThreadInject(); 
    BOOL NtCreateThreadExInject();
    BOOL HijackRemoteThreadInject();
    BOOL SetWindowsHookExInject();
    BOOL QueueUserAPCInject();

private:

    DWORD lastError;
    const char* processName;
    const char* dllPath;
    DWORD pid;
    HANDLE hProcess;

};

Routine::Routine(const char* processName, const char* dllPath) {
    this->processName = processName;
    this->dllPath = dllPath;

    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed" << std::endl;
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hSnap, &pe32)) {
        std::cerr << "Error: Process32First failed" << std::endl;
        return;
    }

    do {
        pid = strcmp((const char*)pe32.szExeFile, processName) == 0 ?
            pe32.th32ProcessID : 0;
    } while (Process32Next(hSnap, &pe32) && pid == 0);

    CloseHandle(hSnap);

    this->pid = pid;

    if (pid == 0) {
        std::cerr << "Error: Process not found" << std::endl;
        return;
    }

    FILE *file = fopen(dllPath, "r");
    if (file != NULL) {
        fclose(file);
    } else {
        std::cerr << "Dll path not found: " << dllPath << std::endl;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to open process: " << lastError << std::endl;
        if (hProcess)
            CloseHandle(hProcess);
        return;
    }

    this->hProcess = hProcess;
}

BOOL Routine::CreateRemoteThreadInject() {
    PVOID location = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to allocate memory: " << lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD oldProtect;
    BOOL isProtected = VirtualProtectEx(hProcess, location, strlen(dllPath) + 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    lastError = GetLastError();
    if (!isProtected) {
        std::cerr << "Failed to set memory protection: " << lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    BOOL written = WriteProcessMemory(hProcess, location, dllPath, strlen(dllPath) + 1, 0);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to write memory: " << lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, location, 0, 0);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to create remote thread: " << lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    if (hThread)
        CloseHandle(hThread);

    if (hProcess)
        CloseHandle(hProcess);

    return TRUE;
}

BOOL Routine::HijackRemoteThreadInject() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed" << std::endl;
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    if (!Thread32First(hSnap, &te32)) {
        std::cerr << "Error: Thread32First failed" << std::endl;
        return FALSE;
    }

    HANDLE hThread = 0;
    do {
        hThread = te32.th32OwnerProcessID == pid ? 
            OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID) : 0;
    } while (Thread32Next(hSnap, &te32) && hThread == 0);

    CloseHandle(hSnap);

    if (hThread == 0) {
        std::cerr << "Error: Thread not found" << std::endl;
        return FALSE;
    }

    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to get thread context: " << lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    CONTEXT context = { 0 };
    #ifdef _M_AMD64
        context.ContextFlags = CONTEXT_FULL;
    #elif _M_IX86
        context.ContextFlags = WOW64_CONTEXT_FULL;
    #endif

    BOOL fetched = GetThreadContext(hThread, &context);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to get thread context: " << lastError << std::endl;
        CloseHandle(hThread);
        return FALSE;
    }

    DWORD oldEip;
    DWORD64 oldRip;
    unsigned char shellcode[4096];

    #ifdef _M_AMD64
        oldRip = context.Rip;

        unsigned char replacement[] = {
            0x68, 0x00, 0x00, 0x00, 0x00,                   // push low 32 bits of oldRip
            0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, // mov [rsp+4], high 32 bits of oldRip
            0xC3                                            // ret
        };

        *((DWORD*)(replacement + 1)) = (DWORD)(oldRip & 0xFFFFFFFF); // low 32 bits
        *((DWORD*)(replacement + 9)) = (DWORD)((oldRip >> 32) & 0xFFFFFFFF); // high 32 bits

        memcpy(shellcode, replacement, sizeof(replacement));

    #elif _M_IX86
        oldEip = context.Eip;

        unsigned char replacement[] = {
            0x83, 0xEC, 0x04,                               // sub esp, 0x04
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,       // mov [esp], oldEip
            0xC3                                            // ret
        };

        *((DWORD*)(replacement + 6)) = oldEip; // oldEip

        memcpy(shellcode, replacement, sizeof(replacement));

    #endif

    PVOID location = VirtualAllocEx(hProcess, 0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to allocate memory: " << lastError << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD oldProtect;
    BOOL isProtected = VirtualProtectEx(hProcess, location, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);
    lastError = GetLastError();
    if (!isProtected) {
        std::cerr << "Failed to set memory protection: " << lastError << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    BOOL written = WriteProcessMemory(hProcess, location, shellcode, sizeof(shellcode), 0);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to write memory: " << lastError << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    SuspendThread(hThread);

    BOOL set = SetThreadContext(hThread, &context);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to set thread context: " << lastError << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    BOOL resume = ResumeThread(hThread);
    lastError = GetLastError();
    if (lastError != 0) {
        std::cerr << "Failed to resume thread: " << lastError << std::endl;
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}