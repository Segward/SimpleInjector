#pragma once
#include <iostream>
#include <cstring>
#include <Windows.h>
#include <TlHelp32.h>

class Routine {

public:

    Routine(const char* processName, const char* dllPath);
    BOOL CreateRemoteThreadInject();
    BOOL HijackRemoteThreadInject();

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
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to open process: " << this->lastError << std::endl;
        if (hProcess)
            CloseHandle(hProcess);
        return;
    }

    this->hProcess = hProcess;
}

BOOL Routine::CreateRemoteThreadInject() {
    PVOID location = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to allocate memory: " << this->lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    BOOL written = WriteProcessMemory(hProcess, location, dllPath, strlen(dllPath) + 1, 0);
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to write memory: " << this->lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, location, 0, 0);
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to create remote thread: " << this->lastError << std::endl;
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

    LPCONTEXT context;
    BOOL fetched = GetThreadContext(hThread, context);
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to get thread context: " << this->lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    context->ContextFlags = CONTEXT_FULL;
    
    #ifdef _WIN64
        if (context->Rip == 0) {
            CloseHandle(hProcess);
            std::cerr << "RIP is 0" << std::endl;
            return FALSE;
        }
    #elif _WIN32 
        if (context->Eip == 0) {
            CloseHandle(hProcess);
            std::cerr << "EIP is 0" << std::endl;
            return FALSE;
        }
    #endif

    PVOID location = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to allocate memory: " << this->lastError << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    BOOL written = WriteProcessMemory(hProcess, location, dllPath, strlen(dllPath) + 1, 0);
    this->lastError = GetLastError();
    if (this->lastError != 0) {
        std::cerr << "Failed to write memory: " << this->lastError << std::endl;
        VirtualFreeEx(hProcess, location, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (hProcess)
        CloseHandle(hProcess);

    
    
    return TRUE;
}