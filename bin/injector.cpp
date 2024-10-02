#include <iostream>
#include <cstring>
#include <Windows.h>
#include <TlHelp32.h>

int main(const int argc, const char* argv[]) {
    
    if (argc < 2) {
        std::cerr << "Missing Arguments: <process name> <dll path>" << std::endl;
        return 1;
    }

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        std::cerr << "Basic Usage: injector <process name> <dll path>" << std::endl;
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];

    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: CreateToolhelp32Snapshot failed" << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hSnap, &pe32)) {
        std::cerr << "Error: Process32First failed" << std::endl;
        return 1;
    }

    do {
        pid = strcmp((const char*)pe32.szExeFile, processName) == 0 ?
            pe32.th32ProcessID : 0;
    } while (Process32Next(hSnap, &pe32) && pid == 0);

    CloseHandle(hSnap);

    if (pid == 0) {
        std::cerr << "Error: Process not found" << std::endl;
        return 1;
    }

    FILE *file = fopen(dllPath, "r");
    if (file != NULL) {
        fclose(file);
    } else {
        std::cerr << "Dll path not found: " << dllPath << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD error = GetLastError();
    if (error != 0) {
        std::cerr << "Failed to open process: " << error << std::endl;
        return 1;
    }

    PVOID location = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    error = GetLastError();
    if (error != 0) {
        std::cerr << "Failed to allocate memory: " << error << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    BOOL written = WriteProcessMemory(hProcess, location, dllPath, strlen(dllPath) + 1, 0);
    error = GetLastError();
    if (error != 0) {
        std::cerr << "Failed to write memory: " << error << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, location, 0, 0);
    error = GetLastError();
    if (error != 0) {
        std::cerr << "Failed to create remote thread: " << error << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (hThread)
        CloseHandle(hThread);

    if (hProcess)
        CloseHandle(hProcess);

    return 0;
}