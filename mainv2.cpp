#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>

DWORD asdasfv(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &processEntry)) {
            do {
                if (processName == processEntry.szExeFile) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processId;
}

bool isInteresting(HANDLE hProcess, std::uint32_t offset) {
    BYTE buffer[4];
    SIZE_T bytesRead;
    
    if (ReadProcessMemory(hProcess, (LPCVOID)offset, &buffer, sizeof(buffer), &bytesRead) && bytesRead == sizeof(buffer)) {
        std::uint32_t value = *reinterpret_cast<std::uint32_t*>(buffer);

        // actually a placeholder
        if (value != 0 && value < 1000000) { // replace this please
            return true;
        }
    }
    return false;
}

void log(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process." << std::endl;
        return;
    }

    std::ofstream logFile("offsets_log"+(const char*)processID+".c", std::ios::out);
    if (logFile.is_open()) {
        logFile << "#include <cstdint>\n\n";
        logFile << "namespace offsets {\n";

        MEMORY_BASIC_INFORMATION mbi;
        unsigned char* address = nullptr;
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
                for (unsigned char* offset = (unsigned char*)mbi.BaseAddress;
                     offset < (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
                     offset += sizeof(std::uint32_t)) {
                    if (isInteresting(hProcess, (std::uint32_t)offset)) {
                        logFile << "    constexpr std::uint32_t offset_" << std::hex << (std::uintptr_t)offset << " = 0x" << (std::uintptr_t)offset << ";\n";
                    }
                }
            }
            address += mbi.RegionSize;
        }

        logFile << "}\n";
        logFile.close();
    }

    CloseHandle(hProcess);
}

int main() {
    std::wstring processName = L"ihavenoideaifthisevenworks.exe"; // replace with the target application
    DWORD processID = asdasfv(processName);
    if (processID == 0) {
        std::cerr << "Could not find process." << std::endl;
        return 1;
    }

    log(processID);
    return 0;
}
