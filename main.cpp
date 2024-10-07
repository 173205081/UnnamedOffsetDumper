// UnnamedOffsetDumper

#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
// i won't use clang tidy here
bool IsValidString(const char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (data[i] == '\0') {
            return true;
        }
        if (!isprint(static_cast<unsigned char>(data[i]))) {
            return false;
        }
    }
    return false;
}

DWORD GetProcessIdByName(const std::string& processName) {
    DWORD processID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (!_stricmp(pe.szExeFile, processName.c_str())) {
                    processID = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return processID;
}

void DumpOffsetsToFile(HANDLE hProcess, const std::string& outputFileName, const std::string& processName, const std::string& mode) {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;

    std::ofstream outFile(outputFileName);
    if (!outFile.is_open()) {
        std::cerr << "Failed to open file: " << outputFileName << std::endl;
        return;
    }

    outFile << "// Memory dump for " << processName << " - Mode: " << mode << "\n\n";
    outFile << "#include <stddef.h>\n\n";

    size_t iterationCount = 0;
    const size_t maxIterations = ULLONG_MAX; // nvm

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) && iterationCount < maxIterations) {
        std::cout << "Processing memory region at: " << static_cast<void*>(address) << ", Size: " << mbi.RegionSize << std::endl;

        if (address != nullptr && mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            size_t bytesToRead = std::min(mbi.RegionSize, static_cast<SIZE_T>(4096)); // read in smaller chunks if necessary
            std::vector<char> buffer(bytesToRead);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, address, buffer.data(), bytesToRead, &bytesRead)) {
                std::cout << "Successfully read " << bytesRead << " bytes from memory." << std::endl;
                std::cout << "Buffer contents: ";
                for (size_t i = 0; i < bytesRead; ++i) {
                    std::cout << static_cast<unsigned int>(buffer[i]) << " ";
                }
                std::cout << std::endl;

                if (mode == "all") {
                    const size_t startAddress = reinterpret_cast<size_t>(address);
                    const size_t endAddress = reinterpret_cast<size_t>(address + mbi.RegionSize);
                    outFile << "// Memory region from: " << static_cast<void*>(address)
                        << " to: " << static_cast<void*>(address + mbi.RegionSize) << "\n";
                    outFile << "const size_t offset_" << startAddress << " = " << startAddress << ";\n";
                    outFile << "const size_t offset_" << endAddress << " = " << endAddress << ";\n\n";
                    std::cout << "Dumping full memory region from " << startAddress << " to " << endAddress << std::endl;
                }
                else if (mode == "string") {
                    for (size_t i = 0; i < bytesRead; ++i) {
                        if (IsValidString(buffer.data() + i, bytesRead - i)) {
                            std::string str(buffer.data() + i);
                            size_t strLength = str.find('\0'); // use this to find the length
                            if (strLength != std::string::npos) {
                                std::string variableName = "a" + str.substr(0, strLength);
                                for (auto& ch : variableName) {
                                    if (!isalnum(ch)) {
                                        ch = '_';
                                    }
                                }
                                outFile << "const char* " << variableName << " = \"" << str.substr(0, strLength) << "\";\n";
                                std::cout << "Found string: " << str.substr(0, strLength) << " at offset: " << reinterpret_cast<size_t>(address + i) << std::endl;
                                i += strLength;
                            }
                        }
                    }
                }
                else if (mode == "int") {
                    for (size_t i = 0; i < bytesRead - sizeof(int); i += sizeof(int)) {
                        int value;
                        memcpy(&value, buffer.data() + i, sizeof(int));
                        outFile << "const int intOffset_" << reinterpret_cast<size_t>(address + i) << " = " << value << ";\n";
                        std::cout << "Found int: " << value << " at offset: " << reinterpret_cast<size_t>(address + i) << std::endl;
                    }
                }
            }
            else {
                DWORD error = GetLastError();
                std::cerr << "Failed to read memory at: " << static_cast<void*>(address) << ", Error: " << error << std::endl;
            }
        }
        address += mbi.RegionSize;
        ++iterationCount;
    }

    if (iterationCount >= maxIterations) {
        std::cerr << "Reached maximum number of iterations, exiting loop." << std::endl;
    }

    outFile.close();
    std::cout << "Memory dump written to " << outputFileName << std::endl;
}

int main(int argc, char* argv[]) {
    std::string processName;
    std::string outputFileName;
    std::string mode;

    if (argc < 4) { // uhhhhhhh
        std::cout << "Enter the process name (e.g., input.exe): ";
        std::getline(std::cin, processName);
        std::cout << "Enter the output file name (e.g., output.c): ";
        std::getline(std::cin, outputFileName);
        std::cout << "Enter the mode (all/string/int): "; // string doesn't work, since we're parsing buffers, which are uints lol
        std::getline(std::cin, mode);
    } else {
        processName = argv[1];
        outputFileName = argv[2];
        mode = argv[3];
    }

    DWORD processID = GetProcessIdByName(processName);
    if (processID) {
        std::cout << "Process ID found: " << processID << std::endl;
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (hProcess) {
            DumpOffsetsToFile(hProcess, outputFileName, processName, mode);
            CloseHandle(hProcess);
        } else {
            std::cerr << "Failed to open process with ID: " << processID << std::endl;
        }
    } else {
        std::cerr << "Process not found: " << processName << std::endl;
    }
    return 0;
}