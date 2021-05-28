// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <string>
#include <thread>
#include <libloaderapi.h>
#pragma comment(lib, "urlmon.lib")

using namespace std;

struct CVacModule {
    LPVOID m_CRC;
    HANDLE m_hModule;
    DWORD m_pModule;
    FARPROC m_fnEntryPoint;
    DWORD m_nLastResult;
    DWORD m_dwModuleSize;
    LPVOID m_pRawModule;
    DWORD  m_dwUnknown;
};



#include <windows.h> 
#include <stdio.h>
#include <conio.h>
#include <tchar.h>

#define BUFSIZE 512

int SignalInject(const char* dll_path)
{
    HANDLE hPipe;

    TCHAR  chBuf[BUFSIZE];
    BOOL   fSuccess = FALSE;
    DWORD  cbRead, cbToWrite, cbWritten, dwMode;
    LPCSTR lpszPipename = "\\\\.\\pipe\\vactools";

    LPCSTR lpvMessage = (char*)malloc(4096);

    strcpy((char*)lpvMessage, "INJ\0");
    strcat((char*)lpvMessage, dll_path);



    // Try to open a named pipe; wait for it, if necessary. 

    while (1)
    {
        hPipe = CreateFile(
            lpszPipename,   // pipe name 
            GENERIC_READ |  // read and write access 
            GENERIC_WRITE,
            0,              // no sharing 
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe 
            0,              // default attributes 
            NULL);          // no template file 

      // Break if the pipe handle is valid. 

        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        // Exit if an error other than ERROR_PIPE_BUSY occurs. 

        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            printf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());
            return -1;
        }

        // All pipe instances are busy, so wait for 20 seconds. 

        if (!WaitNamedPipe(lpszPipename, 20000))
        {
            printf("Could not open pipe: 20 second wait timed out.");
            return -1;
        }
    }

    // The pipe connected; change to message-read mode. 

    dwMode = PIPE_READMODE_MESSAGE;
    fSuccess = SetNamedPipeHandleState(
        hPipe,    // pipe handle 
        &dwMode,  // new pipe mode 
        NULL,     // don't set maximum bytes 
        NULL);    // don't set maximum time 
    if (!fSuccess)
    {
        printf(TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError());
        return -1;
    }

    // Send a message to the pipe server. 

    cbToWrite = (lstrlen(lpvMessage) + 1) * sizeof(TCHAR);
    printf(TEXT("Sending %d byte message: \"%s\"\n"), cbToWrite, lpvMessage);

    fSuccess = WriteFile(
        hPipe,                  // pipe handle 
        lpvMessage,             // message 
        cbToWrite,              // message length 
        &cbWritten,             // bytes written 
        NULL);                  // not overlapped 

    if (!fSuccess)
    {
        printf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
        return -1;
    }

    printf("\nMessage sent to server, receiving reply as follows:\n");

    do
    {
        // Read from the pipe. 

        fSuccess = ReadFile(
            hPipe,    // pipe handle 
            chBuf,    // buffer to receive reply 
            BUFSIZE * sizeof(TCHAR),  // size of buffer 
            &cbRead,  // number of bytes read 
            NULL);    // not overlapped 

        if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
            break;

        printf(TEXT("\"%s\"\n"), chBuf);
    } while (!fSuccess);  // repeat loop if ERROR_MORE_DATA 

    if (!fSuccess)
    {
        printf(TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError());
        return -1;
    }

    printf("\n<End of message, press ENTER to terminate connection and exit>");
    _getch();

    CloseHandle(hPipe);

    return 0;
}



/* Get Process ID */
void GET_PROC_ID(const char* window_title, DWORD &process_id) {
    GetWindowThreadProcessId(FindWindow(NULL, window_title), &process_id);
}

/* Display Error Messages */
void error(const char* error_title, const char* error_message) {
    MessageBox(0, error_message, error_title, 0);
    exit(-1);
}

/* Check if file exists */
bool file_exists(string file_name) {
    struct stat buffer;
    return (stat(file_name.c_str(), &buffer) == 0);
}
#include <Windows.h>
#include <TlHelp32.h>

uintptr_t GetProcessID(char* ExeName)
{
    PROCESSENTRY32 ProcEntry = { 0 };
    HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!SnapShot)
        return NULL;

    ProcEntry.dwSize = sizeof(ProcEntry);

    if (!Process32First(SnapShot, &ProcEntry))
        return NULL;

    do
    {
        if (!strcmp(ProcEntry.szExeFile, ExeName))
        {
            CloseHandle(SnapShot);
            return ProcEntry.th32ProcessID;
        }
    } while (Process32Next(SnapShot, &ProcEntry));

    CloseHandle(SnapShot);
    return NULL;
}

MODULEENTRY32 GetModule(uintptr_t dwProcID, char* moduleName)
{
    MODULEENTRY32 modEntry = { 0 };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcID);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        modEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &modEntry))
        {
            do
            {
                if (strcmp(modEntry.szModule, moduleName) == 0)
                {
                    break;
                }
            } while (Module32Next(hSnapshot, &modEntry));
        }
        CloseHandle(hSnapshot);
    }
    return modEntry;
}


uintptr_t ComboFindPattern(char* base, size_t size, char* pattern)
{
    size_t patternLength = strlen(pattern);
    for (size_t i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (int j = 0; j < patternLength; j += 3)
        {
            //convert string literal to byte 
            if (pattern[j] == ' ')
            {
                j -= 2; //makes the j+=3 work properly in this case
                continue;
            }

            //if a wildcard or space, just continue
            if (pattern[j] == '?')
            {
                continue;
            }

            long int  lower = strtol(&pattern[j], 0, 16);

            //if byte does not match the byte from memory
            if ((char)lower != *(char*)(base + i + j / 3))
            {
                found = false; break;
            }
        }
        if (found)
        {
            return (uintptr_t)base + i;
        }
    }
    return 0;
}


//Internal Pattern scan, external pattern scan is just a wrapper around this
uintptr_t FindPattern(char* base, unsigned int size, char* pattern)
{
    return ComboFindPattern( base,  size,  pattern);
#if 0
    size_t patternLength = strlen(mask);

    for (uintptr_t i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (uintptr_t j = 0; j < patternLength; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j))
            {
                found = false;
                break; // yeah that's right, stop iterating when pattern is bad.  Looking at you fleep...
            }
        }

        if (found)
        {
            return (uintptr_t)base + i;
        }
    }
    return 0;
#endif
}

//Scan just one module
uintptr_t FindPatternEx(HANDLE hProcess, char* module, char* pattern)
{
    //Grab module information from External Process
    MODULEENTRY32 modEntry = GetModule(GetProcessId(hProcess), module);
    uintptr_t start = (uintptr_t)modEntry.modBaseAddr;
    uintptr_t end = start + modEntry.modBaseSize;

    uintptr_t currentChunk = start;
    SIZE_T bytesRead;

    while (currentChunk < end)
    {
        //make data accessible to ReadProcessMemory
        DWORD oldprotect;
        VirtualProtectEx(hProcess, (void*)currentChunk, 4096, PROCESS_VM_READ, &oldprotect);

        //Copy chunk of external memory into local storage
        byte buffer[4096];
        ReadProcessMemory(hProcess, (void*)currentChunk, &buffer, 4096, &bytesRead);

        //if readprocessmemory failed, return
        if (bytesRead == 0)
        {
            return 0;
        }

        //Find pattern in local buffer, if pattern is found return address of matching data
        uintptr_t InternalAddress = FindPattern((char*)&buffer, bytesRead, pattern);

        //if Find Pattern returned an address
        if (InternalAddress != 0)
        {
            //convert internal offset to external address and return
            uintptr_t offsetFromBuffer = InternalAddress - (uintptr_t)&buffer;
            return currentChunk + offsetFromBuffer;
        }

        //pattern not found in this chunk
        else
        {
            //advance to next chunk
            currentChunk = currentChunk + bytesRead;
        }
    }
    return 0;
}

template <typename T>
static constexpr auto relativeToAbsoluteEx(HANDLE hProcess, uintptr_t address) noexcept
{
    void* ReadMem = 0;
    ReadProcessMemory(hProcess, (LPCVOID)address, &ReadMem, 4, 0);
    return (T)(address + 4 + ReadMem);
}


#include <iostream>


int main()
{
    DWORD proc_id = NULL;
    char dll_path[MAX_PATH];
    //const char* dll_name = "Harpoon.dll";
    //const char* dll_name = "C:\\Users\\user\\source\\repos\\Harpoon\\Release\\Harpoon.dll";
    const char* dll_name("C:\\Users\\user\\source\\repos\\ConsoleApplication1\\Release\\LoaderProj.dll");
    //const char* window_title = "Team Fortress 2";
    //const char* dwnld_URL = "http://www.dnf-csgo.com/Harpoon/Harpoon.dll";
    const char* game_name = "Counter-Strike: Global Offensive";
    
    GetFileAttributes(dll_name); // from winbase.h
    //if (!(INVALID_FILE_ATTRIBUTES == GetFileAttributes("C:\\MyFile.txt") && GetLastError() == ERROR_FILE_NOT_FOUND))
    //{
    //    DeleteFileA(dll_name);
    //}

    //if (URLDownloadToFile(NULL, dwnld_URL, dll_name, 0, NULL) != S_OK) {
    //    error("Download Failed", "Unable To Download Harpoon.dll");
    //}
    std::string newStr; 
    if (!file_exists(dll_name)) {

        printf("No Harpoon.dll Found, Different DLL Name?\n");
        
        std::getline(std::cin, newStr);
        dll_name = newStr.data();
        if (!file_exists(dll_name)) {
            error("file_exists(DOOR STUCK)", "File Doesn't Exist!");
        }
    }
    cout << dll_name << endl;
    if (!GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr)) {
        cout << dll_path << endl;
        error("GetFullPathName", "Didn't get the full path");
     
    }

    GET_PROC_ID(game_name, proc_id);
    if (proc_id == NULL) {
        error("GET_PROC_ID", "GET_PROC_ID returned NULL\n\nRunning in Administrator?");
    }

    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);
    if (!h_process) {
        error("OpenProcess", "Failed to get handle for process\nAdministrator Mode?");
    }

    if ( h_process)
    {

        printf("Patching Valve AC Functions...\n");
        printf("Finding Memory Location Of jnz...");
        HANDLE hCsgo = h_process;
        char* pAddress = (char*)FindPatternEx(hCsgo, (char*)"client.dll", (char*)"80 7D 08 00 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ??") + int(5);
        char* num_times_injected = (char*)FindPatternEx(hCsgo, (char*)"client.dll", (char*)"0F 85 ?? ?? ?? ?? FF 05 ?? ?? ?? ??") + int(2);
        if (pAddress)
            printf("%d\n", pAddress);
        else
            error("VALVE AC BYPASS", "CANT FIND JUMP ADDRESS!");

        printf("Writing New Jump....");
        DWORD protect1 = 0;
        VirtualProtectEx(hCsgo, (void*)pAddress, 5, PAGE_EXECUTE_READWRITE, &protect1);
        //*(char*)(pAddress) = (char)0x85;
        char val = 0x85;
        SIZE_T stNumBytesWritten = 0;
        WriteProcessMemory(hCsgo, pAddress, &val, 1, &stNumBytesWritten);
        VirtualProtectEx(hCsgo, (void*)pAddress, 5, protect1, &protect1);
        printf("Ok\n");

        printf("Incrementing Internal CS:GO Injected DLL's Counter...");
        uint32_t num_times_addr = 0;
        ReadProcessMemory(hCsgo, num_times_injected, &num_times_addr, 4, 0);
        uint32_t count = 0;
        ReadProcessMemory(hCsgo, (LPCVOID)num_times_addr, &count, 4, 0);
        count += UINT_MAX;
        WriteProcessMemory(hCsgo, (LPVOID)num_times_addr, &count, 4, 0);
        printf("(%d) Ok\n", count);

        pAddress = NULL;
        printf("Finding Memory Location Of jz...");
        pAddress = (char*)FindPatternEx(hCsgo, (char*)"client.dll", (char*)"74 13 85 FF");
        if (pAddress)
            printf("%d\n", pAddress);
        else
            error("VALVE AC BYPASS", "CANT FIND JUMP #2 ADDRESS!");

        printf("Writing New Jump E8....");

        VirtualProtectEx(hCsgo, (void*)pAddress, 5, PAGE_EXECUTE_READWRITE, &protect1);
        //*(char*)(pAddress) = (char)0x85;
        val = 0xEB;
        stNumBytesWritten = 0;
        WriteProcessMemory(hCsgo, pAddress, &val, 1, &stNumBytesWritten);
        VirtualProtectEx(hCsgo, (void*)pAddress, 5, protect1, &protect1);
        printf("Ok\n");

        // 74 13 85 FF

        char patchedBytes[5];
#if 1
        if (!strcmp(game_name, "Counter-Strike: Global Offensive")) { /* https://github.com/danielkrupinski/OneByteLdr <- A god amoung men */

            LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
            MODULEENTRY32 csgo = GetModule(GetProcessID((char*)"csgo.exe"), (char*)"ntdll");
            FARPROC csgoNtOpenFile = GetProcAddress(csgo.hModule, "NtOpenFile");
            if (ntOpenFile) {
                char originalBytes[5];
                memcpy(originalBytes, ntOpenFile, 5);
                WriteProcessMemory(h_process, ntOpenFile, originalBytes, 5, NULL);
            }
            else {
                error("Unable to open NtOpenFile", "Unable to open NtOpenFile, Exiting to avoid VAC ban/Untrusted Launch");
                return 1;
            }

            //loseHandle(ntOpenFile);
        }
#endif

        GET_PROC_ID("SteamService.exe", proc_id);
        if (proc_id == NULL) {

            GET_PROC_ID("steam.exe", proc_id);
            error("GET_PROC_ID", "GET_PROC_ID returned NULL\n\nRunning in Administrator?");
            return true;
        }

        HANDLE steam_service = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);
        if (!steam_service) {
            error("OpenProcess", "Failed to get handle for steam_service process\nAdministrator Mode?");
        }
    } 
    else
    {

        SignalInject(dll_path);
    }




    void* allocated_memory = VirtualAllocEx(h_process, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocated_memory) {
        error("VirtualAllocEx", "Failed to Allocate Memory");
    }

    if (!WriteProcessMemory(h_process, allocated_memory, dll_path, MAX_PATH, nullptr)) {
        error("WriteProcessMemory", "Could not write DLL to process memory");
    }

    HANDLE h_thread = CreateRemoteThread(h_process, nullptr, NULL, LPTHREAD_START_ROUTINE(LoadLibraryA), allocated_memory, NULL, nullptr);
    if (!h_thread) {
        error("CreateRemoteThread", "Failed to create remote thread");
    }

    //if (!strcmp(game_title, "Counter-Strike: Global Offensive")) {
    //    LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
    //    WriteProcessMemory(h_process, ntOpenFile, patchedBytes, 5, NULL);
    //   CloseHandle(ntOpenFile);
    //}
    CloseHandle(h_process);
    VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
    MessageBox(0, "DLL Injection Complete", "DLL Has Been Injected to Target Process", 0);

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
