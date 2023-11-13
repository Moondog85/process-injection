#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tlhelp32.h>

DWORD GetPidByName(const wchar_t* pName)
{
    PROCESSENTRY32W pEntry; // Note added trailing "W" - .szExeFile is now wchar_t[]
    HANDLE snapshot;

    pEntry.dwSize = sizeof(PROCESSENTRY32W);

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32FirstW(snapshot, &pEntry) == TRUE) {
        while (Process32FirstW(snapshot, &pEntry) == TRUE) {
            if (wcscmp(pEntry.szExeFile, pName) == 0) {
                return pEntry.th32ProcessID;
            }
        }
    }
    return 0; // Need to return SOMETHING, here, to signal a "not found" result!
}

int main(void) {

    STARTUPINFOEX info = { sizeof(0),};
    PROCESS_INFORMATION processInfo;
    
    SIZE_T cbAttributeListSize = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
    HANDLE hExplorerProcess = NULL;
    DWORD dwExplorerPid = 0;

    dwExplorerPid = GetPidByName(L"explorer.exe");

    if (dwExplorerPid == 0) {
        dwExplorerPid = GetCurrentProcessId();
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
    pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize); //
    InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

    hExplorerProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwExplorerPid);
    UpdateProcThreadAttribute(pAttributeList,
    0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    &hExplorerProcess,
    sizeof(HANDLE),
    NULL,
    NULL);

    info.lpAttributeList = pAttributeList;

    CreateProcessA(
        NULL,
        (LPSTR)"Notepad.exe",
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,  //include and modify attribute list
        NULL,
        NULL,
        (LPSTARTUPINFOA) &info.StartupInfo,
        &processInfo
    );

    printf("malware PID: %d\n", GetCurrentProcessId());
    printf("explorer PID: %d\n", dwExplorerPid);
    printf("notepad PID: %d\n", processInfo.dwProcessId);

    Sleep(30000);

    DeleteProcThreadAttributeList(pAttributeList);
    CloseHandle(hExplorerProcess);

}