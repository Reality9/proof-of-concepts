// DLL injection Via CreateRemoteThread()
// 32 bits processes only

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD findPidByName(char * pname){
	HANDLE h;
	PROCESSENTRY32 psnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	psnapshot.dwSize = sizeof(PROCESSENTRY32);
	
	do{
		if(!strcmp(psnapshot.szExeFile, pname)){
		    DWORD pid = psnapshot.th32ProcessID;
			CloseHandle(h);
			printf("[*] PID found: %d\n", pid);
			return pid;
		}
	} while(Process32Next(h, &psnapshot));

	CloseHandle(h);
	return 0;    
}

int _tmain(int argc, char* argv[]) {
	char * pname;
	char * dlltoinject;
	
	if(argc != 3) {
		printf("[*] Usage: %s <process name> <path/to/dll>\n", argv[0]);
		exit(0);
	}

	printf("argv[0] = %s\nargv[1] = %s\nargv[2] = %s\n", argv[0], argv[1], argv[2]);

	pname = (char *) malloc(strlen(argv[1]));
	strcpy(pname, argv[1]);
	
	DWORD pid = findPidByName(pname);
	free(pname);

	if (pid == 0) {
		printf("[*] Error: Could not find PID (%d).\n", pid);
		exit(1);
	}

	dlltoinject = (char *) malloc(strlen(argv[2]));
	strcpy(dlltoinject, argv[2]);

	// get process handle for PID
    	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(process == NULL) {
		printf("[*] Error: Could not open process for PID (%d).\n", pid);
		exit(1);
	}

	// get the address of LoadLibraryA
    	LPVOID address = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if(address == NULL) {
		printf("[*] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n");
		exit(1);
	}

	// allocate a new memory region inside PID address space
    	LPVOID baseaddress = (LPVOID)VirtualAllocEx(process, NULL, strlen(dlltoinject), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if(baseaddress == NULL) {
		printf("[*] Error: Could not allocate memory inside PID (%d).\n", pid);
		exit(1);
	}

	// write the argument to LoadLibraryA to the process's newly allocated memory region
    	int retv = WriteProcessMemory(process, baseaddress, dlltoinject, strlen(dlltoinject), NULL);
	if(retv == 0) {
		printf("[*] Error: Could not write any bytes into the PID (%d) address space.\n", pid);
		exit(1);
	}

	free(dlltoinject);

	// inject the DLL into the process's address space
    	HANDLE hnthread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)address, baseaddress, NULL, NULL);
	if(hnthread == NULL) {
		printf("[*] Error: Could not create the Remote Thread.\n");
		exit(1);
	}
	else
		printf("[*] Success: Remote Thread successfully created. DLL injected.\n");

	// DLL injected, we can close the handle to the process now
    	CloseHandle(process);

	return 0;
}

