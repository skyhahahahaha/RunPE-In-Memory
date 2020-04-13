#include <Windows.h>
#include "peBase.hpp"
#include "fixIAT.hpp"
#include "fixReloc.hpp"

bool peLoader(const char* exePath)
{
	LONGLONG fileSize = -1;
	BYTE* data = MapFileToMemory(exePath, fileSize);
	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)getNtHdrs(data);
	if (!ntHeader)
	{
		printf("[+] File %s isn't a 32bit PE file.", exePath);
		return false;
	}

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	printf("[+] Exe File Prefer Image Base at %llx\n", preferAddr);

	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase); // ummap the address of this process that is the Exe File Prefer Image Base

	pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pImageBase && !relocDir)
	{
		printf("[-] Allocate Image Base At %x Failure.\n", preferAddr);
		return false;
	}
	if (!pImageBase && relocDir)
	{
		printf("[+] Try to Allocate Memory for New Image Base\n");
		pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pImageBase)
		{
			printf("[-] Allocate Memory For Image Base Failure.\n");
			return false;
		}
	}
	printf("[+] VirtualAlloc Image Base at %llx\n", pImageBase);
	puts("[+] Mapping Section ...");
	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		printf("    [+] Mapping Section %s\n", SectionHeaderArr[i].Name);
		memcpy
		(
			LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress),
			LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData),
			SectionHeaderArr[i].SizeOfRawData
		);
	}
	fixIAT(pImageBase);

	if (pImageBase != preferAddr) {
		if (applyReloc((size_t)pImageBase, (size_t)preferAddr, pImageBase, ntHeader->OptionalHeader.SizeOfImage)) {
			puts("[+] Relocation Fixed.");
		}
		else
		{
			puts("[+] Else.");
		}
	}
	else 
	{
		puts("[+] Another Else.");
	}
	size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("Run Exe Module: %s\n", exePath);
	printf("Rip: %llx\n", retAddr);
	getchar();
	((void(*)())retAddr)();
}
#include <string>
int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("Usage: %s [Exe Path]", strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
		getchar();
		return 0;
	}

	peLoader(argv[1]);
	//peLoader("hello.exe");

	getchar();
	return 0;
}
