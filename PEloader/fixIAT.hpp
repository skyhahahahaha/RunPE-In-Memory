#include <windows.h>
#include <exception>
#include <winnt.h>

using namespace std;

bool fixIAT(PVOID modulePtr)
{
	printf("[+] Fix Import Address Table\n");
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return false;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
		printf("    [+] Import DLL: %s\n", lib_name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (true)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);
			PIMAGE_THUNK_DATA  import_Int = (PIMAGE_THUNK_DATA)(lib_desc->OriginalFirstThunk + size_t(modulePtr));

			if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				//Find Ordinal Id
				
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				printf("        [V] API %llx at %llx\n", orginThunk->u1.Ordinal, addr);
				printf("/////////////////////%llx\n", orginThunk->u1.Ordinal);
				fieldThunk->u1.Function = addr;
				//printf("/////////////////////%llx\n", fieldThunk->u1.Function);
			}
			if (fieldThunk->u1.Function == NULL) break;

			if (fieldThunk->u1.Function == orginThunk->u1.Function) {

				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);
				if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) return false;

				LPSTR func_name = (LPSTR)by_name->Name;
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
				printf("        [V] API %s at %llx\n", func_name, addr);
				fieldThunk->u1.Function = addr;
				//printf("/////////////////////%llx\n", fieldThunk->u1.Function);
			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return true;
}