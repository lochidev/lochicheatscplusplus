#include "LochiCheats.h"
HANDLE hProc = NULL;
DWORD pID;
THREADENTRY32 te32;
const char* procName;
#pragma comment(lib, "ntdll.lib")
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege
(
    ULONG    Privilege,
    BOOLEAN  Enable,
    BOOLEAN  CurrentThread,
    PBOOLEAN Enabled
);
bool AttachProcess() {
    BOOLEAN trash;
    RtlAdjustPrivilege(SC_DEBUG_PRIVILEGE, TRUE, FALSE, &trash);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(PROCESSENTRY32);
    auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::cout << "failed to snap" << std::endl;
        return false;
    }
    while (Process32Next(snap, &pEntry)) {
        if (!strcmp(procName, pEntry.szExeFile)) {
            std::cout << "Found process " << pEntry.szExeFile << " with PID: " << pEntry.th32ProcessID << std::endl;
            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEntry.th32ProcessID);
            pID = pEntry.th32ProcessID;

            if (hProc == NULL) {
                std::cout << "Failed to open process" << std::endl;
            }
			CloseHandle(snap);
			te32.dwSize = sizeof(te32);
            snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pID);
            Thread32First(snap, &te32);
            while (Thread32Next(snap, &te32)) {
                if (te32.th32OwnerProcessID == pID) {
                    break;
                }
            }
            CloseHandle(snap);
            return true;
        }
    }
    std::cout << "Could not find process" << std::endl;
    CloseHandle(snap);
    return false;
}
 inline void errnex(const char* title, const char* desc) {
	CloseHandle(hProc);
	MessageBox(NULL, desc, title, NULL);
	exit(-1);
}
 void SetProcName(const char* name)
 {
	 procName = name;
 }
 inline bool fileExists(const std::string& name) {
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}
LPBYTE ptr;
PVOID allocated_memory, buffer;
#if _WIN32 || _WIN64
#if _WIN64
char shell_code[] = {
	 0x48, 0xb8, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 
	 0x48, 0xb9, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 
	 0x48, 0x83, 0xec, 0x40, 0x48, 0x83, 0xe4, 0xf0,
	 0xff, 0xd0, 
	 0x48, 0xb8, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
	 0x48, 0xb9, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 
	 0x48, 0x31, 0xd2, 0xff, 0xd0
};
//[Bits 64]
//mov rax, 0xCCCCCCCCCCCCCCCC; ptr loadlibrary
//mov rcx, 0xCCCCCCCCCCCCCCCC; ptr dllPath
//sub rsp, 64; allocate shadow space for the function
//and rsp, 0xFFFFFFFFFFFFFFF0; align
//call rax
//mov rax, 0xDDDDDDDDDDDDDDDD; address of rtlrestorecontext
//mov rcx, 0xDDDDDDDDDDDDDDDD; address of ptrContext
//xor rdx, rdx; 2nd arg == zero
//call rax
#else
char shell_code[] = {
	0X60, 0XE8, 0X00, 0X00, 0X00, 0X00,
	0X5B /*POP EBX*/, 0X81 /*SUB*/, 0XEB, 0X06, 0X00, 0X00, 0X00, // CUZ LIL ENDIAN BABY
	0XB8, 0XCC, 0XCC, 0XCC, 0XCC, 0X8D /*LEA*/, 0X93 /*EBX*/, 0X22,
	0X00, 0X00, 0X00, 0X52, 0XFF, 0XD0, 0X61, 0X68, 0XCC, 0XCC, 0XCC, 0XCC, 0XC3
};
#endif
#endif

 void Inject(const char* dllPath) {
	if (!fileExists(dllPath)) {
		errnex("Dll not found", "Bonk");
	}
	allocated_memory = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (!allocated_memory) {
		errnex("Error", "Failed to allocate memory");
	}
	HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
	if (!h_thread) {
		VirtualFreeEx(hProc, allocated_memory, NULL, MEM_RELEASE);
		errnex("OpenThread", "Failed to open thread");
	}
	SuspendThread(h_thread);
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(h_thread, &ctx);
	PVOID context_address_ex = VirtualAllocEx(hProc, NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	buffer = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	ptr = (LPBYTE)buffer;
	memcpy(buffer, &shell_code, sizeof(shell_code));
	while (1) {
		if (*ptr == 0xB8 && *(PDWORD64)(ptr + 1) == 0xCCCCCCCCCCCCCCCC) {
			*(PDWORD64)(ptr + 1) = (DWORD64)LoadLibraryA;
		}
		if (*ptr == 0xB8 && *(PDWORD64)(ptr + 1) == 0xDDDDDDDDDDDDDDDD) {
			*(PDWORD64)(ptr + 1) = (DWORD64)RtlRestoreContext;
		}
		if (*ptr == 0xB9 && *(PDWORD64)(ptr + 1) == 0xCCCCCCCCCCCCCCCC) {
			*(PDWORD64)(ptr + 1) = (DWORD64)allocated_memory + sizeof(shell_code);
		}
		if (*ptr == 0xB9 && *(PDWORD64)(ptr + 1) == 0xDDDDDDDDDDDDDDDD) {
			*(PDWORD64)(ptr + 1) = (DWORD64)context_address_ex;
		}
		if (*ptr == 0xd2) {
			ptr += 3;
			break;
		}
		ptr++;
	}
	strcpy((char*)ptr, dllPath);
	if (!WriteProcessMemory(hProc, allocated_memory, buffer, sizeof(shell_code) + strlen((char*)ptr), nullptr)
		|| !WriteProcessMemory(hProc, context_address_ex, &ctx, sizeof(CONTEXT), nullptr)) {

		VirtualFreeEx(hProc, allocated_memory, NULL, MEM_RELEASE);
		VirtualFreeEx(hProc, context_address_ex, NULL, MEM_RELEASE);
		ResumeThread(h_thread);
		CloseHandle(h_thread);
		VirtualFree(buffer, NULL, MEM_RELEASE);
		errnex("WPM", "Could not write shell code");
	}
	ctx.Rip = (DWORD64)allocated_memory;
	if (!SetThreadContext(h_thread, &ctx)) {
		VirtualFreeEx(hProc, allocated_memory, NULL, MEM_RELEASE);
		VirtualFreeEx(hProc, context_address_ex, NULL, MEM_RELEASE);
		ResumeThread(h_thread);
		CloseHandle(h_thread);
		VirtualFree(buffer, NULL, MEM_RELEASE);
		errnex("Failed", "Could not set thread context");
	}
	ResumeThread(h_thread);
	CloseHandle(h_thread);
	VirtualFree(buffer, NULL, MEM_RELEASE);
	MessageBox(NULL, "Success!", "Injection successful", NULL);
}
template<class dType>
 void wpm(dType valToWrite, long long address) {
	WriteProcessMemory(hProc, (LPVOID)address, &valToWrite, sizeof(dType), 0);
}
template<class dType>
 dType rpm(long long address) {
	dType rpmBuffer;
	ReadProcessMemory(hProc, (PVOID)address, &rpmBuffer, sizeof(dType), 0);
	return rpmBuffer;
}