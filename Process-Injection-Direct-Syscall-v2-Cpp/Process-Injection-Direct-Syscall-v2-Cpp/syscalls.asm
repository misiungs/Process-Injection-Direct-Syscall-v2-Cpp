.code

; Reference: https://j00ru.vexillium.org/syscalls/nt/64/

myNtOpenProcess proc
		mov r10, rcx
		mov eax, 26h
		syscall
		ret
myNtOpenProcess endp

myNtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, 18h
		syscall
		ret
myNtAllocateVirtualMemory endp

myNtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, 3Ah
		syscall
		ret
myNtWriteVirtualMemory endp

myNtCreateThreadEx proc
		mov r10, rcx
		mov eax, 0C2h
		syscall
		ret
myNtCreateThreadEx endp

myNtWaitForSingleObject proc
		mov r10, rcx
		mov eax, 4
		syscall
		ret
myNtWaitForSingleObject endp

end