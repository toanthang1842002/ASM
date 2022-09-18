.data
endl   db 0ah
msg1   db "Input : ",0dh
msg2   db "Output : ",0ah,0dh
endline   db 0ah,0dh	

fVirtualAlloc db "VirtualAlloc", 0
fVirtualFree db "VirtualFree", 0
fwrite db "WriteConsole",0
fGetStdHandle db "GetStdHandle", 0
fexit db "ExitProcess", 0
fread db "ReadConsole",0
end_line db 0ah,0dh
count dq 0
time  dq 0
fi0 dq 0
fi1 dq 1
num_int dq 0
size_array dq 0
mem dq 0 

.data?
string dq 1 dup(?)

fibo2 dq 1 dup(?)
fibo0 dq 1 dup(?)
fibo1 dq 1 dup(?)


BaseAddress dq 5 dup(?)
VA_of_exported_dir dq 5 dup(?)
VA_of_exported_table dq 5 dup(?)     
_Write dq 5 dup (?)        
_Read dq 5 dup (?)         
_GetStdHandle dq 5 dup (?)        
_Exit dq 5 dup (?)         
write dq 5 dup (?)       
read dq 5 dup (?)                    
STD_IN dq 5 dup (?)  
STD_OUT dq 5 dup (?) 
_VirtualAlloc dq 5 dup (?) 
_VirtualFree dq 5 dup (?) 

;======== Parameter of VirtualAlloc======================
; value of flAllocationType
MEM_COMMIT equ 1000h
MEM_RESERVE equ 2000h
MEM_RESET equ 80000h
MEM_RESET_UNDO equ 1000000h

;======== Parameter of VirtualFree======================
;Value of dwFreeType
MEM_DECOMMIT equ 4000h
MEM_RELEASE equ 8000h

;========Memory Protection Constants=====================
PAGE_READWRITE equ 04h
PAGE_EXECUTE_READWRITE equ 40h

len dq 5 dup (?) 
n   dq 5 dup(?)
n2   dq 5 dup(?)



.code

main proc
	call init

	; dynamic allocation=======================================================

	lea rcx,fibo0
	mov rdx,100
	call Alloc
	mov fibo0,rax

	lea rcx,fibo1
	mov rdx,100
	call Alloc
	mov fibo1,rax

	lea rcx,fibo2
	mov rdx,100
	call Alloc
	mov fibo2,rax

	mov rcx,n
	mov rdx,100
	call Alloc
	mov n,rax

	;=========================================================================

	lea rdx,msg1
	call _OUTPUT
	
	mov r8,4
	mov rdx,n
	call _INPUT

	mov rcx,0h
	mov rdx,fibo0
	call Itoa

	mov rcx,1h
	mov rdx,fibo1
	call Itoa


	;============================================================

	mov rcx,n
	call Atoi
	mov rcx,num_int
	mov size_array,rcx

	cmp size_array,0
	je Zero


	First:
		mov rdx,fibo1
		call _OUTPUT
		dec size_array
		lea rdx,end_line
		call _OUTPUT

	Start_fibo:
		cmp size_array,0
		je  End_fibo

		mov rcx,fibo0
		mov rdx,fibo1
		mov r8,fibo2
		call Addition

		mov rdx,fibo2
		call _OUTPUT

		lea rdx,end_line
		call _OUTPUT

		mov rcx,fibo1
		call Reverse

		mov rcx,fibo1
		mov rdx,fibo0
		call _Copy

		mov rcx,fibo2
		mov rdx,fibo1
		call _Copy

		dec size_array
		jmp Start_fibo

	Zero:
		mov rdx,fibo0
		call _OUTPUT

	End_fibo:
		
		mov rcx,fibo1
		call Free

		mov rcx,fibo2
		call Free

		mov rcx,fibo0
		call Free

		mov rcx,n
		call Free
		mov rax, _Exit
		mov rcx,0
		call rax


main endp

;====================================================================================================================================================

GetBaseAddress proc
	push rbp
	mov rbp,rsp
	xor rax,rax
	mov rax, gs:[rax+60h]     ; PEB at fs:[0x30](x86) or gs:[0x60](x64)
	mov rax, [rax+18h]        ; PEB -> Ldr
	mov rsi, [rax+20h]        ; PEB -> Ldr.InMemOrder
	lodsq					  ; rax = Second Module (ntdll.dll) || load value of pointer -> rsi to rax
	xchg rax,rsi              ; rax = PEB -> Ldr.InMemOrder ;  rsi = Second Module (ntdll.dll)
	lodsq                     ; rax = Third Module (kernel32.dll)
	mov rax, [rax+20h]        ; rax = Base Adrress
	mov BaseAddress, rax      ; Save
	leave
	ret
GetBaseAddress endp

GetExportedTable proc
	push rbp
	mov rbp,rsp
	xor rcx,rcx
	mov ecx,[rax+3ch]        ; rcx = DOS ->e_lfanew || RVA of PE signature || the last 4 bytes in MS-DOS header are e_lfanew
	add rcx,rax              ; VA = BaseAddress + RVA
	mov ecx,[rcx+88h]        ; RVA of exported directory
	add rcx,rax              ; VA of exported directory
	mov VA_of_exported_dir,rcx
	mov esi,[rcx+20h]        ; RVA of exported table
	add rsi,BaseAddress      ; VA of exported table
	mov VA_of_exported_table,rsi
	leave
	ret
GetExportedTable endp

GetProcAddress proc
	push rbp
	mov rbp,rsp
	sub rsp,16
	mov [rbp-8],rcx
	mov [rbp-16],rdx
	push rax
	push rbx
	push rdi
	xor rax,rax
	xor rcx,rcx
	xor rbx,rbx
	mov rsi,VA_of_exported_table
	mov rbx,[rbp-16]

	Start_find:
		inc rcx
		lodsd
		add rax,BaseAddress        ;VA of function
		xor rdi,rdi
	Cmp_function_name:
		xor rdx,rdx
		mov dl, byte ptr [rax+rdi]
		mov dh, byte ptr [rbx+rdi]
		inc rdi
		cmp dh,0
		je  Finish_find
		cmp dh,dl
		je  Cmp_function_name
		jmp Start_find
	Finish_find:
		mov rbx,VA_of_exported_dir
		mov esi, [rbx+24h]         ;RVA of function ordinal table
		add rsi, BaseAddress       ; VA of function ordinal table
		mov cx, [rsi+rcx*2]		   ; get LoadLibray biased_ordinal
		dec rcx					   ; get LoadLibray ordinal
		mov esi, [rbx+1ch]         ; RVA of Address Of Functions
		add rsi, BaseAddress       ; VA
		mov esi, [rsi+rcx*4]       ; RVA of LoadLibrayA
		add rsi, BaseAddress
		xor rbx,rbx
		mov rbx,[rbp-8]
		mov [rbx],rsi
		pop rdi
		pop rbx
		pop rax
		leave
		ret 

GetProcAddress endp

init proc
	push rbp
	mov rbp,rsp
	
	call GetBaseAddress
	call GetExportedTable

	lea rcx , _Write
	lea rdx , fWrite
	call GetProcAddress

	lea rcx , _Read
	lea rdx , fRead
	call GetProcAddress

	lea rcx , _GetStdHandle
	lea rdx , fGetStdHandle
	call GetProcAddress

	lea rcx , _Exit
	lea rdx , fExit
	call GetProcAddress

	mov rax, _GetStdHandle
	mov rcx,-11
	call rax
	mov STD_OUT , rax

	mov rax, _GetStdHandle
	mov rcx,-10
	call rax
	mov STD_IN, rax

	;LPVOID VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect)

	lea rcx , _VirtualAlloc
	lea rdx , fVirtualAlloc
	call GetProcAddress

	;VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType)
	lea rcx , _VirtualFree
	lea rdx , fVirtualFree
	call GetProcAddress

	leave
	ret
init endp

Strlen PROC                                         ; return value to RAX
	push	rbp
	mov		rbp,rsp
	push    rsi
	xor		rsi,rsi
	xor		rax,rax
	count_char:
		cmp	byte ptr [rcx+rsi],0dh
		jz finished
		inc rsi
		jmp count_char

	finished:
		mov rax,rsi
		pop rsi
		leave
		ret 
Strlen endp

_INPUT proc
	push rbp
	mov	rbp,rsp

	sub rsp,8
	mov rax, _Read
	mov rcx, STD_IN
	lea r9, read
	push 0
	call rax
	add rsp,16						; Align stack after call func
	leave
	ret

_INPUT endp

_OUTPUT proc
	push rbp
	mov rbp,rsp
	mov rcx,rdx
	call Strlen
	
	sub rsp,8
	mov r8, rax
	mov rax, _Write
	mov rcx, STD_OUT
	lea r9, write
	push 0
	call rax
	add rsp,16                     ; Align stack after call func
	leave
	ret

_OUTPUT endp

Alloc proc
	;ptr = VirtualAlloc(NULL,size,MEM_RESERVE,PAGE_READWRITE); //reserving memory
	;ptr = VirtualAlloc(ptr,size,MEM_COMMIT,PAGE_READWRITE);  //commiting memory
	push rbp
	mov rbp,rsp
	sub rsp,20h
	mov [rbp-8],rcx
	mov [rbp-16],rdx
	
	mov rax,_VirtualAlloc
	mov rcx,0
	mov r8, MEM_RESERVE
	mov r9, PAGE_READWRITE
	call rax

	mov rcx,rax
	mov rax,_VirtualAlloc
	mov rdx,[rbp-16]
	mov r8, MEM_COMMIT
	mov r9, PAGE_READWRITE
	call rax

	add rsp,20h
	leave
	ret
Alloc endp

Free proc
	;VirtualFree(ptr, 0, MEM_RELEASE)    //releasing memory

	push rbp
	mov rbp,rsp
	sub rsp,40h
	mov rax, _VirtualFree
	mov rdx,0
	mov r8,MEM_RELEASE
	call rax

	leave
	ret
Free endp

;====================================================================================================================================================


Itoa proc                     ;rcx = int     rdx = address of string
	push rbp
	mov rbp,rsp
	sub rsp,8
	mov [rbp-8],rdx
	push rax
	push rbx
	push rdx
	push rsi
	xor rbx,rbx
	mov rax,rcx
	mov rsi,10
	Start_div:
		xor rdx,rdx
		div rsi
		add dl,30h
		push rdx
		inc rbx
		cmp rax,0
		je Tmp
		jmp Start_div
	Tmp:
		xor rsi,rsi
		mov rcx,[rbp-8]
		
	Pop_Itoa:
		cmp rbx,0
		je  End_Itoa
		pop rdx
		mov BYTE PTR [rcx+rsi],dl
		inc rsi
		dec rbx
		jmp Pop_Itoa
	End_Itoa:
		mov BYTE PTR [rcx+rsi],0dh
		pop	rsi
		pop rdx
		pop rbx
		pop rax
		add rsp,8
		leave
		ret
Itoa endp

Atoi proc              ; rcx = string -> Atoi in Num_int
	push rbp
	mov rbp,rsp
	push rax
	push rbx
	push rdx
	push rsi
	xor rsi,rsi
	xor rax,rax
	mov rbx,10
	Start_mul:
		cmp BYTE PTR [rcx + rsi],0dh
		je  End_mul
		xor rdx,rdx
		mov dl,BYTE PTR [rcx + rsi]
		sub dl,30h
		add rax,rdx                    ; s=s*10+a
		mul rbx
		inc rsi
		jmp Start_mul
		
	End_mul:
		div rbx
		mov num_int,rax
		pop rsi
		pop rdx
		pop rbx
		pop rax
		leave
		ret
Atoi endp

Reverse proc							; rcx = address of string
	push rbp
	mov rbp,rsp
	push rdx
	push rsi
	push rdi
	xor rdx,rdx
	xor rsi,rsi
	xor rdi,rdi
	Push_reverse:
		mov dl,byte ptr [rcx+rsi]
		push rdx
		inc rsi
		cmp byte ptr [rcx+rsi],0dh
		jne  Push_reverse
	Pop_reverse:
		pop rdx
		mov byte ptr [rcx+rdi],dl
		dec rsi
		inc rdi
		cmp rsi,0
		jne Pop_reverse
	End_reverse:
		pop rdi
		pop rsi
		pop rdx
		leave
		ret
		
Reverse endp

_Copy proc											;rcx = source            rdx = copy
	push rbp
	mov rbp,rsp
	push rsi
	push rbx
	xor rsi,rsi
	xor rbx,rbx
	
	Start_copy:
		cmp byte ptr [rcx+rsi],0dh
		je  End_copy
		mov bl,byte ptr [rcx+rsi]
		mov byte ptr [rdx+rsi],bl
		inc rsi
		jmp Start_copy
	End_copy:
		mov byte ptr [rdx+rsi],0dh
		pop rbx
		pop rsi
		leave
		ret
_Copy endp

Addition proc
	push rbp
	mov rbp,rsp
	sub rsp,18h
	mov [rbp-8h],rcx
	mov [rbp-10h],rdx
	mov [rbp-18h],r8								; address of result
	push rbx
	push rsi
	push rdi

	call Reverse
	mov rcx, [rbp-10h]
	CALL Reverse

	mov rcx,[rbp-8h]
	call Strlen
	mov rsi,rax										; rsi = length of num1

	mov rcx,[rbp-10h]
	call Strlen
	mov rdi,rax										; rdi = length of num2

	cmp rsi,rdi
	jg prepare2

	prepare1:
		mov rcx, [rbp-8h]							; lower
		mov rdx, [rbp-10h]							; Higher
		jmp Skip_prepare

	prepare2:
		mov rdx, [rbp-8h]
		mov rcx, [rbp-10h]
	Skip_prepare:
		xor rsi,rsi
		xor rdi,rdi
		xor r9,r9
		xor rbx,rbx
		mov byte ptr[mem],0
	Start_add:
		cmp byte ptr [rcx+rsi],0dh
		je  Next_add
		mov bl,byte ptr [rcx+rsi]
		mov bh,byte ptr [rdx+rdi]
		inc rsi
		inc rdi
		mov r9,1
		add bh,bl
		add bh,byte ptr [mem]
		sub bh,60h
		xor bl,bl
		cmp bh,10
		jl  Smaller

	Greater:
		sub bh,10
		add bh, 30h
		push rbx
		mov byte ptr [mem],1
		cmp r9,1
		je Start_add
		cmp r9,2
		je  Next_add

	Smaller:
		add bh, 30h
		push rbx
		mov byte ptr [mem],0
		cmp r9,1
		je Start_add
		cmp r9,2
		je  Next_add

	Next_add:
		cmp byte ptr [rdx+rdi],0dh
		je  Check_mem
		mov bh,byte ptr [rdx+rdi]
		inc rdi
		mov r9,2
		add bh,byte ptr[mem]
		sub bh,30h
		cmp bh,10
		jl  Smaller
		jmp Greater
	Check_mem:
		cmp byte ptr[mem],0
		je  Skip
		mov bh,31h
		push rbx
		inc rdi
	Skip:
		mov rcx,[rbp-18h]
		xor rsi,rsi
	Pop_to_res:
		cmp rdi,0
		je  End_add
		pop rbx
		mov byte ptr [rcx+rsi],bh
		inc rsi
		dec rdi
		jmp Pop_to_res

	End_add:
		mov byte ptr [rcx+rsi],0dh
		pop rdi
		pop rsi
		pop rbx
		add rsp,18h
		leave 
		ret
	



Addition endp

end