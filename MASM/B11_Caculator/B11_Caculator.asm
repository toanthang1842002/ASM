.data
Operator db "Select operator:", 0Ah, "1. Addition", 0Ah, "2. Subtraction", 0Ah, "3. Multiply", 0Ah, "4. Division", 0Ah,"5. Exit",0ah,0dh
Option_  db "Your option: ",0dh
msg1 db "Number 1: ",0dh
msg2 db "Number 2: ",0dh
msg3 db "Result: ",0dh
msg5 db "Remainder: ",0dh
msg4 db 0ah,"GoodBye: ",0dh
endline   db 0ah,0dh	

fVirtualAlloc db "VirtualAlloc", 0
fVirtualFree db "VirtualFree", 0
fwrite db "WriteConsole",0
fGetStdHandle db "GetStdHandle", 0
fexit db "ExitProcess", 0
fread db "ReadConsole",0
end_line db 0ah,0dh
num2 dq 0
num1  dq 0
mem dq 0
num_int dq 0
size_array dq 0
checkd dq 0 

.data?

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

opt dq 5 dup (?)
res dq 5 dup (?) 
number1   dq 5 dup(?)
number2   dq 5 dup(?)



.code

main proc
	call init

	lea rcx,number1
	mov rdx,100
	call Alloc
	mov number1,rax

	lea rcx,number2
	mov rdx,100
	call Alloc
	mov number2,rax

	lea rcx,res
	mov rdx,100
	call Alloc
	mov res,rax

	Start_opt:

	lea rdx,Operator
	call _OUTPUT

	lea rdx,Option_
	call _OUTPUT

	lea rdx,opt
	mov r8,10
	call _INPUT

	lea rcx,opt
	call Atoi
	mov r8,num_int


	cmp r8,1
	je  Add_

	cmp r8,2
	je  Sub_

	cmp r8,3
	je  Mul_

	cmp r8,4
	je  Div_

	jmp End_calc

	Add_:
		call scan_number
		add rax,rbx
		jmp print_res

	Sub_:
		call scan_number
		cmp rax,rbx
		jl  Change_value
		sub rax,rbx
		jmp print_res

	Change_value:
		xchg rax,rbx
		sub rax,rbx
		jmp print_res
	Mul_:
		call scan_number
		mul rbx
		jmp print_res
	Div_:
		call scan_number
		div rbx
		mov rcx,rdx
		mov rdx,res
		call Itoa

		lea rdx,msg5
		call _OUTPUT

		mov rdx,res
		call _OUTPUT

		lea rdx,endline
		call _OUTPUT
		jmp print_res
	print_res:
		mov rcx,rax
		mov rdx,res
		call Itoa

		lea rdx,msg3
		call _OUTPUT
	
		mov rdx,res
		call _OUTPUT

		lea rdx,endline
		call _OUTPUT
		lea rdx,endline
		call _OUTPUT

		jmp Start_opt

	End_calc:

	
	lea rdx,msg4
	call _OUTPUT

	mov rcx,number1
	call Free

	mov rcx,number2
	call Free

	mov rcx,res
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
		cmp BYTE PTR [rcx + rsi],20h
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



scan_number proc
	push rbp
	mov rbp,rsp

	lea rdx,msg1
	call _OUTPUT

	mov r8,100
	mov rdx,number1
	call _INPUT

	lea rdx,msg2
	call _OUTPUT

	mov r8,100
	mov rdx,number2
	call _INPUT

	mov rcx,number1
	call Atoi
	mov rcx,num_int
	mov rax,rcx

	mov rcx,number2
	call Atoi
	mov rcx,num_int
	mov rbx,rcx

	leave
	ret
scan_number endp

end