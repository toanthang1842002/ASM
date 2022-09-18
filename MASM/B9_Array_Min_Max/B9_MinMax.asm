.data
msg1   db "Size of array : ",0dh
msg2   db "Number of array : ",0dh
msg3   db "Min : ",0dh
msg4   db "Max : ",0dh
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
num_int dq 0
size_array dq 1
checkd dq 0 

.data?
num dq 1 dup(?)
min dq 1 dup(?)
max dq 1 dup(?)



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
array   dq 5 dup(?)



.code

main proc
	call init
	;dynamic allocation==================================================================
	lea rcx,array
	mov rdx,100*10
	call Alloc
	mov array,rax

	lea rcx,min
	mov rdx,100
	call Alloc
	mov min,rax

	lea rcx,max
	mov rdx,100
	call Alloc
	mov max,rax

	lea rcx,n
	mov rdx,100
	call Alloc
	mov n,rax

	;dynamic allocation==================================================================

	mov rcx,0ffffffffh
	mov rdx,min
	call Itoa

	mov rcx,0h
	mov rdx,max
	call Itoa

	lea rdx,msg1
	call _OUTPUT

	mov r8,30
	call Get_element

	mov rcx,array
	call Atoi
	mov rcx,num_int
	mov size_array,rcx

	lea rdx,msg2
	call _OUTPUT

	mov r8,100											; r8 = size of input
	call Get_element

	mov rcx,num_int
	mov size_array,rcx
	call Find_MIN_MAX

	End_array:

	lea rdx,msg3
	call _OUTPUT

	mov rdx,min
	call _OUTPUT

	lea rdx,endline
	call _OUTPUT

	lea rdx,msg4
	call _OUTPUT

	mov rdx,max
	call _OUTPUT

	mov rcx,array
	call Free

	mov rcx,min
	call Free

	mov rcx,max
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



Compare_str proc
	push rbp
    mov rbp,rsp
    sub rsp,10h
    mov [rbp-8h],rcx
    mov [rbp-10h],rdx
    push rbx
    push rdi
    push rsi
    xor rdi,rdi

    cmp_len:
        cmp byte ptr [rcx+rdi],0dh
        je  Check_2
        cmp byte ptr [rdx+rdi],0dh
        je  Check_1
        inc rdi
        jmp cmp_len

    Check_1:
        cmp byte ptr [rcx+rdi],0dh
        jne Mark_2
        jmp Skip_cmp

    Check_2:
        cmp byte ptr [rdx+rdi],0dh
        jne Mark_1
        jmp Skip_cmp

    Skip_cmp:
        xor rdi,rdi
        mov rsi,[count]

    Cmp_equal_str:
        cmp byte ptr [rdx+rdi],0dh
        je  Mark_3
        xor rbx,rbx
        mov bh, byte ptr [rcx+rdi]
        mov bl, byte ptr [rdx+rdi]
        inc rdi
        cmp bh,bl
        jl  Mark_1
        cmp bh,bl
        jg  Mark_2
        jmp Cmp_equal_str
        
    Mark_1:
        mov byte ptr [checkd],1
        jmp End_str_cmp

    Mark_2:
        mov byte ptr [checkd],2
        jmp End_str_cmp
    
    Mark_3:
        mov byte ptr [checkd],3
        jmp End_str_cmp
    
    End_str_cmp:
        pop rdi
        pop rbx
        add rsp,10h
        leave
        ret


Compare_str endp

Find_MIN_MAX proc
    push rbp
    mov rbp,rsp

    push rax
    push rdi
    push rsi
	mov count,0
    Start_find_MIN_MAX:
        cmp size_array,0
        je End_find_MIN_MAX
        
        mov rcx,array
        mov rdx,n
        mov rax,count
        call Copy
        mov count,rax


    Cmp_MIN:
        mov rcx,n
        mov rdx,min
        call Compare_str

        cmp byte ptr [checkd],1
        je   Copy_MIN
    
    Cmp_MAX:
        mov rcx,n
        mov rdx,max
        call Compare_str

        dec size_array

        cmp byte ptr [checkd],2
        je   Copy_MAX
        jmp Start_find_MIN_MAX
    
    Copy_MAX:
		xor rax,rax
        mov rcx,n
        mov rdx,max
        call Copy
        jmp Start_find_MIN_MAX

     Copy_MIN:
		xor rax,rax
        mov rcx,n
        mov rdx,min
        call Copy
        jmp Cmp_MAX

    End_find_MIN_MAX:
        pop rsi
        pop rdi
        pop rax
        leave
        ret
Find_MIN_MAX endp

Split_str proc
    push rbp
	mov rbp,rsp
	sub rsp,10h
	mov [rbp-8],rcx           ;str
    mov [rbp-10h],rdx         ; array                         
                              ; rax = count
	push rbx
	push rdi
	push rsi
    mov rsi,rax
	xor rdi,rdi

	check_space:
		cmp byte ptr [rcx+rdi],0dh
		je End_split
		cmp byte ptr [rcx+rdi],20h
		jne  Start_split
		inc rdi
		jmp check_space

	Start_split:
		cmp BYTE ptr [rcx+rdi],0dh
		je  change_str
		cmp BYTE ptr [rcx+rdi],20h
		je  change_str
		xor rbx,rbx
		mov bl, BYTE ptr [rcx+rdi]
		mov BYTE ptr [rdx+rsi],bl
		inc rdi
        inc rsi
		jmp Start_split

    change_str:
        mov BYTE ptr [rdx+rsi],20h
        inc rsi
        dec size_array
        cmp size_array,0
        je  End_split
        jmp check_space
    End_split:
        mov rax,rsi
        pop rsi
        pop rdi
        pop rbx
        add rsp,10h
        leave
        ret

Split_str endp

Get_element proc
    push rbp
    mov  rbp,rsp

	mov count,0h
    Loop_get:
        push r8
        mov rdx,n
		call _INPUT

        mov rax,count
        mov rcx,n
        mov rdx,array
        call Split_str
        mov count,rax

		pop r8
        cmp size_array,0
        jne Loop_get
    leave
    ret
Get_element endp

Copy proc									; rcx = array  rdx=copy
    push rbp
    mov rbp,rsp
    push rdi
    push rsi
    xor rdi,rdi
    mov rsi,rax
    Start_copy:
        cmp BYTE ptr [rcx+rsi],0dh
        je End_copy
        cmp BYTE ptr [rcx+rsi],20h
        je End_copy
        xor rax,rax
        mov al, BYTE ptr [rcx+rsi]
        mov BYTE ptr [rdx+rdi],al
        inc rsi
        inc rdi
        jmp Start_copy
    End_copy:
        mov BYTE ptr [rdx+rdi],0dh
        inc rsi
        mov rax,rsi
        pop rsi
        pop rdi
        leave
        ret
Copy endp
end