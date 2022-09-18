writeCS:
    mov rcx,rsi
    call strlen
    mov rdi,1            ;STD_OUT
    mov rax,1            ;SYS_write
    syscall
    ret

readCS:
    mov rdi,0           ;STD_IN
    mov rax,0           ;SYS_READ
    syscall
    ret
Exit:
    xor rdi,rdi         ;value
    mov rax,60          ;SYS_exit
    syscall

strlen:                     ; rcx = address of string       ; rdx = length of string
    push rbp
    mov rbp,rsp
    push rsi
    xor rsi,rsi 

    Start_count:
        cmp byte [rcx+rsi],0ah
        je End_count
        inc rsi
        jmp Start_count
    End_count:
        mov rdx,rsi 
        pop rsi
        leave
        ret

Uppercase: ; rcx = address of string
    push rbp
    mov rbp,rsp
    push rsi
    push rdi
    push rdx
    xor rsi,rsi
    xor rdi,rdi
    Start_upper:
        cmp byte [rcx+rsi],0ah
        je End_upper
        mov dl, BYTE [rcx+rsi]
        cmp dl, 'a'
        jl  skip_upper  
    Next_upper:
        cmp dl, 'z'
        jg  skip_upper
        sub dl, 20h
        mov BYTE [rcx+rsi], dl
    skip_upper:
        inc rsi
        jmp Start_upper
    End_upper:
        mov byte [rcx+rsi], 0ah
        pop rdx
        pop rdi
        pop rsi
        leave 
        ret

Endline:
    mov rdx,2
    mov rdi,1            ;STD_OUT
    mov rax,1            ;SYS_write
    syscall
    ret

Itoa:             ; rdx = int      rcx = string
    push rbp
    mov rbp,rsp
    push rsi
    push rax
    push rbx
    xor rbx,rbx
    mov rsi,10
    mov rax,rdx
    Start_div:
        xor rdx,rdx
        div rsi
        add dl,30h
        push rdx
        inc rbx
        cmp rax,0
        jne Start_div

    xor rsi,rsi
    Pop_Itoa:
        cmp rbx,0
        je End_Itoa
        pop rdx
        mov BYTE [rcx+rsi],dl
        dec rbx
        inc rsi
        jmp Pop_Itoa
    End_Itoa:
        mov byte [rcx+rsi], 0ah
        pop rbx
        pop rax
        pop rsi
        leave
        ret

Atoi:            ;rax = int      rcx = string
    push rbp
    mov rbp,rsp
    push rsi
    push rbx
    push rdx
    xor rsi,rsi
    mov rbx,10
    xor rax,rax
    Start_atoi:
        cmp byte [rcx+rsi],0ah
        je End_atoi
        cmp byte [rcx+rsi],20h
        je  End_atoi
        xor rdx,rdx
        mov dl, BYTE [rcx+rsi]
        sub dl, 30h
        add rax, rdx
        mul rbx
        inc rsi
        jmp Start_atoi
    End_atoi:
        div rbx
        pop rdx
        pop rbx
        pop rsi
        leave
        ret



Addition:              ; rcx = address of high  rdx = address of low   r8= res
    push rbp
    mov rbp,rsp
    sub rsp,18h
    push rsi
    push rdi
    push rax
    push rbx
    mov [rbp-8],rcx
    mov [rbp-10h],rdx
    mov [rbp-18h],r8
    xor rbx,rbx  ; rbx = mem        
    mov r9,1

    mov rcx,[rbp-8]
    call Reverse

    mov rcx,[rbp-16]
    call Reverse

    mov rcx,[rbp-8]
    call strlen
    mov rdi,rdx                ; strlen of string 1

    mov rcx,[rbp-16]
    call strlen
    mov rsi,rdx                ; strlen of string 2

    cmp rdi,rsi
    jg  Prepare_1
    cmp rdi,rsi
    jl  Prepare_2

    Prepare_1:
        mov rcx,[rbp-8]
        mov rdx,[rbp-16]
        jmp Skip_prepare
    Prepare_2:
        mov rcx,[rbp-16]
        mov rdx,[rbp-8]
        jmp Skip_prepare
    Skip_prepare:
    xor rsi,rsi
    xor rdi,rdi
    Start_add:
        cmp BYTE [rdx+rsi],0ah
        je Next_add
        cmp BYTE [rdx+rsi],20h
        je Next_add
        xor rax,rax
        mov ah, BYTE [rcx+rsi]
        mov al, BYTE [rdx+rsi]
        inc rsi
        sub ah,30h
        sub al,30h
        add ah, al
        add ah, bl
        cmp ah,10 
        jl  low_than
        jmp great_than
    Next_add:
        mov r9,2 
        cmp BYTE [rcx+rsi],0ah
        je Check_mem  
        mov ah, BYTE [rcx+rsi]
        inc rsi  
        sub ah,30h
        add ah,bl
        cmp ah,10 
        jl  low_than
        jmp great_than
    low_than:
        xor al,al
        add ah,30h
        mov bl,0
        push rax
        cmp r9,1
        je  Start_add
        jmp Next_add
    great_than:
        xor al,al
        sub ah,10 
        add ah,30h
        mov bl,1
        push rax
        cmp r9,1
        je  Start_add
        jmp Next_add
    
    Check_mem:
        cmp bl,0 
        je  Temp_add
        mov ah,1
        add ah,30h
        push rax
        inc rsi 
    
    Temp_add:
        xor rcx,rcx
        xor rdi,rdi
        mov rcx,[rbp-18h]
    Pop_st:
        cmp rsi,0 
        je End_add
        pop rax
        mov byte [rcx+rdi],ah
        inc rdi
        dec rsi 
        jmp Pop_st

    End_add:
        mov byte[rcx+rdi], 0ah
        pop rbx
        pop rax
        pop rdi
        pop rsi
        add rsp,18h
        leave
        ret


Reverse:                      ; rcx = address of string
    push rbp
    mov rbp,rsp
    push rsi
    push rdi
    push rdx
    xor rsi,rsi
    xor rdi,rdi
    Start_reverse:
        xor rdx,rdx
        mov dl, BYTE [rcx+rsi]
        push rdx
        inc rsi
        cmp BYTE [rcx+rsi],0ah
        jne Start_reverse
    Pop_reverse:
        dec rsi
        pop rdx
        mov BYTE [rcx+rdi],dl
        inc rdi
        cmp rsi,0
        jne Pop_reverse
    End_reverse:
        mov byte [rcx+rdi], 0ah
        pop rdx
        pop rdi
        pop rsi
        leave
        ret


Copy:            ; rcx = array  rdx=copy
    push rbp
    mov rbp,rsp
    push rdi
    push rsi
    xor rdi,rdi
    mov rsi,rax
    Start_copy_f_array:
        cmp BYTE [rcx+rsi],0ah
        je End_copy_f_array
        cmp BYTE [rcx+rsi],20h
        je End_copy_f_array
        xor rax,rax
        mov al, BYTE [rcx+rsi]
        mov BYTE [rdx+rdi],al
        inc rsi
        inc rdi
        jmp Start_copy_f_array
    End_copy_f_array:
        mov BYTE [rdx+rdi],0ah
        inc rsi
        mov rax,rsi
        pop rsi
        pop rdi
        leave
        ret


Alloc:                          ;rdx = size of string
	push rbp
	mov rbp, rsp
	xor rdi, rdi
	mov rax, 0x0c
	syscall
	mov rdi,rdx
	add rax, rdi
	mov rdi, rax
	mov rax, 0x0c
	syscall
    sub rax,rdx
	leave
	ret

Split_str:
    push rbp
	mov rbp,rsp
	sub rsp,10h
	mov [rbp-8],rcx           ;str
    mov [rbp-10h],rdx         ; array
                              ; r8= size_array
                              ; rax = count
	push rbx
	push rdi
	push rsi
    mov rsi,rax
	xor rdi,rdi

	check_space:
		cmp byte [rcx+rdi],0ah
		je End_split
		cmp byte [rcx+rdi],20h
		jne  Start_split
		inc rdi
		jmp check_space

	Start_split:
		cmp BYTE [rcx+rdi],0ah
		je  change_str
		cmp BYTE [rcx+rdi],20h
		je  change_str
		xor rbx,rbx
		mov bl, BYTE [rcx+rdi]
		mov BYTE [rdx+rsi],bl
		inc rdi
        inc rsi
		jmp Start_split

    change_str:
        mov BYTE [rdx+rsi],20h
        inc rsi
        dec r8
        cmp r8,0
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