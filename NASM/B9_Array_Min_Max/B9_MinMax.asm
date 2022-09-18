%include 'Functions.asm'

section .data
endl db 0ah,0
count      dq 0
size_array dq 1
checkd     dq 0
msg1 db "Size of array: ",0ah,0
msg2 db "Number of array: ",0ah,0

msg3 db "Min: ",0ah,0

msg4 db "Max: ",0ah,0

section .bss
    num resq 1
    n resq 1
    array resq 1
    MAX resq 1
    MIN resq 1
section .text

global _start:
_start:
;======Dynamic allocation============================
    mov rdx,1000*10
    call Alloc
    mov [array],rax

    mov rdx,100*10
    call Alloc
    mov [n],rax

    mov rdx,30
    call Alloc
    mov [MAX],rax

    mov rdx,30
    call Alloc
    mov [MIN],rax


;======Prepare============================
    xor r10,r10
    mov rcx,[MIN]
    mov rdx, 0FFFFFFFFh
    call Itoa
    
    mov rcx,[MAX]
    mov rdx, 0h
    call Itoa
    
    mov rsi,msg1
    call writeCS
    
    mov r8, [size_array]
    mov byte [count],0
    mov rdx,30
    call Get_element

;=============================================================
    mov rcx,[array]
    call Atoi
    mov [size_array],rax        
    mov r8,rax                        ; r8 = size of array

    mov rsi,msg2
    call writeCS

    mov byte [count],0
    mov rdx,100
    call Get_element

    mov byte [count],0h
    mov r8,[size_array]
    mov rcx,[array]
    call Find_MIN_MAX

    mov rsi,msg3
    call writeCS

    mov rsi,[MIN]
    call writeCS

    mov rsi,endl
    call Endline

    mov rsi,msg4
    call writeCS

    mov rsi,[MAX]
    call writeCS

    mov rsi,endl
    call Endline

    call Exit


Get_element:
    push rbp
    mov  rbp,rsp
    Loop_get:
        push rdx
        mov rsi,[n]
        call readCS


        mov rax,[count]
        mov rcx,[n]
        mov rdx,[array]
        call Split_str
        mov [count],rax

        pop rdx
        cmp r8,0
        jne Loop_get

    leave
    ret


Find_MIN_MAX:
    push rbp
    mov rbp,rsp

    push rax
    push rdi
    push rsi

    Start_find_MIN_MAX:
        cmp r8,0
        je End_find_MIN_MAX
        
        mov rcx,[array]
        mov rdx,[n]
        mov rax,[count]
        call Copy
        mov [count],rax


    Cmp_MIN:
        mov rcx,[n]
        mov rdx,[MIN]
        call Str_cmp

        cmp byte [checkd],1
        je   Copy_MIN
    
    Cmp_MAX:
        mov rcx,[n]
        mov rdx,[MAX]
        call Str_cmp

        dec r8

        cmp byte [checkd],2
        je   Copy_MAX
        jmp Start_find_MIN_MAX
    
    Copy_MAX:
        xor rax,rax
        mov rcx,[n]
        mov rdx,[MAX]
        call Copy
        jmp Start_find_MIN_MAX

     Copy_MIN:
        xor rax,rax
        mov rcx,[n]
        mov rdx,[MIN]
        call Copy
        jmp Cmp_MAX

    End_find_MIN_MAX:
        pop rsi
        pop rdi
        pop rax
        leave
        ret

Str_cmp:                    ;rcx = array     rdx = MAX or MIN
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
        cmp byte [rcx+rdi],0ah
        je  Check_2
        cmp byte [rdx+rdi],0ah
        je  Check_1
        inc rdi
        jmp cmp_len

    Check_1:
        cmp byte [rcx+rdi],0ah
        jne Mark_2
        jmp Skip_cmp

    Check_2:
        cmp byte [rdx+rdi],0ah
        jne Mark_1
        jmp Skip_cmp

    Skip_cmp:
        xor rdi,rdi
        mov rsi,[count]

    Cmp_equal_str:
        cmp byte [rdx+rdi],0ah
        je  Mark_3
        xor rbx,rbx
        mov bh, byte [rcx+rdi]
        mov bl, byte [rdx+rdi]
        inc rdi
        cmp bh,bl
        jl  Mark_1
        cmp bh,bl
        jg  Mark_2
        jmp Cmp_equal_str
        
    Mark_1:
        mov byte [checkd],1
        jmp End_str_cmp

    Mark_2:
        mov byte [checkd],2
        jmp End_str_cmp
    
    Mark_3:
        mov byte [checkd],3
        jmp End_str_cmp
    
    End_str_cmp:
        pop rdi
        pop rbx
        add rsp,10h
        leave
        ret