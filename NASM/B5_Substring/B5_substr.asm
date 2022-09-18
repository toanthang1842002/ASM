%include 'Functions.asm'

section .data
endl db 0ah,0
count dq 0
time  dq 0

msg1 db "string 1: ",0ah,0
msg2 db "string 2: ",0ah,0
msg3 db "The number of occurrences: ",0ah,0
msg4 db "Position: ",0ah,0
section .bss
    string resq 100
    str1 resq 1
    str2 resq 1
    res resq  1
    res_times resq 1
section .text

global _start:
_start:
;======Dynamic allocation============================
    mov rdx,1000
    call Alloc
    mov [str1],rax

    mov rdx,10
    call Alloc
    mov [str2],rax

    mov rdx,100*10
    call Alloc
    mov [res],rax

    mov rdx,10
    call Alloc
    mov [res_times],rax

    mov rdx,100
    call Alloc
    mov [string],rax

;======Dynamic allocation============================


    mov rsi,msg1
    call writeCS

    mov rdx,1000
    mov rsi,[str1]
    call readCS

    mov rsi,msg2
    call writeCS

    mov rdx,10
    mov rsi,[str2]
    call readCS
;=============================================================
    mov rcx,[str1]
    mov rdx,[str2]
    call Substring

    mov rsi,msg3
    call writeCS

    mov rcx,[res_times]
    mov rdx,[time]
    call Itoa

    mov rsi,[res_times]
    call writeCS

    mov rsi,endl
    call Endline

    mov rsi,msg4
    call writeCS

    mov rsi,[res]
    call writeCS

    mov rsi,endl
    call Endline

    call Exit

Substring:
    push rbp
    mov rbp,rsp
    sub rsp,10h
    mov [rbp-8],rcx                     ; string
    mov [rbp-10h], rdx                  ; substring
    push rax
    push rbx
    push rdi
    push rsi

    xor rsi,rsi
    xor rdi,rdi
    xor rbx,rbx

    Start_find:
        cmp byte [rcx+rsi],0ah
        je  End_find
        mov bh,byte [rcx+rsi]
        mov bl,byte [rdx]
        cmp bh,bl
        je Next_find
        inc rsi
        jmp Start_find

    Next_find:
        cmp byte [rdx+rdi],0ah
        je  push_pos
        mov bh,byte [rcx+rsi]
        mov bl,byte [rdx+rdi]
        inc rsi
        inc rdi
        cmp bh,bl
        je  Next_find

    Temp_find:
        sub rsi,rdi
        inc rsi
        xor rdi,rdi
        jmp Start_find

    push_pos:
        sub rsi,rdi
        mov rdx,rsi
        mov rcx,[string]
        call Itoa

        mov rcx,[string]
        mov rdx,[res]
        call Push_positions

        inc byte[time]
        inc rsi
        xor rdi,rdi

        mov rcx,[rbp-8h]
        mov rdx,[rbp-10h]

        jmp Start_find

    End_find:
        pop rsi
        pop rdi
        pop rbx
        pop rax
        add rsp,10h
        leave
        ret
    
Push_positions:                     ; rcx = string    rdx = res copy
    push rbp
    mov rbp,rsp
    push rdi
    push rsi
    push rbx
    xor rsi,rsi
    xor rdi,rdi
    mov rdi,[count]                     ; count = next position at [res_times]
    Start_push:
        cmp BYTE [rcx+rsi],0ah
        je End_push
        xor rbx,rbx
        mov bl, BYTE [rcx+rsi]
        mov BYTE [rdx+rdi],bl
        inc rsi
        inc rdi
        jmp Start_push
    End_push:
        mov BYTE [rdx+rdi],20h
        inc rdi
        mov BYTE [rdx+rdi],0ah
        mov [count],rdi                 ; save r10
        pop rbx
        pop rsi
        pop rdi
        leave
        ret