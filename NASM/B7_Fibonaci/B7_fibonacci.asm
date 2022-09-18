%include 'Functions.asm'

section .data
endl db 0ah,0
size_array dq 1
msg1 db "Input: ",0ah,0
msg2 db "Output: ",0ah,0

section .bss
    num resq 1
    n resq 1
    fibo1 resq 1
    fibo2 resq 1
    fibo0 resq 1
    array resq 1
section .text

global _start:
_start:
;======Dynamic allocation============================
    mov rdx,100*10
    call Alloc
    mov [array],rax

    mov rdx,30
    call Alloc
    mov [n],rax

    mov rdx,30
    call Alloc
    mov [fibo1],rax

    mov rdx,30
    call Alloc
    mov [fibo0],rax

    mov rdx,30
    call Alloc
    mov [fibo2],rax


;======Prepare============================
    mov rdx,0h
    mov rcx,[fibo0]
    call Itoa

    mov rdx,1h
    mov rcx,[fibo1]
    call Itoa


    mov r8, [size_array]
    mov rsi,msg1
    call writeCS

    Start_B7:
        mov rdx,30
        mov rsi,[n]
        call readCS

        xor rax,rax
        mov rcx,[n]
        mov rdx,[array]
        call Split_str

        cmp r8,0
        jne Start_B7

;=============================================================
    mov rcx,[array]
    call Atoi
    mov [size_array],rax        

    mov rsi,msg2
    call writeCS

    mov rsi,endl
    call Endline

    cmp byte [size_array],0h
    je  Zero

    First:
        mov rsi,[fibo1]
        call writeCS

        mov rsi,endl
        call Endline
        dec byte [size_array]

    Start_fibo:
        cmp byte [size_array],0h
        je  End_fibo

        mov rcx,[fibo0]
        mov rdx,[fibo1]
        mov r8, [fibo2]
        call Addition

        mov rcx,[fibo1]
        call Reverse

        mov rcx,[fibo1]
        mov rdx,[fibo0]
        call Copy

        mov rcx,[fibo2]
        mov rdx,[fibo1]
        call Copy

        mov rsi,[fibo2]
        call writeCS

        mov rsi,endl
        call Endline

        dec byte [size_array]
        jmp Start_fibo
    Zero:
        mov rsi,[fibo0]
        call writeCS

    End_fibo:
    mov rsi,endl
    call Endline

    call Exit
