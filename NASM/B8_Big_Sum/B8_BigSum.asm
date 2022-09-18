%include 'Functions.asm'

section .data
endl db 0ah,0
size_array dq 1
msg1 db "Number 1: ",0ah,0
msg2 db "Number 2: ",0ah,0
msg3 db "Result: ",0ah,0

section .bss
    n resq 1
    num1 resq 1
    array resq 1
section .text

global _start:
_start:
;======Dynamic allocation============================
    mov rdx,100
    call Alloc
    mov [array],rax

    mov rdx,100
    call Alloc
    mov [n],rax

    mov rdx,100
    call Alloc
    mov [num1],rax


;======Prepare============================

    mov rsi,msg1
    call writeCS

    mov r8,1
    call Get_Number

    xor rax,rax
    mov rcx,[array]
    mov rdx,[num1]
    call Copy_f_array

    mov rsi,msg2
    call writeCS

    mov r8,1
    call Get_Number

    xor rax,rax
    mov rcx,[array]
    mov rdx,[n]
    call Copy_f_array

    mov rcx,[num1]
    mov rdx,[n]
    mov r8, [n]
    call Addition

    mov rsi,msg3
    call writeCS

    mov rsi,[n]
    call writeCS

    mov rsi,endl
    call Endline

    call Exit

Get_Number:
    push rbp
    mov rbp,rsp
    Start_Get:
        mov rdx,100
        mov rsi,[n]
        call readCS

        xor rax,rax
        mov rcx,[n]
        mov rdx,[array]
        call Split_str

        cmp r8,0
        jne Start_Get
    leave
    ret