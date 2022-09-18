%include 'Functions.asm'

section .data
endl db 0ah,0
count dq 0
time  dq 0

msg1 db "Input: ",0ah,0
msg2 db "Output: ",0ah,0

section .bss
    string resq 1
section .text

global _start:
_start:
;======Dynamic allocation============================
    mov rdx,300
    call Alloc
    mov [string],rax


;======Dynamic allocation============================


    mov rsi,msg1
    call writeCS

    mov rdx, 300
    mov rsi,[string]
    call readCS

;=============================================================
    mov rcx,[string]
    call Reverse

    mov rsi,msg2
    call writeCS

    mov rsi,[string]
    call writeCS

    mov rsi,endl
    call Endline

    call Exit
