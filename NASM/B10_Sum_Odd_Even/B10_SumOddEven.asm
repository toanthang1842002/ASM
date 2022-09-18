%include 'Functions.asm'

section .data
endl db 0ah,0
count dq 0
size_array dq 1

checkd dq 0

zero db "0",0ah




msg1 db "The size of array: ",0ah,0
msg2 db "The number of array: ",0ah,0
msg3 db "Sum of Odd number : ",0ah,0
msg4 db "Sum of Even number : ",0ah,0
section .bss
    num resq 1
    n resq 1
    array resq 1
    SumOdd resq 1
    SumEven resq 1
section .text

global _start:
_start:
    mov rbp,rsp
;==================================
    ;======Dynamic allocation============================
    mov rdx,1000*10
    call Alloc
    mov [array],rax

    mov rdx,100*10
    call Alloc
    mov [n],rax

    mov rdx,11*10
    call Alloc
    mov [SumOdd],rax

    mov rdx,11*10
    call Alloc
    mov [SumEven],rax


;======Prepare============================
    xor r10,r10
    mov rcx,[SumEven]
    mov rdx, 0h
    call Itoa
    
    mov rcx,[SumOdd]
    mov rdx, 0h
    call Itoa
    
    mov r8, [size_array]
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

    mov byte [count],0
    mov r8,[size_array]
    mov rcx,[array]
    call Sum_odd_even
    
    End_array:
        mov rsi,msg3
        call writeCS

        mov rsi,[SumOdd]
        call writeCS
        
        mov rsi,endl
        call Endline
;==============================================

        mov rsi,msg4
        call writeCS

        mov rsi,[SumEven]
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

Sum_odd_even:
    push rbp
    mov rbp,rsp
    sub rsp,8h
    mov [rbp-8],rcx

    push rbx
    push rsi
    push rdi
    
    xor rdi,rdi
    mov rbx,2
    Find_number:
        cmp r8,0
        je End_sum_odd_even
        
        mov rax,[count]
        mov rcx,[array]
        mov rdx,[n]
        call Copy
        mov [count],rax
    Select_number:
        dec r8
        mov rcx,[n]
        call strlen

        xor rax,rax
        dec rdx
        mov al,byte [rcx+rdx]
        xor rdx,rdx
        div rbx
        cmp rdx,1
        je  Odd_number
        jmp Even_number

    Odd_number:
        push r8
        mov rcx,[n]
        mov rdx,[SumOdd]
        mov r8, [SumOdd]
        call Addition
        pop r8
        jmp Find_number
    Even_number:
        push r8
        mov rcx,[n]
        mov rdx,[SumEven]
        mov r8, [SumEven]
        call Addition
        pop r8
        jmp Find_number

    End_sum_odd_even:
        pop rdi
        pop rsi
        pop rbx
        add rsp,8
        leave
        ret
    
        



