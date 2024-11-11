[bits 64]

; A simple program that returns the actual date (month/day/year).

main:
    sub rsp, 8 ; Stack alignment before calling a function.
    sub rsp, 32 ; Shadow space.

    lea rcx, 0x00402000 ; .data section

    call [0x0040506C] ; "GetLocalTime"
    ; The result get returned into XMM0 (128 bit) register (register used for SIMD instruction).

    mov rcx, 0x00403000 ; .format section
    ; "pextrw" is an opcode that extrapolate the "imm8" word stored into xmm0 register. It works like a parser 
    ;  of the SYSTEMTIME struct.
    pextrw eax, xmm0, 2
    mov rdx, rax
    pextrw eax, xmm0, 1
    mov r8, rax
    pextrw eax, xmm0, 0
    mov r9, rax
    call [0x0040508C] ; "printf"
    add rsp, 32

    mov rcx, 3000 ; 3 seconds
    call [0x00405074] ; "Sleep"
    add rsp, 32

    call [0x0040507C] ; "ExitProcess"