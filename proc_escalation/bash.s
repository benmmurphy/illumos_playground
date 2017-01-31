        .global _start

        .text
_start:
        #setuid
        mov $23, %rax
        mov $0, %rdi
        syscall
        #setgid
        mov $46, %rax
        mov $0, %rdi
        syscall

        #execve
        mov $59, %rax
        mov $bash, %rdi
        mov $args, %rsi
        mov $0, %rdx
        syscall

        # exit(0)
        mov     $1, %rax               # system call 60 is exit
        mov     $1, %rdi
        syscall                         # invoke operating system to exit

.data

.section .rodata

bash:
        .ascii "/bin/bash\0"

args:
        .quad bash
        .quad 0
