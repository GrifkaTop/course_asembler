; net.inc — сетевые хелперы и I/O
; Платформа: Linux x86-64, FASM
; Соглашение: System V AMD64 ABI

; ─────────────────────────────────────────────────────────────
; tcp_send — отправить буфер в сокет
; rdi=sock, rsi=buf, rdx=len → rax=bytes_sent
; ─────────────────────────────────────────────────────────────
tcp_send:
    mov rax, 1          ; sys_write
    syscall
    ret

; ─────────────────────────────────────────────────────────────
; tcp_recv — получить данные из сокета
; rdi=sock, rsi=buf, rdx=maxlen → rax=bytes_read (0=закрыт)
; ─────────────────────────────────────────────────────────────
tcp_recv:
    mov rax, 0          ; sys_read
    syscall
    ret

; ─────────────────────────────────────────────────────────────
; send_byte — отправить 1 байт в сокет
; rdi=sock, sil=byte
; ─────────────────────────────────────────────────────────────
send_byte:
    push rsi
    mov  rax, 1
    mov  rsi, rsp
    mov  rdx, 1
    syscall
    pop  rsi
    ret

; ─────────────────────────────────────────────────────────────
; send_u64 — отправить 8 байт (u64) в сокет
; rdi=sock, rsi=value
; ─────────────────────────────────────────────────────────────
send_u64:
    push rsi
    mov  rax, 1
    mov  rsi, rsp
    mov  rdx, 8
    syscall
    pop  rsi
    ret

; ─────────────────────────────────────────────────────────────
; recv_u64 — получить 8 байт из сокета
; rdi=sock → rax=value
; ─────────────────────────────────────────────────────────────
recv_u64:
    push rbx
    sub  rsp, 8
    mov  rax, 0
    mov  rsi, rsp
    mov  rdx, 8
    syscall
    mov  rax, [rsp]
    add  rsp, 8
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; print_str — вывод строки (null-terminated) в stdout
; rdi=str
; ─────────────────────────────────────────────────────────────
print_str:
    push rdi
    xor  rdx, rdx
.count:
    cmp  byte [rdi + rdx], 0
    je   .print
    inc  rdx
    jmp  .count
.print:
    mov  rax, 1
    mov  rsi, rdi
    mov  rdi, 1
    syscall
    pop  rdi
    ret

; ─────────────────────────────────────────────────────────────
; print_str_n — вывод строки длиной n в stdout
; rdi=str, rsi=len
; ─────────────────────────────────────────────────────────────
print_str_n:
    mov  rdx, rsi
    mov  rsi, rdi
    mov  rdi, 1
    mov  rax, 1
    syscall
    ret

; ─────────────────────────────────────────────────────────────
; read_line — читать строку из stdin до \n или maxlen
; читает по 1 байту — корректно работает с pipe и tty
; rdi=buf, rsi=maxlen → rax=bytes_read
; null-терминирует результат, \n не включается
; ─────────────────────────────────────────────────────────────
read_line:
    push rbx
    push r12
    push r13

    mov  r12, rdi       ; r12 = buf
    mov  r13, rsi       ; r13 = maxlen
    dec  r13            ; место для \0
    xor  rbx, rbx       ; rbx = счётчик

.byte_loop:
    cmp  rbx, r13
    jge  .done

    mov  rax, 0         ; sys_read
    xor  rdi, rdi       ; stdin
    lea  rsi, [r12 + rbx]
    mov  rdx, 1
    syscall

    test rax, rax
    jle  .done          ; EOF или ошибка

    cmp  byte [r12 + rbx], 10   ; '\n'?
    je   .done

    inc  rbx
    jmp  .byte_loop

.done:
    mov  byte [r12 + rbx], 0
    mov  rax, rbx
    pop  r13
    pop  r12
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; parse_ip — парсинг "x.x.x.x" → 4 байта по адресу rdi
; rsi=строка IP, rdi=куда писать
; (взято из примера client_tictactoe.asm)
; ─────────────────────────────────────────────────────────────
parse_ip:
    push rbx
    push rcx
    push rdx

    xor eax, eax
    xor ecx, ecx
    xor rdx, rdx

.next_char:
    mov  bl, [rsi]
    inc  rsi

    cmp  bl, '.'
    je   .save_byte
    cmp  bl, 10
    je   .finish
    cmp  bl, 0
    je   .finish

    sub  bl, '0'
    movzx rbx, bl
    imul ecx, 10
    add  ecx, ebx
    jmp  .next_char

.save_byte:
    mov  [rdi], cl
    inc  rdi
    xor  ecx, ecx
    jmp  .next_char

.finish:
    mov  [rdi], cl
    pop  rdx
    pop  rcx
    pop  rbx
    ret
