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
; tcp_recv — получить ровно rdx байт из сокета (цикл до получения всех)
; rdi=sock, rsi=buf, rdx=len → rax=len (0=EOF/ошибка)
; ─────────────────────────────────────────────────────────────
tcp_recv:
    push rbx
    push r12
    push r13
    mov  r12, rdi          ; r12 = sock
    mov  r13, rsi          ; r13 = buf (сдвигается)
    mov  rbx, rdx          ; rbx = осталось прочитать
.recv_loop:
    test rbx, rbx
    jz   .recv_done
    mov  rax, 0            ; sys_read
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    syscall
    test rax, rax
    jle  .recv_eof         ; 0=закрыт, <0=ошибка
    add  r13, rax
    sub  rbx, rax
    jmp  .recv_loop
.recv_eof:
    xor  rax, rax
    jmp  .recv_ret
.recv_done:
    mov  rax, r13          ; ненулевой — успех
.recv_ret:
    pop  r13
    pop  r12
    pop  rbx
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
    sub  rsp, 8
    mov  rsi, rsp
    mov  rdx, 8
    call tcp_recv
    mov  rax, [rsp]
    add  rsp, 8
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
