; keygen.asm — утилита генерации ключей пользователя
; Использование: ./keygen  → создаёт файл username.key
;
; Формат файла .key (56 байт):
;   [0-7]   n   (u64) — модуль
;   [8-15]  e   (u64) — публичный экспонент (65537)
;   [16-23] d   (u64) — приватный экспонент
;   [24-55] username (32 байта, null-padded)

format ELF64
public _start

include 'proto.inc'
include 'crypto.inc'
include 'net.inc'

KEY_FILE_SIZE equ 24 + USERNAME_LEN   ; 56 байт

; ─────────────────────────────────────────────────────────────
section '.data' writable
    msg_enter   db "Введите имя пользователя: ", 0
    msg_saved   db "Ключи сохранены в файл: ", 0
    msg_newline db 10, 0
    msg_err     db "Ошибка создания файла!", 10, 0
    dot_key     db ".key", 0

; ─────────────────────────────────────────────────────────────
section '.bss' writable
    username    rb USERNAME_LEN + 1
    key_n       rq 1
    key_e       rq 1
    key_d       rq 1
    filename    rb USERNAME_LEN + 8     ; "username.key\0"
    key_buf     rb KEY_FILE_SIZE        ; буфер для записи в файл

; ─────────────────────────────────────────────────────────────
section '.text' executable

_start:
    ; 1. Запрашиваем имя пользователя
    mov  rdi, msg_enter
    call print_str

    mov  rdi, username
    mov  rsi, USERNAME_LEN
    call read_line

    ; 2. Генерируем ключевую пару
    lea  rdi, [key_n]
    lea  rsi, [key_e]
    lea  rdx, [key_d]
    call rsa_keygen

    ; 3. Заполняем буфер для файла
    mov  rax, [key_n]
    mov  qword [key_buf],      rax
    mov  rax, [key_e]
    mov  qword [key_buf + 8],  rax
    mov  rax, [key_d]
    mov  qword [key_buf + 16], rax

    ; копируем username в key_buf+24
    lea  rsi, [username]
    lea  rdi, [key_buf + 24]
    mov  rcx, USERNAME_LEN
    rep  movsb

    ; 4. Строим имя файла: username + ".key\0"
    lea  rdi, [filename]
    lea  rsi, [username]
.copy_name:
    mov  al, [rsi]
    test al, al
    jz   .copy_name_done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    jmp  .copy_name
.copy_name_done:
    mov byte [rdi],   '.'
    mov byte [rdi+1], 'k'
    mov byte [rdi+2], 'e'
    mov byte [rdi+3], 'y'
    mov byte [rdi+4], 0

    ; 5. Создаём файл
    mov  rax, 2             ; sys_open
    lea  rdi, [filename]
    mov  rsi, 0x241         ; O_CREAT | O_WRONLY | O_TRUNC
    mov  rdx, 0x1A4         ; 0644
    syscall

    test rax, rax
    js   .err

    mov  rbx, rax           ; rbx = fd

    ; 6. Пишем ключи в файл
    mov  rdi, rbx
    lea  rsi, [key_buf]
    mov  rdx, KEY_FILE_SIZE
    call tcp_send

    ; 7. Закрываем файл
    mov  rax, 3             ; sys_close
    mov  rdi, rbx
    syscall

    ; 8. Сообщение об успехе
    mov  rdi, msg_saved
    call print_str
    lea  rdi, [filename]
    call print_str
    mov  rdi, msg_newline
    call print_str

    mov  rax, 60
    xor  rdi, rdi
    syscall

.err:
    mov  rdi, msg_err
    call print_str
    mov  rax, 60
    mov  rdi, 1
    syscall
