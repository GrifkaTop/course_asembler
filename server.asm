; server.asm — многопоточный сервер чата
; Каждый клиент → отдельный поток через sys_clone (CLONE_VM)
; Разделяемые данные защищены спинлоком

format ELF64
public _start

include 'proto.inc'
include 'crypto.inc'
include 'net.inc'

; ─────────────────────────────────────────────────────────────
; Константы хранилища
; ─────────────────────────────────────────────────────────────
MAX_USERS       equ 16
MAX_CHATS       equ 16
MAX_CHAT_KEYS   equ 128
MAX_MESSAGES    equ 256

THREAD_STACK    equ 65536   ; 64 KB стека на поток

; Размеры записей и смещения — см. proto.inc

; Локальные данные сессии — на стеке потока
; r14 = базовый указатель на эту область
LOCAL_AUTH      equ 0       ; 1 байт — авторизован (0/1)
LOCAL_PAD       equ 1       ; 7 байт padding
LOCAL_CHALLENGE equ 8       ; 8 байт — текущий challenge
LOCAL_USER      equ 16      ; 32 байта — username авторизованного
LOCAL_RECV      equ 48      ; 512 байт — буфер приёма
LOCAL_SIZE      equ 560

; clone: CLONE_VM | CLONE_FILES | CLONE_SIGHAND | SIGCHLD
THREAD_FLAGS    equ 0x00000D11

; Размер блока данных для сохранения (от user_count до конца messages)
DATA_SIZE equ 4*8 + MAX_USERS*USER_REC + MAX_CHATS*CHAT_REC + MAX_CHAT_KEYS*CHAT_KEY_REC + MAX_MESSAGES*MSG_REC

; ─────────────────────────────────────────────────────────────
section '.data' writable
    server_addr:
        dw  AF_INET
        db  0x1F, 0x90      ; порт 8080
        dd  0               ; 0.0.0.0
        dq  0

    msg_start   db "Сервер запущен на порту 8080", 10, 0
    opt_val     dd 1                ; SO_REUSEADDR = 1
    msg_conn    db "[+] Клиент подключился", 10, 0
    msg_disc    db "[-] Клиент отключился", 10, 0
    msg_reg     db "[R] ", 0
    msg_auth_ok db "[A] ", 0
    msg_nl      db 10, 0
    msg_loaded  db "[*] Данные загружены из data.bin", 10, 0
    data_magic  db "CHATDAT1"
    data_file   db "data.bin", 0

; ─────────────────────────────────────────────────────────────
section '.bss' writable
    server_sock     rq 1

    ; спинлок для разделяемых данных (0=свободен, 1=занят)
    global_lock     rq 1

    ; счётчики
    user_count      rq 1
    chat_count      rq 1
    chat_key_count  rq 1
    msg_count       rq 1

    ; хранилища
    users           rb MAX_USERS     * USER_REC
    chats           rb MAX_CHATS     * CHAT_REC
    chat_keys       rb MAX_CHAT_KEYS * CHAT_KEY_REC
    messages        rb MAX_MESSAGES  * MSG_REC

; ─────────────────────────────────────────────────────────────
section '.text' executable

_start:
    mov  rax, 41
    mov  rdi, AF_INET
    mov  rsi, SOCK_STREAM
    xor  rdx, rdx
    syscall
    mov  [server_sock], rax

    ; SO_REUSEADDR — позволяет rebind после убийства сервера
    mov  rax, 54            ; sys_setsockopt
    mov  rdi, [server_sock]
    mov  rsi, 1             ; SOL_SOCKET
    mov  rdx, 2             ; SO_REUSEADDR
    lea  r10, [opt_val]
    mov  r8,  4
    syscall

    mov  rax, 49
    mov  rdi, [server_sock]
    lea  rsi, [server_addr]
    mov  rdx, 16
    syscall

    mov  rax, 50
    mov  rdi, [server_sock]
    mov  rsi, 8
    syscall

    mov  rdi, msg_start
    call print_str

    call load_data

; ── Основной цикл приёма — accept + clone ───────────────────
accept_loop:
    mov  rax, 43
    mov  rdi, [server_sock]
    xor  rsi, rsi
    xor  rdx, rdx
    syscall
    mov  r13, rax           ; r13 = client_sock (наследуется потоком)

    mov  rdi, msg_conn
    call print_str

    ; mmap 64 KB стека для нового потока
    mov  rax, 9
    xor  rdi, rdi
    mov  rsi, THREAD_STACK
    mov  rdx, 3             ; PROT_READ | PROT_WRITE
    mov  r10, 0x22          ; MAP_PRIVATE | MAP_ANONYMOUS
    mov  r8,  -1
    xor  r9,  r9
    syscall

    lea  rsi, [rax + THREAD_STACK]  ; rsi = вершина стека (растёт вниз)

    ; clone — дочерний поток наследует все регистры (в т.ч. r13)
    mov  rax, 56
    mov  rdi, THREAD_FLAGS
    ; rsi уже = stack_top
    xor  rdx, rdx
    xor  r10, r10
    xor  r8,  r8
    syscall

    test rax, rax
    jnz  accept_loop        ; родитель → следующий accept

    ; ─── дочерний поток ───
    call handle_client

    mov  rdi, msg_disc
    call print_str

    ; закрываем сокет и выходим
    mov  rax, 3
    mov  rdi, r13
    syscall
    mov  rax, 60
    xor  rdi, rdi
    syscall

; ─────────────────────────────────────────────────────────────
; handle_client
; r13 = client_sock  (не меняется)
; r14 = &session     (локальные данные на стеке этого потока)
; ─────────────────────────────────────────────────────────────
handle_client:
    push rbp
    push r15

    sub  rsp, LOCAL_SIZE
    mov  r14, rsp

    ; инициализация сессии
    mov  byte [r14 + LOCAL_AUTH], 0
    mov  qword [r14 + LOCAL_CHALLENGE], 0
    lea  rdi, [r14 + LOCAL_USER]
    xor  al,  al
    mov  rcx, USERNAME_LEN
    rep  stosb

.next_cmd:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, 1
    call tcp_recv
    test rax, rax
    jle  .done

    movzx rbp, byte [r14 + LOCAL_RECV]  ; rbp = cmd

    cmp  byte [r14 + LOCAL_AUTH], 1
    je   .authed

    ; без авторизации — только REGISTER и AUTH_START
    cmp  rbp, CMD_REGISTER
    je   .do_register
    cmp  rbp, CMD_AUTH_START
    je   .do_auth_start
    call send_err
    jmp  .next_cmd

.authed:
    cmp  rbp, CMD_REGISTER
    je   .do_register
    cmp  rbp, CMD_AUTH_START
    je   .do_auth_start
    cmp  rbp, CMD_LIST_CHATS
    je   .do_list_chats
    cmp  rbp, CMD_CREATE_CHAT
    je   .do_create_chat
    cmp  rbp, CMD_GET_KEY
    je   .do_get_key
    cmp  rbp, CMD_SEND_KEY
    je   .do_send_key
    cmp  rbp, CMD_GET_PUBKEY
    je   .do_get_pubkey
    cmp  rbp, CMD_CHAT_AUTH
    je   .do_chat_auth
    cmp  rbp, CMD_SEND_MSG
    je   .do_send_msg
    cmp  rbp, CMD_GET_MSGS
    je   .do_get_msgs
    cmp  rbp, CMD_LIST_MY_CHATS
    je   .do_list_my_chats
    cmp  rbp, CMD_GET_USER_BY_NPART
    je   .do_get_user_by_npart
    call send_err
    jmp  .next_cmd

; ── REGISTER ────────────────────────────────────────────────
.do_register:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, USERNAME_LEN + KEY_SIZE * 2
    call tcp_recv

    call acquire_lock

    lea  rdi, [r14 + LOCAL_RECV]
    call find_user
    test rax, rax
    jnz  .reg_full

    cmp  qword [user_count], MAX_USERS
    jge  .reg_full

    mov  rax, [user_count]
    mov  rcx, USER_REC
    mul  rcx
    lea  rdi, [users + rax]
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rcx, USER_REC
    rep  movsb
    inc  qword [user_count]

    call release_lock
    call save_data

    mov  rdi, msg_reg
    call print_str
    lea  rdi, [r14 + LOCAL_RECV]
    call print_str
    mov  rdi, msg_nl
    call print_str

    call send_ok
    jmp  .next_cmd

.reg_full:
    call release_lock
    call send_err
    jmp  .next_cmd

; ── AUTH_START ──────────────────────────────────────────────
.do_auth_start:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, USERNAME_LEN
    call tcp_recv

    call acquire_lock
    lea  rdi, [r14 + LOCAL_RECV]
    call find_user      ; rax = &user_record или 0
    call release_lock

    test rax, rax
    jz   .err_and_next
    mov  r15, rax       ; r15 = &user_record

    ; генерируем challenge через getrandom
    sub  rsp, 8
    mov  rax, 318
    mov  rdi, rsp
    mov  rsi, 8
    xor  rdx, rdx
    syscall
    mov  rax, [rsp]
    add  rsp, 8
    btr  rax, 63                     ; сбрасываем бит 63: challenge < 2^63 < n
    mov  [r14 + LOCAL_CHALLENGE], rax

    ; шифруем pubkey пользователя: enc = challenge^e mod n
    mov  rdi, [r14 + LOCAL_CHALLENGE]
    mov  rsi, [r15 + USER_E]
    mov  rdx, [r15 + USER_N]
    call rsa_encrypt

    ; RESP_CHALLENGE + enc_challenge
    push rax
    mov  rdi, r13
    mov  sil, RESP_CHALLENGE
    call send_byte
    pop  rsi
    mov  rdi, r13
    call send_u64

    ; recv CMD_AUTH_RESP
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, 1
    call tcp_recv
    cmp  byte [r14 + LOCAL_RECV], CMD_AUTH_RESP
    jne  .err_and_next

    ; recv challenge (8 байт)
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, KEY_SIZE
    call tcp_recv

    mov  rax, qword [r14 + LOCAL_RECV]
    cmp  rax, [r14 + LOCAL_CHALLENGE]
    jne  .err_and_next

    ; авторизован
    mov  byte [r14 + LOCAL_AUTH], 1
    lea  rdi, [r14 + LOCAL_USER]
    lea  rsi, [r15 + USER_NAME]
    mov  rcx, USERNAME_LEN
    rep  movsb

    mov  rdi, msg_auth_ok
    call print_str
    lea  rdi, [r14 + LOCAL_USER]
    call print_str
    mov  rdi, msg_nl
    call print_str

    call send_ok
    jmp  .next_cmd

; ── LIST_CHATS ───────────────────────────────────────────────
.do_list_chats:
    call acquire_lock
    mov  rbx, [chat_count]
    call release_lock

    mov  rdi, r13
    mov  sil, RESP_CHAT_LIST
    call send_byte
    mov  rdi, r13
    mov  rsi, rbx
    call send_u64

    xor  rbx, rbx
.lc_loop:
    call acquire_lock
    mov  rax, [chat_count]
    call release_lock
    cmp  rbx, rax
    jge  .next_cmd

    mov  rax, rbx
    mov  rcx, CHAT_REC
    mul  rcx
    lea  rsi, [chats + rax]
    mov  rdi, r13
    mov  rdx, CHAT_REC
    call tcp_send

    inc  rbx
    jmp  .lc_loop

; ── CREATE_CHAT ──────────────────────────────────────────────
.do_create_chat:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, CHAT_NAME_LEN + KEY_SIZE * 2
    call tcp_recv

    call acquire_lock

    cmp  qword [chat_count], MAX_CHATS
    jge  .cc_full

    ; chat_n (публичный ключ чата) от клиента — это и есть идентификатор чата
    mov  rbx, qword [r14 + LOCAL_RECV + CHAT_NAME_LEN]

    mov  rax, [chat_count]
    mov  rcx, CHAT_REC
    mul  rcx
    lea  r15, [chats + rax]

    mov  qword [r15 + CHAT_ID_OFF], rbx   ; CHAT_ID = chat_n
    lea  rdi, [r15 + CHAT_NAME_OFF]
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rcx, CHAT_NAME_LEN + KEY_SIZE * 2
    rep  movsb

    inc  qword [chat_count]
    call release_lock
    call save_data

    call send_ok
    jmp  .next_cmd

.cc_full:
    call release_lock
    call send_err
    jmp  .next_cmd

; ── GET_KEY ──────────────────────────────────────────────────
.do_get_key:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, CHAT_ID_SIZE
    call tcp_recv

    mov  rdi, qword [r14 + LOCAL_RECV]
    lea  rsi, [r14 + LOCAL_USER]
    call acquire_lock
    call find_chat_key
    test rax, rax
    jz   .gk_miss
    push qword [rax + CKEY_KEY_OFF]     ; enc_key на стек

    mov  rdi, qword [r14 + LOCAL_RECV]  ; chat_id
    call find_chat                       ; rax = &chat_record
    call release_lock

    test rax, rax
    jz   .gk_no_chat

    mov  rbx, qword [rax + CHAT_N_OFF]

    mov  rdi, r13
    mov  sil, RESP_CHAT_KEY
    call send_byte
    pop  rsi                             ; enc_key
    mov  rdi, r13
    call send_u64
    mov  rdi, r13
    mov  rsi, rbx                        ; chat_n
    call send_u64
    jmp  .next_cmd

.gk_miss:
    call release_lock
    jmp  .err_and_next

.gk_no_chat:
    add  rsp, 8
    jmp  .err_and_next

; ── SEND_KEY ─────────────────────────────────────────────────
.do_send_key:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, CHAT_KEY_REC
    call tcp_recv

    call acquire_lock

    cmp  qword [chat_key_count], MAX_CHAT_KEYS
    jge  .sk_full

    mov  rax, [chat_key_count]
    mov  rcx, CHAT_KEY_REC
    mul  rcx
    lea  rdi, [chat_keys + rax]
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rcx, CHAT_KEY_REC
    rep  movsb
    inc  qword [chat_key_count]

    call release_lock
    call save_data
    call send_ok
    jmp  .next_cmd

.sk_full:
    call release_lock
    call send_err
    jmp  .next_cmd

; ── GET_PUBKEY ───────────────────────────────────────────────
.do_get_pubkey:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, USERNAME_LEN
    call tcp_recv

    call acquire_lock
    lea  rdi, [r14 + LOCAL_RECV]
    call find_user
    call release_lock

    test rax, rax
    jz   .err_and_next

    push qword [rax + USER_E]
    push qword [rax + USER_N]

    mov  rdi, r13
    mov  sil, RESP_PUBKEY
    call send_byte
    pop  rsi
    mov  rdi, r13
    call send_u64
    pop  rsi
    mov  rdi, r13
    call send_u64
    jmp  .next_cmd

; ── CHAT_AUTH ────────────────────────────────────────────────
.do_chat_auth:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, CHAT_ID_SIZE
    call tcp_recv

    call acquire_lock
    mov  rdi, qword [r14 + LOCAL_RECV]
    call find_chat
    call release_lock

    test rax, rax
    jz   .err_and_next
    mov  r15, rax       ; r15 = &chat record

    ; генерируем challenge
    sub  rsp, 8
    mov  rax, 318
    mov  rdi, rsp
    mov  rsi, 8
    xor  rdx, rdx
    syscall
    mov  rax, [rsp]
    add  rsp, 8
    btr  rax, 63                     ; сбрасываем бит 63: challenge < 2^63 < n
    mov  [r14 + LOCAL_CHALLENGE], rax

    ; шифруем ПУБЛИЧНЫМ ключом чата (доказывает наличие ПРИВАТНОГО)
    mov  rdi, [r14 + LOCAL_CHALLENGE]
    mov  rsi, [r15 + CHAT_E_OFF]
    mov  rdx, [r15 + CHAT_N_OFF]
    call rsa_encrypt

    push rax
    mov  rdi, r13
    mov  sil, RESP_CHALLENGE
    call send_byte
    pop  rsi
    mov  rdi, r13
    call send_u64

    ; recv CMD_CHAT_AUTH_RESP
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, 1
    call tcp_recv
    cmp  byte [r14 + LOCAL_RECV], CMD_CHAT_AUTH_RESP
    jne  .err_and_next

    ; recv chat_id(8) + challenge(8)
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, CHAT_ID_SIZE + KEY_SIZE
    call tcp_recv

    mov  rax, qword [r14 + LOCAL_RECV + CHAT_ID_SIZE]
    cmp  rax, [r14 + LOCAL_CHALLENGE]
    jne  .err_and_next

    call send_ok
    jmp  .next_cmd

; ── SEND_MSG ─────────────────────────────────────────────────
.do_send_msg:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, MSG_REC
    call tcp_recv

    call acquire_lock

    cmp  qword [msg_count], MAX_MESSAGES
    jge  .msg_full

    mov  rax, [msg_count]
    mov  rcx, MSG_REC
    mul  rcx
    lea  rdi, [messages + rax]
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rcx, MSG_REC
    rep  movsb
    inc  qword [msg_count]

    call release_lock
    call save_data
    call send_ok
    jmp  .next_cmd

.msg_full:
    call release_lock
    call send_err
    jmp  .next_cmd

; ── GET_MSGS ─────────────────────────────────────────────────
.do_get_msgs:
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, CHAT_ID_SIZE
    call tcp_recv

    mov  rbx, qword [r14 + LOCAL_RECV]  ; rbx = chat_id

    ; считаем сообщения для этого чата
    call acquire_lock
    mov  r15, [msg_count]
    call release_lock

    xor  rcx, rcx       ; rcx = счётчик совпадений
    xor  rdx, rdx       ; rdx = индекс
.gm_count:
    cmp  rdx, r15
    jge  .gm_send_hdr

    push rcx
    push rdx
    mov  rax, rdx
    mov  rcx, MSG_REC
    mul  rcx
    cmp  qword [messages + rax + MSG_CHAT_OFF], rbx
    pop  rdx
    pop  rcx
    jne  .gm_next
    inc  rcx
.gm_next:
    inc  rdx
    jmp  .gm_count

.gm_send_hdr:
    push rcx                ; save match count — send_byte's syscall clobbers rcx
    mov  rdi, r13
    mov  sil, RESP_MSGS
    call send_byte
    mov  rdi, r13
    pop  rsi                ; rsi = match count
    call send_u64

    xor  rdx, rdx
.gm_send:
    cmp  rdx, r15
    jge  .next_cmd

    push rdx                ; сохраняем индекс (mul и tcp_send затрут rdx)
    mov  rax, rdx
    mov  rcx, MSG_REC
    mul  rcx                ; rax = offset, rdx = 0
    cmp  qword [messages + rax + MSG_CHAT_OFF], rbx
    jne  .gm_send_next

    lea  rsi, [messages + rax]
    mov  rdi, r13
    mov  rdx, MSG_REC
    call tcp_send

.gm_send_next:
    pop  rdx                ; восстанавливаем индекс
    inc  rdx
    jmp  .gm_send

; ── LIST_MY_CHATS ─────────────────────────────────────────────
.do_list_my_chats:
    ; Проход 1: считаем чаты где есть ключ для текущего пользователя
    call acquire_lock
    xor  rbx, rbx           ; rbx = совпадений
    xor  r15, r15           ; r15 = индекс чата
.lmc_cnt:
    cmp  r15, [chat_count]
    jge  .lmc_cnt_done
    imul rax, r15, CHAT_REC
    mov  rdi, qword [chats + rax + CHAT_ID_OFF]
    lea  rsi, [r14 + LOCAL_USER]
    call find_chat_key
    test rax, rax
    jz   .lmc_cnt_next
    inc  rbx
.lmc_cnt_next:
    inc  r15
    jmp  .lmc_cnt
.lmc_cnt_done:
    call release_lock

    ; Отправляем заголовок: RESP_CHAT_LIST + count
    push rbx
    mov  rdi, r13
    mov  sil, RESP_CHAT_LIST
    call send_byte
    mov  rdi, r13
    pop  rsi
    call send_u64

    ; Проход 2: отправляем совпадающие записи
    xor  r15, r15
.lmc_send:
    call acquire_lock
    cmp  r15, [chat_count]
    jge  .lmc_send_done
    imul rax, r15, CHAT_REC
    mov  rdi, qword [chats + rax + CHAT_ID_OFF]
    lea  rsi, [r14 + LOCAL_USER]
    call find_chat_key
    test rax, rax
    jz   .lmc_skip
    imul rax, r15, CHAT_REC
    lea  rsi, [chats + rax]
    call release_lock
    mov  rdi, r13
    mov  rdx, CHAT_REC
    call tcp_send
    inc  r15
    jmp  .lmc_send
.lmc_skip:
    call release_lock
    inc  r15
    jmp  .lmc_send
.lmc_send_done:
    call release_lock
    jmp  .next_cmd

; ── GET_USER_BY_NPART ────────────────────────────────────────
.do_get_user_by_npart:
    ; recv npart(8) — нижние 6 байт n отправителя
    mov  rdi, r13
    lea  rsi, [r14 + LOCAL_RECV]
    mov  rdx, KEY_SIZE
    call tcp_recv

    mov  rbx, qword [r14 + LOCAL_RECV]  ; rbx = npart

    call acquire_lock
    xor  r15, r15           ; r15 = индекс
.gunp_loop:
    cmp  r15, [user_count]
    jge  .gunp_miss
    imul rax, r15, USER_REC
    lea  rdx, [users + rax]
    mov  rax, qword [rdx + USER_N]
    shl  rax, 16
    shr  rax, 16            ; нижние 6 байт user_n
    cmp  rax, rbx
    je   .gunp_found
    inc  r15
    jmp  .gunp_loop
.gunp_miss:
    call release_lock
    call send_err
    jmp  .next_cmd
.gunp_found:
    mov  r15, rdx           ; r15 = &user_record
    call release_lock
    call send_ok
    mov  rdi, r13
    lea  rsi, [r15 + USER_NAME]
    mov  rdx, USERNAME_LEN
    call tcp_send
    jmp  .next_cmd

; ── Общий выход с ошибкой ────────────────────────────────────
.err_and_next:
    call send_err
    jmp  .next_cmd

.done:
    add  rsp, LOCAL_SIZE
    pop  r15
    pop  rbp
    ret

; ─────────────────────────────────────────────────────────────
; Утилиты
; ─────────────────────────────────────────────────────────────

; ─────────────────────────────────────────────────────────────
; save_data — записать все данные в data.bin
; ─────────────────────────────────────────────────────────────
save_data:
    push rbx

    call acquire_lock

    mov  rax, 2                 ; sys_open
    lea  rdi, [data_file]
    mov  rsi, 0x241             ; O_WRONLY|O_CREAT|O_TRUNC
    mov  rdx, 0x1A4             ; 0644
    syscall
    test rax, rax
    js   .sd_unlock
    mov  rbx, rax               ; rbx = fd

    mov  rax, 1                 ; sys_write — магическое число
    mov  rdi, rbx
    lea  rsi, [data_magic]
    mov  rdx, 8
    syscall

    mov  rax, 1                 ; sys_write — все данные
    mov  rdi, rbx
    lea  rsi, [user_count]
    mov  rdx, DATA_SIZE
    syscall

    mov  rax, 3                 ; sys_close
    mov  rdi, rbx
    syscall

.sd_unlock:
    call release_lock
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; load_data — загрузить данные из data.bin (при старте)
; ─────────────────────────────────────────────────────────────
load_data:
    push rbx
    sub  rsp, 8                 ; буфер для магического числа

    mov  rax, 2                 ; sys_open
    lea  rdi, [data_file]
    xor  rsi, rsi               ; O_RDONLY
    xor  rdx, rdx
    syscall
    test rax, rax
    js   .ld_done               ; файла нет — ок, начинаем с нуля
    mov  rbx, rax               ; rbx = fd

    mov  rax, 0                 ; sys_read — читаем магическое число
    mov  rdi, rbx
    mov  rsi, rsp
    mov  rdx, 8
    syscall
    cmp  rax, 8
    jne  .ld_close

    lea  rdi, [rsp]             ; сравниваем с ожидаемым
    lea  rsi, [data_magic]
    mov  rcx, 8
    repe cmpsb
    jne  .ld_close              ; неверный формат файла

    mov  rax, 0                 ; sys_read — все данные
    mov  rdi, rbx
    lea  rsi, [user_count]
    mov  rdx, DATA_SIZE
    syscall

    mov  rdi, msg_loaded
    call print_str

.ld_close:
    mov  rax, 3                 ; sys_close
    mov  rdi, rbx
    syscall
.ld_done:
    add  rsp, 8
    pop  rbx
    ret

; acquire_lock — спинлок захват
acquire_lock:
    mov  eax, 1
.spin:
    xchg [global_lock], rax
    test rax, rax
    jnz  .spin
    ret

; release_lock — спинлок освобождение
release_lock:
    mov  qword [global_lock], 0
    ret

; send_ok / send_err
send_ok:
    mov  rdi, r13
    mov  sil, RESP_OK
    jmp  send_byte

send_err:
    mov  rdi, r13
    mov  sil, RESP_ERR
    jmp  send_byte

; str_eq — сравнить USERNAME_LEN байт
; rdi=s1, rsi=s2 → rax: 1=равно, 0=нет
str_eq:
    push rcx
    push rdi
    push rsi
    mov  rcx, USERNAME_LEN
    repe cmpsb
    setz al
    movzx rax, al
    pop  rsi
    pop  rdi
    pop  rcx
    ret

; find_user — найти запись пользователя по имени
; rdi=username → rax=&record или 0
find_user:
    push rbx
    push r12
    push r13

    mov  r12, rdi
    xor  rbx, rbx
.fu_loop:
    cmp  rbx, [user_count]
    jge  .fu_miss

    mov  rax, rbx
    mov  rcx, USER_REC
    mul  rcx
    lea  r13, [users + rax]

    mov  rdi, r13
    mov  rsi, r12
    call str_eq
    test rax, rax
    jnz  .fu_hit

    inc  rbx
    jmp  .fu_loop

.fu_miss:
    xor  rax, rax
    jmp  .fu_done
.fu_hit:
    mov  rax, r13
.fu_done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; find_chat — найти запись чата по chat_id
; rdi=chat_id → rax=&record или 0
find_chat:
    push rbx
    push r12

    mov  r12, rdi
    xor  rbx, rbx
.fc_loop:
    cmp  rbx, [chat_count]
    jge  .fc_miss

    mov  rax, rbx
    mov  rcx, CHAT_REC
    mul  rcx
    lea  rdx, [chats + rax]

    cmp  qword [rdx + CHAT_ID_OFF], r12
    je   .fc_hit

    inc  rbx
    jmp  .fc_loop

.fc_miss:
    xor  rax, rax
    jmp  .fc_done
.fc_hit:
    mov  rax, rdx
.fc_done:
    pop  r12
    pop  rbx
    ret

; find_chat_key — найти ключ чата для пользователя
; rdi=chat_id, rsi=username → rax=&record или 0
find_chat_key:
    push rbx
    push r12
    push r13

    mov  r12, rdi
    mov  r13, rsi
    xor  rbx, rbx
.fck_loop:
    cmp  rbx, [chat_key_count]
    jge  .fck_miss

    mov  rax, rbx
    mov  rcx, CHAT_KEY_REC
    mul  rcx
    lea  rdx, [chat_keys + rax]

    cmp  qword [rdx + CKEY_ID_OFF], r12
    jne  .fck_next

    lea  rdi, [rdx + CKEY_USER_OFF]
    mov  rsi, r13
    call str_eq
    test rax, rax
    jnz  .fck_hit

.fck_next:
    inc  rbx
    jmp  .fck_loop

.fck_miss:
    xor  rax, rax
    jmp  .fck_done
.fck_hit:
    mov  rax, rdx
.fck_done:
    pop  r13
    pop  r12
    pop  rbx
    ret
