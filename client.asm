; client.asm — клиент чата с шифрованием
; Использование: ./client
; Загружает .key файл, подключается к серверу, авторизуется

format ELF64
public _start

include 'proto.inc'
include 'crypto.inc'
include 'net.inc'

; ─────────────────────────────────────────────────────────────
; Локальное хранилище ключей чатов
; ─────────────────────────────────────────────────────────────
MAX_LOCAL_CHATS equ 8
LCHAT_ID        equ 0   ; u64
LCHAT_N         equ 8   ; u64 — модуль чата
LCHAT_D         equ 16  ; u64 — приватный ключ чата
LCHAT_SIZE      equ 24

; ─────────────────────────────────────────────────────────────
section '.data' writable
    ; Ввод
    msg_name_taken  db "Имя занято, введите другое", 10, 0
    msg_ask_ip      db "IP сервера [127.0.0.1]: ", 0
    msg_ask_choice  db "Выбор: ", 0
    msg_ask_msg     db "Сообщение: ", 0
    msg_ask_cname   db "Название чата: ", 0
    msg_ask_chatid  db "ID чата (Enter = назад): ", 0
    msg_ask_user    db "Имя пользователя: ", 0
    ; Меню
    msg_menu        db 10, "=== МЕНЮ ===", 10, \
                       "1. Создать чат", 10, \
                       "2. Войти в чат", 10, \
                       "3. Пригласить в чат", 10, \
                       "4. Выйти", 10, 0

    msg_chat_menu   db 10, "=== ЧАТ ===", 10, \
                       "1. Читать сообщения", 10, \
                       "2. Написать", 10, \
                       "3. Выйти", 10, 0

    msg_login_menu  db "1. Войти  2. Регистрация: ", 0

    ; Статусы
    msg_connected   db "Подключён к серверу", 10, 0
    msg_reg_ok      db "Зарегистрирован", 10, 0
    msg_auth_ok     db "Авторизован как: ", 0
    msg_chat_ok     db "Доступ к чату открыт", 10, 0
    msg_sent        db "Отправлено", 10, 0
    msg_no_chats    db "Нет чатов", 10, 0
    msg_no_msgs     db "Нет сообщений", 10, 0
    msg_err             db "Ошибка сервера", 10, 0
    msg_conn_err        db "Ошибка подключения", 10, 0
    msg_key_err         db "Ошибка: файл ключей не найден", 10, 0
    msg_err_reg         db "Ошибка: имя уже занято или сервер переполнен", 10, 0
    msg_err_auth        db "Ошибка: вы не зарегистрированы или неверный ключ", 10, 0
    msg_err_no_key      db "Ошибка: нет доступа к чату (вас не пригласили)", 10, 0
    msg_err_chat_auth   db "Ошибка: неверный ключ чата", 10, 0
    msg_err_no_user     db "Ошибка: пользователь не найден", 10, 0
    msg_err_no_lchat    db "Ошибка: у вас нет ключа этого чата", 10, 0
    msg_press_enter     db "[ Enter для продолжения ]", 10, 0
    msg_chat_id     db "id : ", 0
    msg_chat_name   db " : название : ", 0
    msg_from        db "От: ", 0
    msg_colon       db ": ", 0
    msg_nl          db 10, 0
    msg_sep         db 10, "------------------------------------", 10, 10, 0
    msg_created     db "Чат создан, ID: ", 0
    msg_chat_hdr    db "=== ЧАТ ID: ", 0
    msg_chat_input  db 10, "Введите сообщение (Enter = выйти): ", 0
    str_clear       db 27, '[', '2', 'J', 27, '[', 'H', 0

    ; server_addr для connect (как в референсе)
    server_addr:
        dw  AF_INET
        db  0x1F, 0x90          ; порт 8080
        dd  0                   ; IP заполним при старте
        dq  0

; ─────────────────────────────────────────────────────────────
section '.bss' writable
    ; Мои ключи (из .key файла)
    my_n            rq 1
    my_e            rq 1
    my_d            rq 1
    my_username     rb USERNAME_LEN

    ; Сеть
    sock_fd         rq 1

    ; Текущий чат (в котором авторизованы)
    cur_chat_id     rq 1
    cur_chat_n      rq 1
    cur_chat_d      rq 1

    ; Локальные ключи чатов
    lchats          rb MAX_LOCAL_CHATS * LCHAT_SIZE
    lchat_count     rq 1

    ; Буферы
    key_buf         rb 24 + USERNAME_LEN    ; буфер для чтения .key файла
    filename_buf    rb USERNAME_LEN + 8
    ip_buf          rb 32
    input_buf       rb 256
    recv_buf        rb 512
    reg_mode        rb 1

    ; Временные переменные
    tmp_n           rq 1
    tmp_e           rq 1
    tmp_d           rq 1

; ─────────────────────────────────────────────────────────────
section '.text' executable

_start:
    ; ── 1. Меню входа ────────────────────────────────────────
    mov  rdi, msg_login_menu
    call print_str
    lea  rdi, [input_buf]
    mov  rsi, 4
    call read_line
    mov  al, byte [input_buf]
    mov  byte [reg_mode], al

    ; ── 2. IP и подключение к серверу ────────────────────────
;    mov  rdi, msg_ask_ip
;    call print_str
;    lea  rdi, [ip_buf]
;    mov  rsi, 31
;    call read_line
;
;    cmp  byte [ip_buf], 0
;    jne  .parse_ip
    mov  dword [server_addr + 4], 0x0100007F
;    jmp  .do_connect
;.parse_ip:
;    lea  rsi, [ip_buf]
;    lea  rdi, [server_addr + 4]
;    call parse_ip
.do_connect:
    mov  rax, 41
    mov  rdi, AF_INET
    mov  rsi, SOCK_STREAM
    xor  rdx, rdx
    syscall
    mov  [sock_fd], rax

    mov  rax, 42
    mov  rdi, [sock_fd]
    lea  rsi, [server_addr]
    mov  rdx, 16
    syscall
    test rax, rax
    js   .conn_err

    ; ── 3. Войти или зарегистрироваться ──────────────────────
    cmp  byte [reg_mode], '2'
    je   .start_register

    ; === ВОЙТИ ===
.login_ask:
    mov  rdi, msg_ask_user
    call print_str
    lea  rdi, [my_username]
    mov  rsi, USERNAME_LEN
    call read_line
    test rax, rax
    jz   .err_exit
    call build_key_filename
    call load_key_file
    test rax, rax
    jz   .key_err
    call cmd_auth
    test rax, rax
    jz   .err_exit
    jmp  main_loop

    ; === РЕГИСТРАЦИЯ ===
.start_register:
.reg_loop:
    mov  rdi, msg_ask_user
    call print_str
    lea  rdi, [my_username]
    mov  rsi, USERNAME_LEN
    call read_line
    test rax, rax
    jz   .err_exit
    ; генерируем ключевую пару
    lea  rdi, [my_n]
    lea  rsi, [my_e]
    lea  rdx, [my_d]
    call rsa_keygen
    ; пробуем зарегистрироваться
    call cmd_register
    test rax, rax
    jz   .reg_taken
    ; успех — сохраняем ключи и входим
    call save_key_file
    call cmd_auth
    test rax, rax
    jz   .err_exit
    jmp  main_loop
.reg_taken:
    mov  rdi, msg_name_taken
    call print_str
    jmp  .reg_loop

.key_err:
    mov  rdi, msg_key_err
    call print_str
    jmp  .err_exit

.conn_err:
    mov  rdi, msg_conn_err
    call print_str

.err_exit:
    mov  rax, 60
    mov  rdi, 1
    syscall

; ─────────────────────────────────────────────────────────────
main_loop:
    call clear_screen
    mov  rdi, msg_menu
    call print_str
    mov  rdi, msg_ask_choice
    call print_str
    mov  rdi, input_buf
    mov  rsi, 4
    call read_line

    cmp  byte [input_buf], '1'
    je   .create_chat
    cmp  byte [input_buf], '2'
    je   .enter_chat
    cmp  byte [input_buf], '3'
    je   .invite
    cmp  byte [input_buf], '4'
    je   .quit
    jmp  main_loop

.create_chat:
    call cmd_create_chat
    jmp  main_loop

.enter_chat:
    call cmd_enter_chat
    jmp  main_loop

.invite:
    call cmd_invite
    jmp  main_loop

.quit:
    mov  rax, 3
    mov  rdi, [sock_fd]
    syscall
    mov  rax, 60
    xor  rdi, rdi
    syscall

; ─────────────────────────────────────────────────────────────
; load_key_file — загрузить n,e,d,username из файла
; filename_buf содержит путь → rax: 1=OK, 0=ошибка
; ─────────────────────────────────────────────────────────────
load_key_file:
    mov  rax, 2             ; sys_open
    lea  rdi, [filename_buf]
    xor  rsi, rsi           ; O_RDONLY
    xor  rdx, rdx
    syscall
    test rax, rax
    js   .fail

    mov  rbx, rax           ; rbx = fd

    mov  rax, 0             ; sys_read
    mov  rdi, rbx
    lea  rsi, [key_buf]
    mov  rdx, 24 + USERNAME_LEN
    syscall

    mov  rax, 3             ; sys_close
    mov  rdi, rbx
    syscall

    ; извлекаем поля
    mov  rax, qword [key_buf]
    mov  [my_n], rax
    mov  rax, qword [key_buf + 8]
    mov  [my_e], rax
    mov  rax, qword [key_buf + 16]
    mov  [my_d], rax

    lea  rsi, [key_buf + 24]
    lea  rdi, [my_username]
    mov  rcx, USERNAME_LEN
    rep  movsb

    mov  rax, 1
    ret
.fail:
    xor  rax, rax
    ret

; ─────────────────────────────────────────────────────────────
; build_key_filename — заполняет filename_buf = my_username + ".key\0"
; ─────────────────────────────────────────────────────────────
build_key_filename:
    lea  rdi, [filename_buf]
    lea  rsi, [my_username]
.bkf_copy:
    mov  al, [rsi]
    test al, al
    jz   .bkf_append
    mov  [rdi], al
    inc  rdi
    inc  rsi
    jmp  .bkf_copy
.bkf_append:
    mov  byte [rdi],   '.'
    mov  byte [rdi+1], 'k'
    mov  byte [rdi+2], 'e'
    mov  byte [rdi+3], 'y'
    mov  byte [rdi+4], 0
    ret

; ─────────────────────────────────────────────────────────────
; save_key_file — сохраняет my_n/my_e/my_d/my_username в filename_buf
; ─────────────────────────────────────────────────────────────
save_key_file:
    push rbx
    call build_key_filename
    ; заполняем key_buf: n(8) + e(8) + d(8) + username(32)
    mov  rax, [my_n]
    mov  qword [key_buf], rax
    mov  rax, [my_e]
    mov  qword [key_buf + 8], rax
    mov  rax, [my_d]
    mov  qword [key_buf + 16], rax
    lea  rsi, [my_username]
    lea  rdi, [key_buf + 24]
    mov  rcx, USERNAME_LEN
    rep  movsb
    ; создаём файл
    mov  rax, 2
    lea  rdi, [filename_buf]
    mov  rsi, 0x241            ; O_CREAT|O_WRONLY|O_TRUNC
    mov  rdx, 0x1A4            ; 0644
    syscall
    test rax, rax
    js   .skf_done
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [key_buf]
    mov  rdx, 24 + USERNAME_LEN
    call tcp_send
    mov  rax, 3
    mov  rdi, rbx
    syscall
.skf_done:
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; cmd_register — зарегистрировать пользователя на сервере
; → rax: 1=OK, 0=ошибка
; ─────────────────────────────────────────────────────────────
cmd_register:
    ; CMD_REGISTER
    mov  rdi, [sock_fd]
    mov  sil, CMD_REGISTER
    call send_byte

    ; username(32)
    mov  rdi, [sock_fd]
    lea  rsi, [my_username]
    mov  rdx, USERNAME_LEN
    call tcp_send

    ; n(8) + e(8)
    mov  rdi, [sock_fd]
    mov  rsi, [my_n]
    call send_u64
    mov  rdi, [sock_fd]
    mov  rsi, [my_e]
    call send_u64

    ; ждём RESP_OK
    call recv_response
    cmp  al, RESP_OK
    jne  .fail

    mov  rdi, msg_reg_ok
    call print_str
    mov  rax, 1
    ret
.fail:
    xor  rax, rax
    ret

; ─────────────────────────────────────────────────────────────
; cmd_auth — challenge-response авторизация
; → rax: 1=OK, 0=ошибка
; ─────────────────────────────────────────────────────────────
cmd_auth:
    ; CMD_AUTH_START + username
    mov  rdi, [sock_fd]
    mov  sil, CMD_AUTH_START
    call send_byte
    mov  rdi, [sock_fd]
    lea  rsi, [my_username]
    mov  rdx, USERNAME_LEN
    call tcp_send

    ; ждём RESP_CHALLENGE
    call recv_response
    cmp  al, RESP_CHALLENGE
    jne  .fail

    ; recv enc_challenge(8)
    mov  rdi, [sock_fd]
    call recv_u64          ; rax = enc_challenge

    ; дешифруем своим приватным ключом
    mov  rdi, rax
    mov  rsi, [my_d]
    mov  rdx, [my_n]
    call rsa_decrypt       ; rax = plaintext challenge

    ; CMD_AUTH_RESP + challenge
    push rax
    mov  rdi, [sock_fd]
    mov  sil, CMD_AUTH_RESP
    call send_byte
    pop  rsi
    mov  rdi, [sock_fd]
    call send_u64

    ; ждём RESP_OK
    call recv_response
    cmp  al, RESP_OK
    jne  .fail

    mov  rdi, msg_auth_ok
    call print_str
    lea  rdi, [my_username]
    call print_str
    mov  rdi, msg_nl
    call print_str

    mov  rax, 1
    ret
.fail:
    mov  rdi, msg_err_auth
    call show_error
    xor  rax, rax
    ret

; ─────────────────────────────────────────────────────────────
; cmd_list_chats — получить и вывести список чатов
; ─────────────────────────────────────────────────────────────
cmd_list_chats:
    push rbx

    mov  rdi, [sock_fd]
    mov  sil, CMD_LIST_MY_CHATS
    call send_byte

    ; ждём RESP_CHAT_LIST
    call recv_response
    cmp  al, RESP_CHAT_LIST
    jne  .done

    ; count(8)
    mov  rdi, [sock_fd]
    call recv_u64
    mov  rbx, rax           ; rbx = count

    test rbx, rbx
    jnz  .recv_loop
    mov  rdi, msg_no_chats
    call print_str
    jmp  .done

.recv_loop:
    test rbx, rbx
    jz   .done

    ; принимаем одну запись: id(8) + name(32) + n(8) + e(8) = 56 байт
    mov  rdi, [sock_fd]
    lea  rsi, [recv_buf]
    mov  rdx, CHAT_REC
    call tcp_recv

    ; выводим "id : X : название : chatname"
    mov  rdi, msg_chat_id
    call print_str
    mov  rdi, qword [recv_buf]
    call print_u64
    mov  rdi, msg_chat_name
    call print_str
    lea  rdi, [recv_buf + CHAT_ID_SIZE]
    call print_str
    mov  rdi, msg_nl
    call print_str

    dec  rbx
    jmp  .recv_loop

.done:
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; cmd_create_chat — создать новый чат
; ─────────────────────────────────────────────────────────────
cmd_create_chat:
    push rbx
    push r12

    ; запрашиваем название (Enter = отмена)
    mov  rdi, msg_ask_cname
    call print_str
    lea  rdi, [input_buf]
    mov  rsi, CHAT_NAME_LEN - 1
    call read_line
    cmp  byte [input_buf], 0
    je   .cancel

    ; генерируем chat key pair локально
    lea  rdi, [tmp_n]
    lea  rsi, [tmp_e]
    lea  rdx, [tmp_d]
    call rsa_keygen

    ; CMD_CREATE_CHAT + name(32) + chat_n(8) + chat_e(8)
    mov  rdi, [sock_fd]
    mov  sil, CMD_CREATE_CHAT
    call send_byte

    ; имя (32 байта, null-padded)
    lea  rdi, [recv_buf]
    xor  al, al
    mov  rcx, CHAT_NAME_LEN
    rep  stosb
    lea  rdi, [recv_buf]
    lea  rsi, [input_buf]
    mov  rcx, CHAT_NAME_LEN - 1
    rep  movsb

    mov  rdi, [sock_fd]
    lea  rsi, [recv_buf]
    mov  rdx, CHAT_NAME_LEN
    call tcp_send

    mov  rdi, [sock_fd]
    mov  rsi, [tmp_n]
    call send_u64
    mov  rdi, [sock_fd]
    mov  rsi, [tmp_e]
    call send_u64

    ; получаем RESP_CHAT_ID + chat_id
    call recv_response
    cmp  al, RESP_CHAT_ID
    jne  .fail

    mov  rdi, [sock_fd]
    call recv_u64
    mov  rbx, rax           ; rbx = chat_id

    ; сохраняем ключ чата локально
    mov  rdi, rbx
    mov  rsi, [tmp_n]
    mov  rdx, [tmp_d]
    call save_local_chat_key

    ; отправляем зашифрованный chat_d серверу (для себя)
    ; enc_key = rsa_encrypt(chat_d, my_n, my_e)
    mov  rdi, [tmp_d]
    mov  rsi, [my_e]
    mov  rdx, [my_n]
    call rsa_encrypt
    mov  r12, rax           ; r12 = enc_key

    ; CMD_SEND_KEY + chat_id(8) + my_username(32) + enc_key(8)
    mov  rdi, [sock_fd]
    mov  sil, CMD_SEND_KEY
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, rbx
    call send_u64
    mov  rdi, [sock_fd]
    lea  rsi, [my_username]
    mov  rdx, USERNAME_LEN
    call tcp_send
    mov  rdi, [sock_fd]
    mov  rsi, r12
    call send_u64

    call recv_response

    mov  rdi, msg_created
    call print_str
    mov  rdi, rbx
    call print_u64
    mov  rdi, msg_nl
    call print_str
    mov  rdi, msg_press_enter
    call print_str
    lea  rdi, [input_buf]
    mov  rsi, 4
    call read_line

    pop  r12
    pop  rbx
    ret

.cancel:
    pop  r12
    pop  rbx
    ret

.fail:
    mov  rdi, msg_err
    call print_str
    pop  r12
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; cmd_enter_chat — войти в чат (получить ключ + auth + меню)
; ─────────────────────────────────────────────────────────────
cmd_enter_chat:
    push rbx

    call clear_screen
    call cmd_list_chats

    mov  rdi, msg_nl
    call print_str
    mov  rdi, msg_ask_chatid
    call print_str
    lea  rdi, [input_buf]
    mov  rsi, 20
    call read_line
    cmp  byte [input_buf], 0
    je   .leave
    call parse_u64
    mov  rbx, rax           ; rbx = chat_id

    ; ищем ключ локально
    mov  rdi, rbx
    call find_local_chat_key
    test rax, rax
    jnz  .have_key

    ; нет локально — запрашиваем с сервера
    mov  rdi, [sock_fd]
    mov  sil, CMD_GET_KEY
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, rbx
    call send_u64

    call recv_response
    cmp  al, RESP_CHAT_KEY
    jne  .fail

    mov  rdi, [sock_fd]
    call recv_u64           ; rax = enc_chat_d
    push rax                ; enc_chat_d на стек

    mov  rdi, [sock_fd]
    call recv_u64           ; rax = chat_n
    push rax                ; chat_n на стек

    pop  rsi                ; rsi = chat_n
    pop  rdi                ; rdi = enc_chat_d

    ; дешифруем своим приватным ключом
    push rsi                ; сохраняем chat_n
    mov  rsi, [my_d]
    mov  rdx, [my_n]
    call rsa_decrypt        ; rax = chat_d

    mov  rdx, rax           ; rdx = chat_d
    pop  rsi                ; rsi = chat_n
    mov  rdi, rbx           ; rdi = chat_id
    call save_local_chat_key

    mov  rdi, rbx
    call find_local_chat_key

.have_key:
    ; rax = &local_chat_record
    mov  rbx, rax
    mov  rcx, [rbx + LCHAT_ID]
    mov  [cur_chat_id], rcx
    mov  rcx, [rbx + LCHAT_N]
    mov  [cur_chat_n], rcx
    mov  rcx, [rbx + LCHAT_D]
    mov  [cur_chat_d], rcx

    ; CHAT_AUTH — доказываем что у нас есть приватный ключ чата
    call cmd_chat_auth
    test rax, rax
    jne  .chat_loop
    jmp  .fail_pop

.chat_loop:
    call clear_screen
    mov  rdi, msg_chat_hdr
    call print_str
    mov  rdi, [cur_chat_id]
    call print_u64
    mov  rdi, msg_nl
    call print_str

    call cmd_read_msgs

    mov  rdi, msg_chat_input
    call print_str
    lea  rdi, [input_buf]
    xor  al, al
    mov  rcx, 258
    rep  stosb
    lea  rdi, [input_buf]
    mov  rsi, 252
    call read_line

    cmp  byte [input_buf], 0
    je   .leave
    call cmd_send_msg
    jmp  .chat_loop

.leave:
    pop  rbx
    ret

.fail:
    mov  rdi, msg_err_no_key
    call show_error
    pop  rbx
    ret

.fail_pop:
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; cmd_chat_auth — верификация доступа к текущему чату
; cur_chat_id, cur_chat_d, cur_chat_n должны быть заполнены
; → rax: 1=OK, 0=ошибка
; ─────────────────────────────────────────────────────────────
cmd_chat_auth:
    ; CMD_CHAT_AUTH + chat_id
    mov  rdi, [sock_fd]
    mov  sil, CMD_CHAT_AUTH
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, [cur_chat_id]
    call send_u64

    ; ждём RESP_CHALLENGE
    call recv_response
    cmp  al, RESP_CHALLENGE
    jne  .fail

    ; recv enc_challenge(8)
    mov  rdi, [sock_fd]
    call recv_u64

    ; дешифруем ПРИВАТНЫМ ключом чата
    mov  rdi, rax
    mov  rsi, [cur_chat_d]
    mov  rdx, [cur_chat_n]
    call rsa_decrypt        ; rax = challenge

    ; CMD_CHAT_AUTH_RESP + chat_id(8) + challenge(8)
    push rax
    mov  rdi, [sock_fd]
    mov  sil, CMD_CHAT_AUTH_RESP
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, [cur_chat_id]
    call send_u64
    pop  rsi
    mov  rdi, [sock_fd]
    call send_u64

    call recv_response
    cmp  al, RESP_OK
    jne  .fail

    mov  rdi, msg_chat_ok
    call print_str
    mov  rax, 1
    ret
.fail:
    mov  rdi, msg_err_chat_auth
    call show_error
    xor  rax, rax
    ret

; ─────────────────────────────────────────────────────────────
; cmd_read_msgs — получить и расшифровать сообщения чата
; ─────────────────────────────────────────────────────────────
cmd_read_msgs:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 272       ; [rsp+0..7]=имя, [rsp+8..265]=сообщение, [266..271]=pad

    mov  rdi, [sock_fd]
    mov  sil, CMD_GET_MSGS
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, [cur_chat_id]
    call send_u64

    call recv_response
    cmp  al, RESP_MSGS
    jne  .done

    mov  rdi, [sock_fd]
    call recv_u64
    mov  rbx, rax

    test rbx, rbx
    jnz  .msg_loop
    mov  rdi, msg_no_msgs
    call print_str
    jmp  .done

.msg_loop:
    test rbx, rbx
    jz   .done

    ; получаем полный MSG_REC в recv_buf
    mov  rdi, [sock_fd]
    lea  rsi, [recv_buf]
    mov  rdx, MSG_REC
    call tcp_recv

    ; расшифровываем имя отправителя (6 байт → u64 с нулями в старших байтах)
    mov  rdi, qword [recv_buf + MSG_SENDER_OFF]
    mov  rsi, [cur_chat_d]
    mov  rdx, [cur_chat_n]
    call rsa_decrypt
    mov  qword [rsp], rax   ; [rsp+0..5]=имя, [rsp+6..7]=0

    ; расшифровываем MAX_MSG_BLOCKS блоков в [rsp+8..265]
    lea  r12, [recv_buf + MSG_BODY_OFF]
    lea  r13, [rsp + 8]
    mov  r14, MAX_MSG_BLOCKS
.decode_block:
    test r14, r14
    jz   .decode_done
    mov  rdi, qword [r12]
    mov  rsi, [cur_chat_d]
    mov  rdx, [cur_chat_n]
    call rsa_decrypt        ; r12, r13, r14 сохраняются внутри rsa_modexp
    mov  qword [r13], rax   ; 6 байт текста + 2 нулевых байта
    add  r12, 8
    add  r13, 6
    dec  r14
    jmp  .decode_block
.decode_done:
    mov  byte [r13], 0      ; гарантированный нулевой терминатор

    ; выводим "имя: сообщение\n"
    lea  rdi, [rsp]
    call print_str
    mov  rdi, msg_colon
    call print_str
    lea  rdi, [rsp + 8]
    call print_str
    mov  rdi, msg_nl
    call print_str

    dec  rbx
    jmp  .msg_loop

.done:
    add  rsp, 272
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; cmd_send_msg — отправить сообщение в текущий чат
; ─────────────────────────────────────────────────────────────
cmd_send_msg:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; enc_sender = rsa_encrypt(первые 6 байт имени пользователя)
    mov  rdi, qword [my_username]
    shl  rdi, 16
    shr  rdi, 16                   ; обнуляем старшие 2 байта → 6 байт (< 2^48 < n)
    mov  rsi, RSA_E
    mov  rdx, [cur_chat_n]
    call rsa_encrypt
    mov  rbx, rax           ; rbx = enc_sender

    ; CMD_SEND_MSG + chat_id(8) + enc_sender(8)
    mov  rdi, [sock_fd]
    mov  sil, CMD_SEND_MSG
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, [cur_chat_id]
    call send_u64
    mov  rdi, [sock_fd]
    mov  rsi, rbx
    call send_u64

    ; шифруем и отправляем MAX_MSG_BLOCKS блоков по 6 байт
    lea  r14, [input_buf]
    mov  r15, MAX_MSG_BLOCKS
.send_block:
    test r15, r15
    jz   .send_done

    movzx r12, byte [r14]
    movzx r13, byte [r14 + 1]
    shl  r13, 8
    or   r12, r13
    movzx r13, byte [r14 + 2]
    shl  r13, 16
    or   r12, r13
    movzx r13, byte [r14 + 3]
    shl  r13, 24
    or   r12, r13
    movzx r13, byte [r14 + 4]
    shl  r13, 32
    or   r12, r13
    movzx r13, byte [r14 + 5]
    shl  r13, 40
    or   r12, r13

    mov  rdi, r12
    mov  rsi, RSA_E
    mov  rdx, [cur_chat_n]
    call rsa_encrypt        ; r14, r15 сохраняются (rsa_modexp не трогает r15, сохраняет r14)
    mov  rdi, [sock_fd]
    mov  rsi, rax
    call send_u64           ; r14, r15 не трогает

    add  r14, 6
    dec  r15
    jmp  .send_block

.send_done:
    call recv_response

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; cmd_invite — пригласить пользователя в текущий чат
; ─────────────────────────────────────────────────────────────
cmd_invite:
    push rbx
    push r12

    ; показываем список чатов и спрашиваем ID
    call clear_screen
    call cmd_list_chats

    mov  rdi, msg_nl
    call print_str
    mov  rdi, msg_ask_chatid
    call print_str
    lea  rdi, [input_buf]
    mov  rsi, 20
    call read_line
    cmp  byte [input_buf], 0
    je   .leave_invite
    call parse_u64
    mov  rbx, rax           ; rbx = chat_id

    mov  rdi, msg_ask_user
    call print_str

    ; получаем pubkey целевого пользователя
    mov  rdi, [sock_fd]
    mov  sil, CMD_GET_PUBKEY
    call send_byte

    ; читаем username в input_buf (recv_buf нельзя — recv_response его перебивает)
    lea  rdi, [input_buf]
    xor  al, al
    mov  rcx, USERNAME_LEN
    rep  stosb
    lea  rdi, [input_buf]
    mov  rsi, USERNAME_LEN - 1
    call read_line

    mov  rdi, [sock_fd]
    lea  rsi, [input_buf]
    mov  rdx, USERNAME_LEN
    call tcp_send

    call recv_response
    cmp  al, RESP_PUBKEY
    jne  .fail_user

    ; recv target_n(8) + target_e(8)
    mov  rdi, [sock_fd]
    call recv_u64
    mov  r12, rax           ; r12 = target_n

    mov  rdi, [sock_fd]
    call recv_u64           ; target_e (игнорируем, всегда 65537)

    ; находим chat_d для этого чата
    mov  rdi, rbx
    call find_local_chat_key
    test rax, rax
    jz   .fail_lchat

    mov  rdx, [rax + LCHAT_D]   ; rdx = chat_d

    ; enc_key = rsa_encrypt(chat_d, target_e=65537, target_n)
    mov  rdi, rdx
    mov  rsi, RSA_E
    mov  rdx, r12
    call rsa_encrypt

    ; CMD_SEND_KEY + chat_id(8) + username(32) + enc_key(8)
    push rax
    mov  rdi, [sock_fd]
    mov  sil, CMD_SEND_KEY
    call send_byte
    mov  rdi, [sock_fd]
    mov  rsi, rbx
    call send_u64
    mov  rdi, [sock_fd]
    lea  rsi, [input_buf]   ; username из input_buf (не тронут recv_response)
    mov  rdx, USERNAME_LEN
    call tcp_send
    pop  rsi
    mov  rdi, [sock_fd]
    call send_u64

    call recv_response

    pop  r12
    pop  rbx
    ret

.leave_invite:
    pop  r12
    pop  rbx
    ret

.fail_user:
    mov  rdi, msg_err_no_user
    call show_error
    pop  r12
    pop  rbx
    ret

.fail_lchat:
    mov  rdi, msg_err_no_lchat
    call show_error
    pop  r12
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; save_local_chat_key — сохранить ключ чата локально
; rdi=chat_id, rsi=chat_n, rdx=chat_d
; ─────────────────────────────────────────────────────────────
save_local_chat_key:
    push rbx

    cmp  qword [lchat_count], MAX_LOCAL_CHATS
    jge  .done

    ; imul не трогает rdx (в отличие от mul), chat_d в rdx сохраняется
    imul rax, [lchat_count], LCHAT_SIZE
    lea  rbx, [lchats + rax]

    mov  qword [rbx + LCHAT_ID], rdi
    mov  qword [rbx + LCHAT_N],  rsi
    mov  qword [rbx + LCHAT_D],  rdx

    inc  qword [lchat_count]
.done:
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; find_local_chat_key — найти локальный ключ по chat_id
; rdi=chat_id → rax=&record или 0
; ─────────────────────────────────────────────────────────────
find_local_chat_key:
    push rbx
    xor  rbx, rbx
.loop:
    cmp  rbx, [lchat_count]
    jge  .miss

    mov  rax, rbx
    mov  rcx, LCHAT_SIZE
    mul  rcx
    lea  rdx, [lchats + rax]
    cmp  [rdx + LCHAT_ID], rdi
    je   .hit

    inc  rbx
    jmp  .loop
.miss:
    xor  rax, rax
    jmp  .done
.hit:
    mov  rax, rdx
.done:
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; recv_response — получить 1 байт ответа от сервера
; → al = тип ответа
; ─────────────────────────────────────────────────────────────
recv_response:
    mov  rdi, [sock_fd]
    lea  rsi, [recv_buf]
    mov  rdx, 1
    call tcp_recv
    movzx rax, byte [recv_buf]
    ret

; ─────────────────────────────────────────────────────────────
; print_u64 — вывести u64 как десятичное число
; rdi=value
; ─────────────────────────────────────────────────────────────
print_u64:
    push rbx
    push rbp

    mov  rax, rdi
    lea  rbx, [input_buf + 19]

    test rax, rax
    jnz  .convert
    mov  byte [rbx], '0'
    dec  rbx
    jmp  .print

.convert:
    test rax, rax
    jz   .print
    xor  rdx, rdx
    mov  rcx, 10
    div  rcx
    add  dl, '0'
    mov  [rbx], dl
    dec  rbx
    jmp  .convert

.print:
    inc  rbx
    lea  rcx, [input_buf + 20]
    sub  rcx, rbx           ; длина
    mov  rdi, 1
    mov  rsi, rbx
    mov  rdx, rcx
    mov  rax, 1
    syscall

    pop  rbp
    pop  rbx
    ret

; ─────────────────────────────────────────────────────────────
; parse_u64 — парсить десятичное число из input_buf
; → rax=value
; ─────────────────────────────────────────────────────────────
parse_u64:
    xor  rax, rax
    lea  rsi, [input_buf]
.loop:
    movzx rcx, byte [rsi]
    cmp  cl, '0'
    jb   .done
    cmp  cl, '9'
    ja   .done
    sub  cl, '0'
    imul rax, 10
    add  rax, rcx
    inc  rsi
    jmp  .loop
.done:
    ret

; ─────────────────────────────────────────────────────────────
; show_error — вывести сообщение об ошибке и ждать Enter
; rdi = строка с сообщением
; ─────────────────────────────────────────────────────────────
show_error:
    call print_str
    mov  rdi, msg_press_enter
    call print_str
    lea  rdi, [input_buf]
    mov  rsi, 4
    call read_line
    ret

; ─────────────────────────────────────────────────────────────
; clear_screen — очистить терминал (ANSI escape)
; ─────────────────────────────────────────────────────────────
clear_screen:
    mov  rax, 1
    mov  rdi, 1
    lea  rsi, [str_clear]
    mov  rdx, 7
    syscall
    ret
