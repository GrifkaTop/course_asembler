# Чат с шифрованием — внутреннее устройство

---

## Карта файлов

| Файл | Что внутри |
|---|---|
| `client.asm` | клиент: UI, команды, буферы, print_u64, parse_u64 |
| `server.asm` | сервер: accept-loop, handle_client, find_*/save/load |
| `proto.inc` | константы команд/ответов, смещения полей, размеры записей |
| `crypto.inc` | rsa_keygen, rsa_modexp, mulmod, mod_inverse, gen_prime32 |
| `net.inc` | tcp_send, tcp_recv, send_byte, send_u64, recv_u64, read_line, print_str |

---

## Архитектура

```
client ←──── TCP 8080 ────→ server
              бинарный протокол

alice.key / bob.key  (RSA ключи, генерируются при регистрации, хранятся только локально)
```

Два компонента:
- `server` — многопоточный, каждый клиент в отдельном потоке (`sys_clone` + `CLONE_VM`), общие данные защищены спинлоком (`xchg`-based)
- `client` — при регистрации генерирует RSA-ключи и сохраняет `username.key`; при входе загружает `.key` и проходит авторизацию; подключается всегда к `127.0.0.1:8080`

---

## BSS-раскладка client.asm

```
my_n            rq 1          ; RSA-модуль пользователя
my_e            rq 1          ; публичный экспонент (65537)
my_d            rq 1          ; приватный экспонент
my_username     rb 32         ; USERNAME_LEN=32

sock_fd         rq 1

cur_chat_id     rq 1          ; chat_n текущего чата (он же ID)
cur_chat_n      rq 1
cur_chat_d      rq 1

lchats          rb 16*24      ; локальный кеш ключей чатов
lchat_count     rq 1          ; сколько записей в lchats

chat_list_n     rq 16         ; chat_n в порядке показа в меню (обновляется при каждом list)
chat_list_name  rb 16*32      ; имена чатов в том же порядке (CHAT_NAME_LEN=32 каждое)
chat_list_count rq 1
cur_chat_name   rb 32         ; имя текущего открытого чата

key_buf         rb 56         ; буфер для чтения/записи .key файла
filename_buf    rb 40         ; "username.key\0"
ip_buf          rb 32
input_buf       rb 256        ; ввод пользователя (read_line, rep movsb)
recv_buf        rb 512        ; приём с сервера (tcp_recv, recv_response)
reg_mode        rb 1          ; '1'=войти, '2'=регистрация
u64_scratch     rb 24         ; scratch ТОЛЬКО для print_u64, не пересекается с input_buf

key_cache       rb 32*40      ; кэш: fingerprint(8) + username(32) = 40 байт × 32 записи
key_cache_cnt   rq 1          ; сколько записей в key_cache

dmsg_buf        rb 256*272    ; буфер декодированных сообщений: npart(8)+text(264) × 256
dmsg_count      rq 1          ; сколько записей заполнено
```

**Важно:** `print_u64` пишет цифры в `u64_scratch[0..19]`, а не в `input_buf`. Раньше он писал в `input_buf` — это вызывало порчу имён чатов через последующий `rep movsb`. Исправлено добавлением отдельного scratch-буфера.

---

## BSS-раскладка server.asm

```
server_sock     rq 1
global_lock     rq 1          ; спинлок (xchg-based, 0=свободен)

user_count      rq 1
chat_count      rq 1
chat_key_count  rq 1
msg_count       rq 1

users           rb 16*48      ; MAX_USERS * USER_REC
chats           rb 16*56      ; MAX_CHATS * CHAT_REC
chat_keys       rb 128*48     ; MAX_CHAT_KEYS * CHAT_KEY_REC
messages        rb 256*360    ; MAX_MESSAGES * MSG_REC
```

### Стек потока (LOCAL_* смещения относительно r14)

```
LOCAL_AUTH      equ 0         ; 1 байт — авторизован (0/1)
LOCAL_PAD       equ 1         ; 7 байт padding
LOCAL_CHALLENGE equ 8         ; u64 — текущий challenge
LOCAL_USER      equ 16        ; 32 байта — username авторизованного
LOCAL_RECV      equ 48        ; 512 байт — буфер приёма
LOCAL_SIZE      equ 560
```

`r14` = база сессии на стеке; `r13` = client_sock (неизменен в потоке).

---

## Что и где хранится

### Файл `.key` (56 байт, только у пользователя)

```
[0-7]   n   (u64)
[8-15]  e   (u64) — 65537
[16-23] d   (u64) — приватный экспонент
[24-55] username  (32 байта)
```

### Записи сервера (proto.inc)

| Структура | Поля | Размер | Смещения полей |
|---|---|---|---|
| `USER_REC` | `username(32)` + `n(8)` + `e(8)` | 48 | `USER_NAME=0, USER_N=32, USER_E=40` |
| `CHAT_REC` | `chat_id(8)` + `name(32)` + `chat_n(8)` + `chat_e(8)` | 56 | `CHAT_ID_OFF=0, CHAT_NAME_OFF=8, CHAT_N_OFF=40, CHAT_E_OFF=48` |
| `CHAT_KEY_REC` | `chat_id(8)` + `username(32)` + `enc_key(8)` | 48 | `CKEY_ID_OFF=0, CKEY_USER_OFF=8, CKEY_KEY_OFF=40` |
| `MSG_REC` | `chat_id(8)` + `enc_sender(8)` + `enc_blocks[43×8]` | 360 | `MSG_CHAT_OFF=0, MSG_SENDER_OFF=8, MSG_BODY_OFF=16` |

`chat_id` = `chat_n` (RSA-модуль чата, он же уникальный идентификатор).

**Сервер НЕ знает:** приватные ключи пользователей `d`, `chat_d` в открытом виде, содержимое сообщений.

---

## Функции client.asm

| Функция | Вход | Выход | Что делает |
|---|---|---|---|
| `_start` | — | — | меню входа → подключение → регистрация/авторизация → main_loop |
| `main_loop` | — | — | главное меню, диспетчер 1/2/3/4 |
| `cmd_register` | `my_username`, `my_n`, `my_e` в BSS | rax=1/0 | CMD_REGISTER + username + n + e |
| `cmd_auth` | `my_username`, `my_d`, `my_n` в BSS | rax=1/0 | CMD_AUTH_START → challenge → расшифровываем my_d → CMD_AUTH_RESP |
| `cmd_create_chat` | ввод с клавиатуры | — | ввод имени → keygen → CMD_CREATE_CHAT → CMD_SEND_KEY → показ ID |
| `cmd_enter_chat` | ввод с клавиатуры | — | list_chats → ввод номера → get_key/find_local → chat_auth → chat_loop |
| `cmd_invite` | ввод с клавиатуры | — | list_chats → ввод номера → get_pubkey → CMD_SEND_KEY с ключом цели |
| `cmd_list_chats` | — | `chat_list_n[]`, `chat_list_name[]`, `chat_list_count` | CMD_LIST_MY_CHATS → принимает список, печатает «N. name» |
| `cmd_chat_auth` | `cur_chat_id`, `cur_chat_d`, `cur_chat_n` в BSS | rax=1/0 | CMD_CHAT_AUTH → challenge → расшифровываем chat_d → CMD_CHAT_AUTH_RESP |
| `cmd_read_msgs` | `cur_chat_id`, `cur_chat_d`, `cur_chat_n` в BSS | — | три прохода: 1) принять все MSG_REC в `dmsg_buf`; 2) `resolve_all_senders`; 3) вывод |
| `cmd_send_msg` | `input_buf` (текст), `cur_chat_*` в BSS | — | шифрует fingerprint (нижние 6 байт `my_n`) + 43 блока текста → CMD_SEND_MSG |
| `cache_add_name` | rdi=fingerprint, rsi=&username | — | добавляет запись в `key_cache[]`, инкрементирует `key_cache_cnt` |
| `cache_lookup_name` | rdi=fingerprint | rax=&name или 0 | линейный поиск в `key_cache[]` по fingerprint |
| `resolve_all_senders` | `dmsg_buf[]`, `dmsg_count` в BSS | — | для каждого неизвестного fingerprint: CMD_GET_USER_BY_NPART → имя → кэш |
| `save_local_chat_key` | rdi=chat_id, rsi=chat_n, rdx=chat_d | — | пишет запись в `lchats[]`, инкрементирует `lchat_count` |
| `find_local_chat_key` | rdi=chat_id | rax=&LCHAT или 0 | линейный поиск в `lchats[]` по chat_id |
| `recv_response` | `sock_fd` в BSS | al=код ответа | читает 1 байт из сокета в `recv_buf[0]` |
| `print_u64` | rdi=u64 | — | десятичный вывод в stdout; пишет цифры в `u64_scratch` |
| `parse_u64` | `input_buf` | rax=u64 | разбирает десятичное число из буфера |
| `build_key_filename` | `my_username` в BSS | `filename_buf` | формирует `«username».key\0` |
| `load_key_file` / `save_key_file` | `filename_buf` | rax=1/0 | читает/пишет `.key` через `key_buf` |
| `show_error` | rdi=строка ошибки | — | print_str + ожидание Enter |
| `clear_screen` | — | — | ANSI `\033[2J\033[H` через sys_write |

---

## Функции server.asm

| Функция | Вход | Выход | Что делает |
|---|---|---|---|
| `handle_client` | r13=client_sock, r14=&сессия | — | главный цикл потока: читает 1 байт команды, диспетчер |
| `.do_register` | LOCAL_RECV (username+n+e) | RESP_OK/ERR | сохраняет USER_REC; отклоняет дубли имени |
| `.do_auth_start` | LOCAL_RECV (username) | RESP_CHALLENGE+enc | getrandom → encrypt(challenge, user_n) → ждёт CMD_AUTH_RESP |
| `.do_list_chats` | — | RESP_CHAT_LIST + N×CHAT_REC | шлёт все чаты |
| `.do_list_my_chats` | LOCAL_USER (username сессии) | RESP_CHAT_LIST + N×CHAT_REC | только чаты где есть CHAT_KEY_REC для текущего юзера |
| `.do_create_chat` | LOCAL_RECV (name+chat_n+chat_e) | RESP_OK/ERR | сохраняет CHAT_REC; `chat_id = chat_n` |
| `.do_get_key` | LOCAL_RECV (chat_id) | RESP_CHAT_KEY + enc_key + chat_n | find_chat_key → шлёт зашифрованный ключ |
| `.do_send_key` | LOCAL_RECV (chat_id+username+enc_key) | RESP_OK/ERR | сохраняет CHAT_KEY_REC |
| `.do_get_pubkey` | LOCAL_RECV (username) | RESP_PUBKEY + n + e | find_user → шлёт публичный ключ |
| `.do_chat_auth` | LOCAL_RECV (chat_id) | RESP_CHALLENGE → RESP_OK/ERR | challenge-response с приватным ключом чата |
| `.do_send_msg` | LOCAL_RECV (chat_id+enc_sender+43×enc_block) | RESP_OK/ERR | сохраняет MSG_REC |
| `.do_get_msgs` | LOCAL_RECV (chat_id) | RESP_MSGS + count + N×MSG_REC | фильтрует messages[] по chat_id |
| `.do_get_user_by_npart` | LOCAL_RECV (fingerprint(8)) | RESP_OK + username(32) / RESP_ERR | ищет пользователя по нижним 6 байтам n; ← username(32) |
| `find_user` | rdi=username (32 байта) | rax=&USER_REC или 0 | линейный поиск в `users[]` |
| `find_chat` | rdi=chat_id (u64) | rax=&CHAT_REC или 0 | линейный поиск в `chats[]` |
| `find_chat_key` | rdi=chat_id, rsi=username | rax=&CHAT_KEY_REC или 0 | поиск по паре (chat_id, username) |
| `str_eq` | rdi=s1, rsi=s2 | rax=1/0 | побайтовое сравнение USERNAME_LEN байт |
| `acquire_lock` / `release_lock` | — | — | спинлок через `xchg [global_lock], rax` |
| `save_data` / `load_data` | — | — | сериализация BSS-массивов в/из `data.bin` |

---

## Функции net.inc / crypto.inc

**net.inc** — все функции чистые по ABI (сохраняют rbx, rbp, r12–r15):

| Функция | Вход | Выход | Что делает |
|---|---|---|---|
| `tcp_send` | rdi=sock, rsi=buf, rdx=len | rax=bytes_sent | sys_write в цикле |
| `tcp_recv` | rdi=sock, rsi=buf, rdx=len | rax≠0=OK, 0=EOF | sys_read в цикле до rdx байт |
| `send_byte` | rdi=sock, sil=byte | — | push sil → tcp_send 1 байт |
| `send_u64` | rdi=sock, rsi=value | — | push rsi → tcp_send 8 байт (LE) |
| `recv_u64` | rdi=sock | rax=value | sub rsp,8 → tcp_recv → pop |
| `read_line` | rdi=buf, rsi=maxlen | rax=bytes_read | читает stdin побайтово до `\n`; null-terminate, `\n` не включается |
| `print_str` | rdi=str (null-terminated) | — | strlen + sys_write в stdout |
| `print_str_n` | rdi=str, rsi=len | — | sys_write len байт в stdout |

**crypto.inc:**

| Функция | Вход | Выход | Что делает |
|---|---|---|---|
| `rsa_keygen` | rdi=&n, rsi=&e, rdx=&d | записывает n,e,d по указателям | gen_prime32 × 2, e=65537, d=mod_inverse; round-trip проверка |
| `rsa_encrypt` / `rsa_decrypt` | rdi=base, rsi=exp, rdx=n | rax=base^exp mod n | оба — алиасы `rsa_modexp` |
| `rsa_modexp` | rdi=base, rsi=exp, rdx=n | rax=результат | square-and-multiply; base редуцируется mod n перед стартом |
| `mulmod` | rdi=a, rsi=b, rdx=n | rax=(a×b) mod n | 128-бит `mul` + `div` |
| `mod_inverse` | rdi=a, rsi=m | rax=a⁻¹ mod m | расширенный алгоритм Евклида |
| `gen_prime32` | — | rax=простое ≥ 0xC0000001 | getrandom 4 байта; биты 31+30+0 = 1; пробное деление |
| `gen_prime16` | — | rax=16-битное простое | то же, 16 бит (не используется в проекте) |
| `is_prime32` | edi=n | rax=1/0 | пробное деление до √n |

---

## RSA-64

`n = p * q`, где p и q — случайные 32-битные простые числа (≥ 0xC0000001).
Фиксированный публичный экспонент `e = 65537`.

```
encrypt(msg, e, n)  = msg^e mod n
decrypt(enc, d, n)  = enc^d mod n
```

Один RSA-блок вмещает до 6 байт (значение < n ≥ 2^63).
Сообщение разбивается на 43 блока → до 258 байт / 252 символа на сообщение.

**Идентификация отправителя:** вместо прямого шифрования имени шифруется **fingerprint** — нижние 6 байт публичного ключа `my_n` (значение < 2^48 < n). При чтении получатель расшифровывает fingerprint и запрашивает у сервера команду `CMD_GET_USER_BY_NPART` → получает полное имя. Это позволяет отображать имена любой длины (до 31 символа) без изменения формата MSG_REC.

---

## Протокол

Бинарный, поверх TCP. Каждый пакет: 1 байт кода + данные.

### Команды клиент → сервер

| Код | Команда | Данные |
|---|---|---|
| 0x01 | `CMD_REGISTER` | `username(32)` + `n(8)` + `e(8)` |
| 0x02 | `CMD_AUTH_START` | `username(32)` |
| 0x03 | `CMD_AUTH_RESP` | `challenge(8)` |
| 0x04 | `CMD_CHAT_AUTH` | `chat_id(8)` |
| 0x05 | `CMD_CHAT_AUTH_RESP` | `chat_id(8)` + `challenge(8)` |
| 0x06 | `CMD_LIST_CHATS` | — |
| 0x07 | `CMD_CREATE_CHAT` | `name(32)` + `chat_n(8)` + `chat_e(8)` |
| 0x08 | `CMD_GET_KEY` | `chat_id(8)` |
| 0x09 | `CMD_SEND_KEY` | `chat_id(8)` + `username(32)` + `enc_key(8)` |
| 0x0A | `CMD_GET_PUBKEY` | `username(32)` |
| 0x0B | `CMD_SEND_MSG` | `chat_id(8)` + `enc_sender(8)` + `43×enc_block(8)` |
| 0x0C | `CMD_GET_MSGS` | `chat_id(8)` |
| 0x0D | `CMD_LIST_MY_CHATS` | — |
| 0x0E | `CMD_GET_USER_BY_NPART` | `fingerprint(8)` — нижние 6 байт `n` отправителя |

### Ответы сервер → клиент

| Код | Ответ | Данные |
|---|---|---|
| 0x10 | `RESP_OK` | — |
| 0x11 | `RESP_ERR` | — |
| 0x12 | `RESP_CHALLENGE` | `enc_challenge(8)` |
| 0x13 | `RESP_CHAT_LIST` | `count(8)` + N × `CHAT_REC(56)` |
| 0x14 | `RESP_CHAT_KEY` | `enc_key(8)` + `chat_n(8)` |
| 0x15 | `RESP_MSGS` | `count(8)` + N × `MSG_REC(360)` |
| 0x16 | `RESP_PUBKEY` | `n(8)` + `e(8)` |
| 0x17 | `RESP_CHAT_ID` | устарело — не используется |

---

## Основные процессы

### Регистрация

| # | Клиент | Сервер |
|---|---|---|
| 1 | → `CMD_REGISTER` + username(32) + n(8) + e(8) | |
| 2 | | Проверяет имя на дубль; сохраняет USER_REC в `users[]` |
| 3 | | ← `RESP_OK` / `RESP_ERR` |
| 4 | Затем сразу проходит `cmd_auth` (challenge-response) | |

### Вход (challenge-response)

| # | Клиент | Сервер |
|---|---|---|
| 1 | → `CMD_AUTH_START` + username(32) | |
| 2 | | find_user; `challenge = getrandom()`, `btr 63` (< 2^63 < n) |
| 3 | | `enc = rsa_encrypt(challenge, user_e, user_n)` |
| 4 | | ← `RESP_CHALLENGE` + enc(8) |
| 5 | `rsa_decrypt(enc, my_d, my_n)` → challenge | |
| 6 | → `CMD_AUTH_RESP` + challenge(8) | |
| 7 | | Сравнивает с сохранённым challenge |
| 8 | | ← `RESP_OK` / `RESP_ERR` |

### Создание чата

| # | Клиент (Alice) | Сервер |
|---|---|---|
| 1 | `rsa_keygen()` → chat_n, chat_e, chat_d (chat_d остаётся локально) | |
| 2 | → `CMD_CREATE_CHAT` + name(32) + chat_n(8) + chat_e(8) | |
| 3 | | `CHAT_ID = chat_n`; сохраняет CHAT_REC |
| 4 | | ← `RESP_OK` |
| 5 | Сохраняет `{chat_id=chat_n, chat_n, chat_d}` в `lchats[]` | |
| 6 | `enc_key = rsa_encrypt(chat_d, my_e, my_n)` | |
| 7 | → `CMD_SEND_KEY` + chat_id(8) + my_username(32) + enc_key(8) | |
| 8 | | Сохраняет CHAT_KEY_REC |
| 9 | | ← `RESP_OK` |

### Приглашение пользователя

| # | Клиент (Alice) | Сервер |
|---|---|---|
| 1 | → `CMD_GET_PUBKEY` + "bob"(32) | |
| 2 | | find_user("bob") |
| 3 | | ← `RESP_PUBKEY` + bob_n(8) + bob_e(8) |
| 4 | `enc_key = rsa_encrypt(chat_d, bob_e, bob_n)` | |
| 5 | → `CMD_SEND_KEY` + chat_id(8) + "bob"(32) + enc_key(8) | |
| 6 | | Сохраняет CHAT_KEY_REC для bob |
| 7 | | ← `RESP_OK` |

### Вход в чат

| # | Клиент (Bob) | Сервер |
|---|---|---|
| 1 | Проверяет `lchats[]` — ключ не найден локально | |
| 2 | → `CMD_GET_KEY` + chat_id(8) | |
| 3 | | `find_chat_key(chat_id, "bob")` |
| 4 | | ← `RESP_CHAT_KEY` + enc_key(8) + chat_n(8) |
| 5 | `chat_d = rsa_decrypt(enc_key, my_d, my_n)` | |
| 6 | Сохраняет в `lchats[]`; далее cmd_chat_auth | |
| 7 | → `CMD_CHAT_AUTH` + chat_id(8) | |
| 8 | | `challenge = getrandom()`; `enc = rsa_encrypt(challenge, chat_e, chat_n)` |
| 9 | | ← `RESP_CHALLENGE` + enc(8) |
| 10 | `rsa_decrypt(enc, chat_d, chat_n)` → challenge | |
| 11 | → `CMD_CHAT_AUTH_RESP` + chat_id(8) + challenge(8) | |
| 12 | | Сравнивает; ← `RESP_OK` / `RESP_ERR` |

### Отправка сообщения

| # | Клиент | Сервер |
|---|---|---|
| 1 | `fingerprint = my_n & 0xFFFFFFFFFFFF` (нижние 6 байт публичного ключа) | |
| 2 | `enc_sender = rsa_encrypt(fingerprint, chat_e, chat_n)` | |
| 3 | Для каждого из 43 блоков по 6 байт: `enc_block[i] = rsa_encrypt(text[i*6..], chat_e, chat_n)` | |
| 4 | → `CMD_SEND_MSG` + chat_id(8) + enc_sender(8) + 43×enc_block(8) | |
| 5 | | Сохраняет MSG_REC |
| 6 | | ← `RESP_OK` |

### Чтение сообщений

| # | Клиент | Сервер |
|---|---|---|
| 1 | → `CMD_GET_MSGS` + chat_id(8) | |
| 2 | | Фильтрует `messages[]` по chat_id |
| 3 | | ← `RESP_MSGS` + count(8) + N × MSG_REC(360) |
| 4 | **Проход 1:** для каждой записи: `rsa_decrypt(enc_sender)` → fingerprint; декодирует 43 блока текста → сохраняет в `dmsg_buf[]` | |
| 5 | **Проход 2:** для каждого уникального fingerprint без имени в кэше: | |
| 6 | → `CMD_GET_USER_BY_NPART` + fingerprint(8) | |
| 7 | | Ищет пользователя по нижним 6 байтам n |
| 8 | | ← `RESP_OK` + username(32) |
| 9 | Кэширует fingerprint → username в `key_cache[]` | |
| 10 | **Проход 3:** выводит все «имя: текст\n» из `dmsg_buf[]` | |

---

## Персистентность (data.bin)

```
[0-7]    "CHATDAT1"  ← magic
[8+]     user_count(8) + chat_count(8) + chat_key_count(8) + msg_count(8)
         + users[16×48] + chats[16×56] + chat_keys[128×48] + messages[256×360]
```

Итого: ~100 КБ. При старте читает magic, если совпадает — загружает одним `sys_read`.
Сбросить: `make cleandata`.

---

## Лимиты

| Параметр | Значение |
|---|---|
| Максимум пользователей | 16 |
| Максимум чатов | 16 |
| Максимум ключей чатов | 128 |
| Максимум сообщений | 256 |
| Длина сообщения | до 252 байт |
| Имя / название чата | до 31 байта |

Все данные хранятся в одном файле `data.bin` (~100 КБ). Разбивка на несколько файлов (отдельно пользователи, чаты, сообщения) значительно усложнила бы реализацию на чистом ассемблере без стандартной библиотеки, поэтому была выбрана единая плоская структура с фиксированными смещениями.

---

## Что можно добавить в будущем

- **Уведомления в главном меню** — при возврате в меню показывать количество новых сообщений в каждом чате (периодический опрос через `CMD_GET_MSGS` в фоновом потоке)
- **Автообновление чата** — пока пользователь находится внутри чата, подгружать новые сообщения в реальном времени без необходимости выходить и заходить обратно (второй поток-читатель или `poll`/`epoll` на сокете)
- **Система друзей** — список контактов с возможностью добавления по имени; быстрое приглашение в чат через список друзей вместо ввода имени вручную
