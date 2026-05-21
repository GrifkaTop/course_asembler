; proto.inc — константы протокола чата
; Платформа: Linux x86-64, FASM

; ─────────────────────────────────────────────────────────────
; Сетевые константы
; ─────────────────────────────────────────────────────────────
AF_INET     equ 2
SOCK_STREAM equ 1
SERVER_PORT equ 0x1F90      ; 8080

; ─────────────────────────────────────────────────────────────
; Команды: Клиент → Сервер
; ─────────────────────────────────────────────────────────────

; Единственная команда без авторизации
CMD_AUTH_START      equ 0x02    ; username(32)

; После авторизации
CMD_REGISTER        equ 0x01    ; username(32) + n(8) + e(8)
CMD_AUTH_RESP       equ 0x03    ; challenge(8)
CMD_CHAT_AUTH       equ 0x04    ; chat_id(8)
CMD_CHAT_AUTH_RESP  equ 0x05    ; chat_id(8) + challenge(8)
CMD_LIST_CHATS      equ 0x06    ; (нет данных)
CMD_CREATE_CHAT     equ 0x07    ; name(32) + chat_n(8) + chat_e(8)
CMD_GET_KEY         equ 0x08    ; chat_id(8)
CMD_SEND_KEY        equ 0x09    ; chat_id(8) + username(32) + enc_key(8)
CMD_GET_PUBKEY      equ 0x0A    ; username(32)
CMD_SEND_MSG        equ 0x0B    ; chat_id(8) + enc_sender(8) + MAX_MSG_BLOCKS×enc_block(8)
CMD_GET_MSGS        equ 0x0C    ; chat_id(8)
CMD_LIST_MY_CHATS   equ 0x0D    ; (нет данных) — только чаты текущего пользователя
CMD_GET_USER_BY_NPART equ 0x0E  ; npart(8) → RESP_OK+username(32) или RESP_ERR

; ─────────────────────────────────────────────────────────────
; Ответы: Сервер → Клиент
; ─────────────────────────────────────────────────────────────
RESP_OK             equ 0x10
RESP_ERR            equ 0x11
RESP_CHALLENGE      equ 0x12    ; enc_challenge(8)
RESP_CHAT_LIST      equ 0x13    ; count(4) + chat[]: id(8)+name(32)+n(8)+e(8)
RESP_CHAT_KEY       equ 0x14    ; enc_key(8) + chat_n(8)
RESP_MSGS           equ 0x15    ; count(4) + msg[]: enc_sender_n(8)+enc_msg(8)
RESP_PUBKEY         equ 0x16    ; n(8) + e(8)
RESP_CHAT_ID        equ 0x17    ; (устарело — клиент знает chat_n сам)

; ─────────────────────────────────────────────────────────────
; Размеры полей (байты)
; ─────────────────────────────────────────────────────────────
USERNAME_LEN        equ 32
CHAT_NAME_LEN       equ 32
KEY_SIZE            equ 8       ; u64 — n, e, d, enc_key, enc_msg
CHAT_ID_SIZE        equ 8

; ─────────────────────────────────────────────────────────────
; Размеры записей хранилища (используются в сервере и клиенте)
; ─────────────────────────────────────────────────────────────
USER_REC        equ (USERNAME_LEN + KEY_SIZE * 2)                  ; 48
CHAT_REC        equ (CHAT_ID_SIZE + CHAT_NAME_LEN + KEY_SIZE * 2)  ; 56
CHAT_KEY_REC    equ (CHAT_ID_SIZE + USERNAME_LEN + KEY_SIZE)        ; 48
MAX_MSG_BLOCKS  equ 43                                              ; 43 × 6 = 258 байт (до 252 символов)
MSG_REC         equ (CHAT_ID_SIZE + KEY_SIZE * (1 + MAX_MSG_BLOCKS)) ; 360

; Смещения полей User
USER_NAME       equ 0
USER_N          equ USERNAME_LEN
USER_E          equ USERNAME_LEN + KEY_SIZE

; Смещения полей Chat
CHAT_ID_OFF     equ 0
CHAT_NAME_OFF   equ CHAT_ID_SIZE
CHAT_N_OFF      equ CHAT_ID_SIZE + CHAT_NAME_LEN
CHAT_E_OFF      equ CHAT_ID_SIZE + CHAT_NAME_LEN + KEY_SIZE

; Смещения полей ChatKey
CKEY_ID_OFF     equ 0
CKEY_USER_OFF   equ CHAT_ID_SIZE
CKEY_KEY_OFF    equ CHAT_ID_SIZE + USERNAME_LEN

; Смещения полей Message
MSG_CHAT_OFF    equ 0
MSG_SENDER_OFF  equ CHAT_ID_SIZE
MSG_BODY_OFF    equ CHAT_ID_SIZE + KEY_SIZE

; ─────────────────────────────────────────────────────────────
; Размеры пакетов (1 байт тип + данные)
; ─────────────────────────────────────────────────────────────
PKT_AUTH_START      equ 1 + USERNAME_LEN
PKT_AUTH_RESP       equ 1 + KEY_SIZE
PKT_REGISTER        equ 1 + USERNAME_LEN + KEY_SIZE + KEY_SIZE
PKT_CHAT_AUTH       equ 1 + CHAT_ID_SIZE
PKT_CHAT_AUTH_RESP  equ 1 + CHAT_ID_SIZE + KEY_SIZE
PKT_CREATE_CHAT     equ 1 + CHAT_NAME_LEN + KEY_SIZE + KEY_SIZE
PKT_GET_KEY         equ 1 + CHAT_ID_SIZE
PKT_SEND_KEY        equ 1 + CHAT_ID_SIZE + USERNAME_LEN + KEY_SIZE
PKT_GET_PUBKEY      equ 1 + USERNAME_LEN
PKT_SEND_MSG        equ 1 + CHAT_ID_SIZE + KEY_SIZE * (1 + MAX_MSG_BLOCKS)
PKT_GET_MSGS        equ 1 + CHAT_ID_SIZE
