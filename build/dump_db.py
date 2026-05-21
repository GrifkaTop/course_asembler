#!/usr/bin/env python3
"""
dump_db.py — парсит data.bin и выводит содержимое:
пользователи, чаты, ключи чатов, сообщения.
"""
import struct, sys, os

DB_FILE = "data.bin"
MAGIC   = b"CHATDAT1"

USERNAME_LEN  = 32
CHAT_NAME_LEN = 32
KEY_SIZE      = 8
MAX_MSG_BLOCKS = 43

USER_REC      = USERNAME_LEN + KEY_SIZE * 2          # 48
CHAT_REC      = KEY_SIZE + CHAT_NAME_LEN + KEY_SIZE * 2  # 56
CHAT_KEY_REC  = KEY_SIZE + USERNAME_LEN + KEY_SIZE   # 48
MSG_REC       = KEY_SIZE + KEY_SIZE + MAX_MSG_BLOCKS * KEY_SIZE  # 360

CYAN  = "\033[36m"
GRAY  = "\033[90m"
GREEN = "\033[32m"
RST   = "\033[0m"
BOLD  = "\033[1m"


def read_str(data, off, maxlen):
    s = data[off:off+maxlen]
    return s.split(b'\x00', 1)[0].decode("utf-8", errors="replace")

def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def parse(data):
    if data[:8] != MAGIC:
        print("Неверный magic — не data.bin или повреждён")
        sys.exit(1)

    off = 8
    user_count     = read_u64(data, off);     off += 8
    chat_count     = read_u64(data, off);     off += 8
    chat_key_count = read_u64(data, off);     off += 8
    msg_count      = read_u64(data, off);     off += 8

    print(f"\n{CYAN}{BOLD}=== data.bin ==={RST}")
    print(f"  пользователей: {user_count}  чатов: {chat_count}  "
          f"ключей: {chat_key_count}  сообщений: {msg_count}\n")

    # ── Пользователи ─────────────────────────────────────────
    print(f"{CYAN}── Пользователи ({user_count}) ──────────────────────{RST}")
    users = []
    for i in range(16):
        name = read_str(data, off, USERNAME_LEN)
        n    = read_u64(data, off + USERNAME_LEN)
        e    = read_u64(data, off + USERNAME_LEN + KEY_SIZE)
        users.append((name, n, e))
        if i < user_count:
            print(f"  [{i}] {name:<20} n=0x{n:016x}  e={e}")
        off += USER_REC

    # ── Чаты ─────────────────────────────────────────────────
    print(f"\n{CYAN}── Чаты ({chat_count}) ──────────────────────────────{RST}")
    chats = []
    for i in range(16):
        chat_id   = read_u64(data, off)
        chat_name = read_str(data, off + KEY_SIZE, CHAT_NAME_LEN)
        chat_n    = read_u64(data, off + KEY_SIZE + CHAT_NAME_LEN)
        chat_e    = read_u64(data, off + KEY_SIZE + CHAT_NAME_LEN + KEY_SIZE)
        chats.append((chat_id, chat_name, chat_n))
        if i < chat_count:
            print(f"  [{i}] '{chat_name}'  id=0x{chat_id:016x}  n=0x{chat_n:016x}")
        off += CHAT_REC

    # ── Ключи чатов ──────────────────────────────────────────
    print(f"\n{CYAN}── Ключи чатов ({chat_key_count}) ───────────────────{RST}")
    for i in range(128):
        cid      = read_u64(data, off)
        username = read_str(data, off + KEY_SIZE, USERNAME_LEN)
        enc_key  = read_u64(data, off + KEY_SIZE + USERNAME_LEN)
        if i < chat_key_count:
            chat_name = next((c[1] for c in chats if c[0] == cid), f"0x{cid:x}")
            print(f"  [{i}] chat='{chat_name}'  user={username:<20} enc_key=0x{enc_key:016x}")
        off += CHAT_KEY_REC

    # ── Сообщения ─────────────────────────────────────────────
    print(f"\n{CYAN}── Сообщения ({msg_count}) ──────────────────────────{RST}")
    for i in range(256):
        chat_id    = read_u64(data, off)
        enc_sender = read_u64(data, off + KEY_SIZE)
        if i < msg_count:
            chat_name = next((c[1] for c in chats if c[0] == chat_id), f"0x{chat_id:x}")
            print(f"  [{i}] chat='{chat_name}'  enc_sender=0x{enc_sender:016x}")
        off += MSG_REC

    print()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DB_FILE
    if not os.path.exists(path):
        print(f"Файл не найден: {path}")
        sys.exit(1)
    with open(path, "rb") as f:
        data = f.read()
    parse(data)
