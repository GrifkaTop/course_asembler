#!/usr/bin/env python3
"""
Автотест: 6 параллельных клиентов, 6 фаз.
Используется как регрессионный тест.
"""
import threading
import pexpect

BINARY  = "./client"
TIMEOUT = 15

CYAN  = "\033[36m"
GREEN = "\033[32m"
RED   = "\033[31m"
RST   = "\033[0m"
BOLD  = "\033[1m"

USERS = ["tester1", "tester2", "tester3", "tester4", "tester5", "tester6"]

errors = []
errors_lock = threading.Lock()


def ok(msg):
    print(f"  {GREEN}[OK]{RST} {msg}")

def fail(msg):
    print(f"  {RED}[FAIL]{RST} {msg}")
    with errors_lock:
        errors.append(msg)

def header(text):
    print(f"\n{CYAN}{'─'*50}")
    print(f"  {text}")
    print(f"{'─'*50}{RST}")


class Client:
    def __init__(self, username):
        self.username = username
        self.p = None

    def _spawn(self):
        self.p = pexpect.spawn(BINARY, timeout=TIMEOUT,
                               encoding="utf-8", codec_errors="replace")

    def register(self):
        self._spawn()
        self.p.expect("Регистрация")
        self.p.sendline("2")
        self.p.expect("Имя пользователя")
        self.p.sendline(self.username)
        idx = self.p.expect(["Зарегистрирован", "занято", "Ошибка", pexpect.TIMEOUT])
        if idx == 0:
            ok(f"register({self.username})")
            self.p.expect("Выбор:")
            return True
        fail(f"register({self.username}) → idx={idx}")
        return False

    def login(self):
        self._spawn()
        self.p.expect("Регистрация")
        self.p.sendline("1")
        self.p.expect("Имя пользователя")
        self.p.sendline(self.username)
        idx = self.p.expect(["Выбор:", "Ошибка", pexpect.TIMEOUT])
        if idx == 0:
            ok(f"login({self.username})")
            return True
        fail(f"login({self.username}) → idx={idx}")
        return False

    def create_chat(self, name):
        self.p.sendline("1")
        self.p.expect("Название чата")
        self.p.sendline(name)
        idx = self.p.expect([r"Чат создан, ключ:\s*(\d+)", pexpect.TIMEOUT], timeout=TIMEOUT)
        if idx != 0:
            fail(f"create_chat('{name}')")
            return None
        # читаем ordinal из списка чатов после нажатия Enter
        self.p.sendline("")
        self.p.expect("Выбор:")
        # порядковый номер = количество чатов у этого пользователя
        self.p.sendline("2")          # войти в чат — узнаем ordinal
        idx2 = self.p.expect([r"(\d+)\.\s+" + name, pexpect.TIMEOUT])
        if idx2 == 0:
            ordinal = int(self.p.match.group(1))
            ok(f"create_chat('{name}') → ordinal={ordinal}")
            self.p.sendline("")       # Enter = назад
            self.p.expect("Выбор:")
            return ordinal
        fail(f"create_chat('{name}') — не нашли в списке")
        self.p.sendline("")
        self.p.expect("Выбор:")
        return None

    def invite(self, chat_ordinal, target):
        self.p.sendline("3")
        self.p.expect("Номер чата")
        self.p.sendline(str(chat_ordinal))
        self.p.expect("Имя пользователя")
        self.p.sendline(target)
        self.p.expect("Выбор:")
        ok(f"invite(chat={chat_ordinal} → {target})")

    def send_msg(self, chat_ordinal, text):
        self.p.sendline("2")
        self.p.expect("Номер чата")
        self.p.sendline(str(chat_ordinal))
        self.p.expect("Сообщение")
        self.p.sendline(text)
        self.p.expect("Сообщение")
        self.p.sendline("")
        self.p.expect("Выбор:")
        ok(f"send({self.username} → chat{chat_ordinal}): '{text}'")

    def read_msgs(self, chat_ordinal):
        self.p.sendline("2")
        self.p.expect("Номер чата")
        self.p.sendline(str(chat_ordinal))
        self.p.expect("Сообщение")
        buf = self.p.before or ""
        msgs = [l.strip() for l in buf.splitlines()
                if ": " in l and not l.strip().startswith("===")]
        self.p.sendline("")
        self.p.expect("Выбор:")
        return msgs

    def exit(self):
        try:
            self.p.sendline("4")
            self.p.close()
        except Exception:
            if self.p:
                self.p.close(force=True)
        ok(f"exit({self.username})")


# ─── фазы теста ──────────────────────────────────────────────

def phase1_register():
    header("1. Регистрация 6 пользователей (параллельно)")
    clients = [Client(u) for u in USERS]

    def do(c):
        c.register()
        c.exit()

    threads = [threading.Thread(target=do, args=(c,)) for c in clients]
    for t in threads: t.start()
    for t in threads: t.join()


def phase2_create_chats():
    header("2. Создание 12 чатов (tester1)")
    c = Client("tester1")
    c.login()
    for i in range(1, 13):
        c.create_chat(f"chat{i:02d}")
    return c   # оставляем залогиненным


def phase3_invite_all(c1):
    header("3. Все 6 участников → chat01 (id=1)")
    for name in USERS[1:]:
        c1.invite(1, name)


def phase4_invite_one(c1):
    header("4. По одному участнику в chat02–chat12")
    pairs = [
        (2, "tester3"), (3, "tester4"), (4, "tester5"),
        (5, "tester6"), (6, "tester2"), (7, "tester3"),
        (8, "tester4"), (9, "tester5"), (10, "tester6"),
        (11, "tester2"), (12, "tester3"),
    ]
    for ordinal, target in pairs:
        c1.invite(ordinal, target)
    c1.exit()


def phase5_send_parallel():
    header("5. Все 6 клиентов → chat01 параллельно (id=1)")
    clients = [Client(u) for u in USERS]

    def do(c):
        c.login()
        c.send_msg(1, f"Привет от {c.username}!")
        c.exit()

    threads = [threading.Thread(target=do, args=(c,)) for c in clients]
    for t in threads: t.start()
    for t in threads: t.join()


def phase6_read_parallel():
    header("6. Все 6 клиентов читают chat01 параллельно")
    clients = [Client(u) for u in USERS]
    results = {}

    def do(c):
        c.login()
        msgs = c.read_msgs(1)
        results[c.username] = msgs
        ok(f"read({c.username} ← chat1): {len(msgs)} сообщ.")
        for m in msgs:
            print(f"       [{c.username}] {m}")
        c.exit()

    threads = [threading.Thread(target=do, args=(c,)) for c in clients]
    for t in threads: t.start()
    for t in threads: t.join()

    # проверяем что у всех одинаковое количество сообщений
    counts = set(len(v) for v in results.values())
    if len(counts) != 1:
        fail(f"Разное количество сообщений у клиентов: {results}")


# ─── main ─────────────────────────────────────────────────────

def main():
    print(f"\n{CYAN}{'═'*50}")
    print(f"  ТЕСТ: 6 клиентов параллельно")
    print(f"{'═'*50}{RST}")

    phase1_register()
    c1 = phase2_create_chats()
    phase3_invite_all(c1)
    phase4_invite_one(c1)
    phase5_send_parallel()
    phase6_read_parallel()

    print(f"\n{CYAN}{'═'*50}{RST}")
    if errors:
        print(f"  {RED}{BOLD}ОШИБКИ ({len(errors)}):{RST}")
        for e in errors:
            print(f"    - {e}")
    else:
        print(f"  {GREEN}{BOLD}ВСЕ ТЕСТЫ ПРОЙДЕНЫ{RST}")
    print(f"{CYAN}{'═'*50}{RST}\n")


if __name__ == "__main__":
    main()
