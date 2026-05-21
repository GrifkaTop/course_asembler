#!/usr/bin/env python3
"""
Симуляция реального чата: 4 пользователя по очереди входят,
читают переписку и отвечают — как в живом мессенджере.
"""
import time
import pexpect

BINARY  = "./client"
TIMEOUT = 15

CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
GRAY   = "\033[90m"
RST    = "\033[0m"
BOLD   = "\033[1m"

USERS = ["alice", "bob", "charlie", "diana"]

# Сценарий: (отправитель, текст сообщения)
SCRIPT = [
    ("alice",   "Привет всем! Рад вас видеть в нашем чате :)"),
    ("bob",     "Привет Алиса! Наконец-то добрался до компа"),
    ("charlie", "Хей! Долго ждал инвайт, спасибо alice"),
    ("diana",   "Всем привет! Опоздала немного, что пропустила?"),
    ("alice",   "Да ничего особого, только начали. Как у всех дела?"),
    ("bob",     "У меня норм. Кто идёт на встречу в пятницу?"),
    ("charlie", "Я точно буду! Во сколько собираемся?"),
    ("diana",   "В 19:00 как обычно подойдёт?"),
    ("alice",   "Отлично, 19:00 меня устраивает"),
    ("bob",     "Принято. До пятницы тогда!"),
    ("charlie", "Ок, договорились :)"),
    ("diana",   "До встречи всем!"),
]


class Client:
    def __init__(self, username: str):
        self.username = username
        self.p: pexpect.spawn = None

    def _spawn(self):
        self.p = pexpect.spawn(
            BINARY, timeout=TIMEOUT,
            encoding="utf-8", codec_errors="replace"
        )

    def register(self):
        self._spawn()
        self.p.expect("Регистрация")
        self.p.sendline("2")
        self.p.expect("Имя пользователя")
        self.p.sendline(self.username)
        idx = self.p.expect(["Зарегистрирован", "занято", "Ошибка", pexpect.TIMEOUT])
        if idx != 0:
            raise RuntimeError(f"register({self.username}) failed: idx={idx}")
        self.p.expect("Выбор:")

    def login(self):
        self._spawn()
        self.p.expect("Регистрация")
        self.p.sendline("1")
        self.p.expect("Имя пользователя")
        self.p.sendline(self.username)
        idx = self.p.expect(["Выбор:", "Ошибка", "не найден", pexpect.TIMEOUT])
        if idx != 0:
            raise RuntimeError(f"login({self.username}) failed: idx={idx}")

    def create_chat(self, name: str):
        self.p.sendline("1")
        self.p.expect("Название чата")
        self.p.sendline(name)
        self.p.expect(r"Чат создан, ключ:\s*\d+")
        self.p.sendline("")
        self.p.expect("Выбор:")

    def invite(self, chat_id: int, target: str):
        self.p.sendline("3")
        self.p.expect("Номер чата")
        self.p.sendline(str(chat_id))
        self.p.expect("Имя пользователя")
        self.p.sendline(target)
        self.p.expect("Выбор:")

    def send_and_read(self, chat_id: int, text: str) -> list[str]:
        """Войти в чат, прочитать сообщения, отправить текст, выйти из чата."""
        self.p.sendline("2")
        self.p.expect("Номер чата")
        self.p.sendline(str(chat_id))
        self.p.expect("Сообщение")
        buf = self.p.before or ""
        msgs = self._parse_msgs(buf)
        self.p.sendline(text)
        self.p.expect("Сообщение")
        self.p.sendline("")          # Enter = выйти из чата
        self.p.expect("Выбор:")
        return msgs

    def read_all(self, chat_id: int) -> list[str]:
        """Войти в чат, прочитать все сообщения, выйти."""
        self.p.sendline("2")
        self.p.expect("Номер чата")
        self.p.sendline(str(chat_id))
        self.p.expect("Сообщение")
        buf = self.p.before or ""
        msgs = self._parse_msgs(buf)
        self.p.sendline("")
        self.p.expect("Выбор:")
        return msgs

    def _parse_msgs(self, buf: str) -> list[str]:
        msgs = []
        for line in buf.splitlines():
            line = line.strip()
            if ": " in line and not line.startswith("===") and not line.startswith("["):
                msgs.append(line)
        return msgs

    def exit(self):
        try:
            self.p.sendline("4")
            self.p.close()
        except Exception:
            if self.p:
                self.p.close(force=True)


# ─── вывод ───────────────────────────────────────────────────

def print_header(text):
    print(f"\n{CYAN}{'═'*54}")
    print(f"  {text}")
    print(f"{'═'*54}{RST}")

def print_turn(username):
    print(f"\n{YELLOW}  ┌─ {username} открывает чат...{RST}")

def print_history(msgs, last_n=3):
    if msgs:
        shown = msgs[-last_n:]
        if len(msgs) > last_n:
            print(f"  {GRAY}│  ... (ещё {len(msgs) - last_n} сообщ.){RST}")
        for m in shown:
            parts = m.split(": ", 1)
            if len(parts) == 2:
                print(f"  {GRAY}│  {parts[0]}: {parts[1]}{RST}")

def print_send(username, text):
    print(f"  {GREEN}└→ {BOLD}{username}{RST}: {text}")

def print_ok(text):
    print(f"  {GREEN}✓{RST} {text}")


# ─── сценарий ────────────────────────────────────────────────

def main():
    clients = {u: Client(u) for u in USERS}

    # ── 1. Регистрация (все выходят после регистрации) ────────
    print_header("1. Регистрация пользователей")
    for name, c in clients.items():
        c.register()
        c.exit()
        print_ok(f"{name} зарегистрирован")

    # ── 2. alice логинится, создаёт чат, приглашает всех ─────
    print_header("2. alice создаёт чат «общий» и приглашает всех")
    alice = clients["alice"]
    alice.login()
    alice.create_chat("общий")
    print_ok("Чат «общий» создан (id=1)")

    for name in ["bob", "charlie", "diana"]:
        alice.invite(1, name)
        print_ok(f"{name} приглашён")
    alice.exit()

    # ── 3. Живой диалог по сценарию ──────────────────────────
    print_header("3. Симуляция живого разговора")

    # все 4 пользователя логинятся один раз
    sessions: dict[str, Client] = {}
    print(f"  {GRAY}Вход в систему...{RST}")
    for name in USERS:
        clients[name].login()
        sessions[name] = clients[name]
        print_ok(f"{name} вошёл")

    print()

    for sender, text in SCRIPT:
        c = sessions[sender]
        print_turn(sender)
        prev_msgs = c.send_and_read(1, text)
        print_history(prev_msgs)
        print_send(sender, text)
        time.sleep(0.05)

    # завершаем все сессии
    for name, c in sessions.items():
        c.exit()

    # ── 4. Финал: полная история чата ─────────────────────────
    print_header("4. Финал: diana читает всю историю")
    diana = Client("diana")
    diana.login()
    all_msgs = diana.read_all(1)
    diana.exit()

    print(f"\n  {BOLD}═══ ЧАТ: общий ══════════════════════════════{RST}")
    for m in all_msgs:
        parts = m.split(": ", 1)
        if len(parts) == 2:
            sender_name = parts[0]
            body = parts[1]
            color = {
                "alice": "\033[35m", "bob": "\033[34m",
                "charlie": "\033[32m", "diana": "\033[33m",
            }.get(sender_name, GRAY)
            print(f"  {color}{BOLD}{sender_name}{RST}: {body}")
    print(f"  {GRAY}{'─'*46}{RST}")
    print(f"  Всего: {BOLD}{len(all_msgs)}{RST} сообщений")

    print_header("ВСЕ ЭТАПЫ ПРОЙДЕНЫ УСПЕШНО")


if __name__ == "__main__":
    main()
