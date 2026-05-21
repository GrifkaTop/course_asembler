#!/usr/bin/env python3
"""
diag2.py — расширенная диагностика:
проверяет структуры ключей чатов и корректность записей в базе.
Входит как все известные пользователи и проверяет доступность чатов.
"""
import pexpect, sys

BINARY  = "./client"
TIMEOUT = 10

GREEN = "\033[32m"
RED   = "\033[31m"
CYAN  = "\033[36m"
GRAY  = "\033[90m"
YELLOW = "\033[33m"
RST   = "\033[0m"
BOLD  = "\033[1m"

USERS = ["tester1", "tester2", "tester3", "tester4", "tester5", "tester6",
         "alice", "bob", "charlie", "diana"]


def check_user(username):
    p = pexpect.spawn(BINARY, timeout=TIMEOUT,
                      encoding="utf-8", codec_errors="replace")
    try:
        p.expect("Регистрация")
        p.sendline("1")
        p.expect("Имя пользователя")
        p.sendline(username)

        idx = p.expect(["Выбор:", "Ошибка", "не найден", pexpect.TIMEOUT])
        if idx != 0:
            return None   # пользователь не зарегистрирован

        # получаем список своих чатов
        p.sendline("2")
        p.expect("Номер чата")
        buf = p.before or ""
        chats = []
        for line in buf.splitlines():
            line = line.strip()
            if line and line[0].isdigit() and ". " in line:
                chats.append(line)

        p.sendline("")
        p.expect("Выбор:")
        p.sendline("4")
        p.close()
        return chats

    except Exception as e:
        p.close(force=True)
        return None


def try_enter_chat(username, ordinal):
    """Пробует войти в чат и прочитать сообщения. Возвращает кол-во сообщений или -1."""
    p = pexpect.spawn(BINARY, timeout=TIMEOUT,
                      encoding="utf-8", codec_errors="replace")
    try:
        p.expect("Регистрация")
        p.sendline("1")
        p.expect("Имя пользователя")
        p.sendline(username)
        p.expect("Выбор:")

        p.sendline("2")
        p.expect("Номер чата")
        p.sendline(str(ordinal))

        idx = p.expect(["Сообщение", "Ошибка", pexpect.TIMEOUT])
        if idx != 0:
            p.close(force=True)
            return -1

        buf = p.before or ""
        msgs = [l.strip() for l in buf.splitlines()
                if ": " in l and not l.strip().startswith("===")]

        p.sendline("")
        p.expect("Выбор:")
        p.sendline("4")
        p.close()
        return len(msgs)

    except Exception:
        p.close(force=True)
        return -1


def main():
    print(f"\n{CYAN}{'═'*52}")
    print(f"  diag2.py — расширенная диагностика базы")
    print(f"{'═'*52}{RST}\n")

    found_users = {}
    print(f"{CYAN}── Проверка пользователей ──────────────────────{RST}")
    for username in USERS:
        chats = check_user(username)
        if chats is not None:
            found_users[username] = chats
            status = f"{len(chats)} чат(ов)"
            print(f"  {GREEN}✓{RST} {username:<16} — {status}")
            for c in chats:
                print(f"    {GRAY}{c}{RST}")
        else:
            print(f"  {GRAY}–{RST} {username:<16} — не зарегистрирован")

    if not found_users:
        print(f"\n{RED}Нет зарегистрированных пользователей.{RST}")
        print("Сначала запустите: bash run_test.sh\n")
        sys.exit(1)

    # Проверяем чтение сообщений
    print(f"\n{CYAN}── Проверка чтения сообщений ───────────────────{RST}")
    ok_count = 0
    fail_count = 0
    for username, chats in found_users.items():
        for i, chat_line in enumerate(chats[:3]):  # первые 3 чата
            ordinal = i + 1
            n = try_enter_chat(username, ordinal)
            if n >= 0:
                print(f"  {GREEN}✓{RST} {username} → чат #{ordinal}: {n} сообщ.")
                ok_count += 1
            else:
                print(f"  {RED}✗{RST} {username} → чат #{ordinal}: ошибка входа")
                fail_count += 1

    print(f"\n{CYAN}── Итог ────────────────────────────────────────{RST}")
    print(f"  Пользователей: {BOLD}{len(found_users)}{RST}")
    print(f"  Проверок чатов: {GREEN}{ok_count} OK{RST}"
          + (f"  {RED}{fail_count} FAIL{RST}" if fail_count else ""))

    if fail_count == 0:
        print(f"\n  {GREEN}{BOLD}База в порядке.{RST}\n")
    else:
        print(f"\n  {RED}{BOLD}Обнаружены проблемы с ключами чатов.{RST}\n")


if __name__ == "__main__":
    main()
