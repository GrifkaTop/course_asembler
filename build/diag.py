#!/usr/bin/env python3
"""
diag.py — подключается к живому серверу как tester1
и запрашивает список всех чатов / своих чатов.
Диагностика без пересборки.
"""
import pexpect

BINARY  = "./client"
TIMEOUT = 10

GREEN = "\033[32m"
CYAN  = "\033[36m"
GRAY  = "\033[90m"
RST   = "\033[0m"
BOLD  = "\033[1m"


def main():
    print(f"\n{CYAN}=== diag.py — диагностика сервера ==={RST}\n")

    p = pexpect.spawn(BINARY, timeout=TIMEOUT,
                      encoding="utf-8", codec_errors="replace")

    # Вход как tester1
    p.expect("Регистрация")
    p.sendline("1")
    p.expect("Имя пользователя")
    p.sendline("tester1")

    idx = p.expect(["Выбор:", "Ошибка", "не найден", pexpect.TIMEOUT])
    if idx != 0:
        print(f"Не удалось войти как tester1 (idx={idx})")
        print("Сначала запустите тест: bash run_test.sh")
        p.close(force=True)
        return

    print(f"{GREEN}✓ Авторизован как tester1{RST}\n")

    # Войти в чат → получить список своих чатов
    print(f"{CYAN}── Мои чаты (CMD_LIST_MY_CHATS) ──────────────{RST}")
    p.sendline("2")
    p.expect("Номер чата")
    buf = p.before or ""
    chats = []
    for line in buf.splitlines():
        line = line.strip()
        if line and line[0].isdigit() and ". " in line:
            chats.append(line)
            print(f"  {line}")
    if not chats:
        print(f"  {GRAY}(нет чатов){RST}")

    # Выйти из меню чатов
    p.sendline("")
    p.expect("Выбор:")

    print(f"\n  Найдено чатов: {BOLD}{len(chats)}{RST}")

    # Завершить
    p.sendline("4")
    p.close()
    print(f"\n{GREEN}Диагностика завершена.{RST}\n")


if __name__ == "__main__":
    main()
