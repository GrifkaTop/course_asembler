; crypto.inc — RSA-64 для Linux x86-64, FASM
; Соглашение: System V AMD64 ABI
;   аргументы: rdi, rsi, rdx, rcx, r8, r9
;   возврат:   rax
;   сохраняет: rbx, rbp, r12–r15

RSA_E equ 65537     ; фиксированный публичный экспонент

; ─────────────────────────────────────────────────────────────
; mulmod — (a * b) mod n без переполнения (через 128-бит mul)
; rdi=a, rsi=b, rdx=n → rax
; ─────────────────────────────────────────────────────────────
mulmod:
    mov rcx, rdx        ; rcx = n (mul затрёт rdx)
    mov rax, rdi
    mul rsi             ; rdx:rax = a * b
    div rcx             ; rax = quot, rdx = (a*b) mod n
    mov rax, rdx
    ret

; ─────────────────────────────────────────────────────────────
; rsa_modexp — base^exp mod n  (square-and-multiply)
; rdi=base, rsi=exp, rdx=n → rax
; ─────────────────────────────────────────────────────────────
rsa_modexp:
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi        ; r12 = base
    mov r13, rsi        ; r13 = exp
    mov r14, rdx        ; r14 = n

    ; редуцируем base mod n — base может быть >= n (напр. my_n > chat_n)
    xor  rdx, rdx
    mov  rax, r12
    div  r14
    mov  r12, rdx       ; r12 = base mod n

    mov rbx, 1          ; rbx = result = 1

.loop:
    test r13, r13
    jz   .done

    test r13, 1
    jz   .no_mul

    ; result = (result * base) mod n
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r14
    call mulmod
    mov rbx, rax

.no_mul:
    shr r13, 1

    ; base = (base * base) mod n
    mov rdi, r12
    mov rsi, r12
    mov rdx, r14
    call mulmod
    mov r12, rax

    jmp .loop

.done:
    mov rax, rbx
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; encrypt и decrypt — один и тот же modexp, разные ключи
rsa_encrypt:
rsa_decrypt:
    jmp rsa_modexp

; ─────────────────────────────────────────────────────────────
; gcd — наибольший общий делитель (алгоритм Евклида)
; rdi=a, rsi=b → rax
; ─────────────────────────────────────────────────────────────
gcd:
    mov rax, rdi
    mov rcx, rsi
.loop:
    test rcx, rcx
    jz   .done
    xor  rdx, rdx
    div  rcx            ; rdx = a mod b
    mov  rax, rcx
    mov  rcx, rdx
    jmp  .loop
.done:
    ret

; ─────────────────────────────────────────────────────────────
; mod_inverse — a^-1 mod m  (расширенный алгоритм Евклида)
; rdi=a, rsi=m → rax
; ─────────────────────────────────────────────────────────────
mod_inverse:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, rsi        ; r15 = m (для финальной корректировки)

    ; r12=old_r  r13=r  r14=old_s  rbx=s
    mov r12, rdi        ; old_r = a
    mov r13, rsi        ; r     = m
    mov r14, 1          ; old_s = 1
    xor rbx, rbx        ; s     = 0

.loop:
    test r13, r13
    jz   .done

    ; q = old_r / r,  rem = old_r % r
    mov  rax, r12
    xor  rdx, rdx
    div  r13            ; rax=q, rdx=rem

    ; (old_r, r) ← (r, rem)
    mov  rcx, r13
    mov  r13, rdx
    mov  r12, rcx

    ; (old_s, s) ← (s, old_s − q*s)
    push rax            ; save q
    imul rbx            ; rdx:rax = q * s (128-бит, rdx отбрасывается)
    sub  r14, rax       ; r14 = old_s − q*s  (результат всегда влезает в 64 бит)
    xchg r14, rbx       ; r14 = старое s (новое old_s), rbx = новое s
    pop  rax

    jmp .loop

.done:
    mov rax, r14        ; результат = old_s
    test rax, rax
    jns  .positive
    add  rax, r15       ; отрицательный — приводим в [0, m)
.positive:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ─────────────────────────────────────────────────────────────
; is_prime32 — проверка простоты (пробное деление)
; edi=n → rax: 1=простое, 0=составное
; ─────────────────────────────────────────────────────────────
is_prime32:
    cmp edi, 2
    jb  .not_prime
    je  .prime
    test edi, 1
    jz  .not_prime      ; чётное > 2 — составное
    cmp edi, 3
    je  .prime

    push rbx
    push r12

    mov r12d, edi       ; r12d = n
    mov ebx,  3         ; делитель = 3

.trial:
    ; если делитель > n/делитель → делитель > sqrt(n) → простое
    mov  eax, r12d
    xor  edx, edx
    div  ebx            ; eax = n/ebx, edx = n%ebx
    cmp  ebx, eax
    ja   .found_prime

    test edx, edx       ; n % делитель == 0 → составное
    jz   .found_composite

    add  ebx, 2         ; следующий нечётный
    jmp  .trial

.found_prime:
    pop r12
    pop rbx
.prime:
    mov eax, 1
    ret

.found_composite:
    pop r12
    pop rbx
.not_prime:
    xor eax, eax
    ret

; ─────────────────────────────────────────────────────────────
; gen_prime32 — случайное 32-битное простое число
; → rax
; ─────────────────────────────────────────────────────────────
gen_prime32:
    push rbx

.try:
    ; получаем 4 случайных байта через getrandom (syscall 318)
    sub rsp, 8
    mov rax, 318
    mov rdi, rsp
    mov rsi, 4
    xor rdx, rdx
    syscall
    mov ebx, dword [rsp]
    add rsp, 8

    ; устанавливаем биты 31 и 30 (n >= 0xC0000000) и бит 0 (нечётное)
    or  ebx, 0xC0000001

    mov edi, ebx
    call is_prime32
    test eax, eax
    jz  .try

    mov eax, ebx        ; mov 32→64 автоматически зануляет старшие биты
    pop rbx
    ret

; ─────────────────────────────────────────────────────────────
; gen_prime16 — случайное 16-битное простое число
; → rax  (значение в диапазоне [0xC001, 0xFFFF])
;
; С 16-битными простыми φ(n) < 2^32, и промежуточные произведения
; q*s в mod_inverse не превышают ~2^47 — переполнения нет.
; ─────────────────────────────────────────────────────────────
gen_prime16:
    push rbx

.try:
    ; получаем 2 случайных байта через getrandom (syscall 318)
    sub rsp, 8
    mov rax, 318
    mov rdi, rsp
    mov rsi, 2
    xor rdx, rdx
    syscall
    movzx ebx, word [rsp]
    add rsp, 8

    ; устанавливаем биты 15 и 14 (n >= 0xC000) и бит 0 (нечётное)
    or  bx, 0xC001

    mov edi, ebx
    call is_prime32
    test eax, eax
    jz  .try

    mov eax, ebx
    pop rbx
    ret

; ─────────────────────────────────────────────────────────────
; rsa_keygen — генерация ключевой пары (n, e, d)
; rdi=&n, rsi=&e, rdx=&d
; ─────────────────────────────────────────────────────────────
rsa_keygen:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov r12, rdi        ; r12 = &n
    mov r13, rsi        ; r13 = &e
    mov r14, rdx        ; r14 = &d

.gen:
    ; генерируем p
    call gen_prime32
    mov  r15, rax       ; r15 = p

    ; генерируем q ≠ p
.gen_q:
    call gen_prime32
    cmp  rax, r15
    je   .gen_q
    mov  rbx, rax       ; rbx = q

    ; n = p * q
    mov rax, r15
    mul rbx             ; rdx:rax = p*q (влезает в 64 бит)
    mov [r12], rax

    ; e = 65537 (фиксированный)
    mov qword [r13], RSA_E

    ; φ(n) = (p−1) * (q−1)
    mov rax, r15
    dec rax             ; p−1
    mov rcx, rbx
    dec rcx             ; q−1
    mul rcx             ; rax = φ(n)
    mov rbp, rax        ; rbp = φ(n)

    ; проверяем gcd(e, φ(n)) == 1, иначе берём другие простые
    mov rdi, RSA_E
    mov rsi, rbp
    call gcd
    cmp rax, 1
    jne .gen

    ; d = e^-1 mod φ(n)
    mov rdi, RSA_E
    mov rsi, rbp
    call mod_inverse
    mov [r14], rax

    ; --- round-trip верификация ключей ---
    ; test_msg = φ(n)/3  (< n, т.к. φ(n) < n)
    xor  rdx, rdx
    mov  rax, rbp
    mov  rcx, 3
    div  rcx
    mov  r15, rax       ; r15 = test_msg (p больше не нужен)

    ; enc = test_msg ^ e mod n
    mov  rdi, r15
    mov  rsi, RSA_E
    mov  rdx, [r12]
    call rsa_modexp

    ; dec = enc ^ d mod n
    mov  rdi, rax
    mov  rsi, [r14]
    mov  rdx, [r12]
    call rsa_modexp

    ; dec должен совпасть с test_msg — иначе d вычислен неверно
    cmp  rax, r15
    jne  .gen

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
