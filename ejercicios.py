"""
ejercicios.py
─────────────
Demostraciones del cifrador LFSR. Cada función es independiente:
recibe parámetros, imprime resultados y no tiene efectos secundarios.

Importa exclusivamente desde lfsr_core.
"""

from lfsr_core import (
    LFSR,
    LFSRStreamCipher,
    check_primitive,
)


# ─────────────────────────────────────────────────────────────────────────────
# UTILIDADES DE PRESENTACIÓN
# ─────────────────────────────────────────────────────────────────────────────

def _header(title: str) -> None:
    w = 68
    print(f"\n{'═'*w}\n  {title}\n{'═'*w}")


def _state_diagram(lfsr: LFSR) -> None:
    """Diagrama ASCII del estado actual del LFSR."""
    s, n = lfsr.state_binary, lfsr.n_bits
    print("\n  Estado:")
    print("  ┌" + "───┬" * (n - 1) + "───┐")
    print("  │ " + " │ ".join(s) + " │  ──► salida: " + s[-1])
    print("  └" + "───┴" * (n - 1) + "───┘")
    print("  " + "".join(f"  {i}  " for i in range(1, n + 1)))
    print("  " + "".join(" ▲  " if i in lfsr.taps else "    " for i in range(1, n + 1)))
    print("  (▲ = tap conectado al XOR)")


def _state_table(lfsr: LFSR) -> None:
    """Tabla completa de estados durante un período."""
    table      = lfsr.get_state_table()
    period     = lfsr.compute_period()
    max_period = (1 << lfsr.n_bits) - 1

    print(f"\n  {'Paso':>5} │ {'Estado':^{lfsr.n_bits}} │ Salida")
    print(f"  {'─'*5}─┼─{'─'*lfsr.n_bits}─┼─{'─'*6}")
    for paso, estado, bit in table:
        print(f"  {paso:>5} │ {estado:^{lfsr.n_bits}} │ {bit:>6}")
    print(f"\n  Período real: {period}  │  Máximo posible: {max_period}  │  "
          f"{'✔ período máximo' if period == max_period else '✘ no es período máximo'}")


# ─────────────────────────────────────────────────────────────────────────────
# EJERCICIO 1: LFSR básico — tabla de estados
# ─────────────────────────────────────────────────────────────────────────────

def ejercicio_1_tabla_de_estados() -> None:
    """
    Muestra el funcionamiento paso a paso de un LFSR de 4 bits
    con polinomio x^4 + x^3 + 1 (primitivo, período máximo = 15).
    """
    _header("EJERCICIO 1: LFSR de 4 bits — tabla de estados completa")

    lfsr = LFSR(n_bits=4, taps=[4, 3], seed=0b0001)
    print(f"\n  {lfsr}")
    print(f"  Polinomio: x^4 + x^3 + 1")

    _state_diagram(lfsr)
    _state_table(lfsr)

    lfsr.reset()
    seq = lfsr.generate(lfsr.compute_period())
    print(f"\n  Secuencia de salida completa: {''.join(map(str, seq))}")


# ─────────────────────────────────────────────────────────────────────────────
# EJERCICIO 2: Efecto de los taps en el período
# ─────────────────────────────────────────────────────────────────────────────

def ejercicio_2_efecto_de_los_taps() -> None:
    """
    Compara el período de un LFSR de 4 bits con distintos conjuntos de taps.
    Solo los polinomios primitivos producen el período máximo 2^4 - 1 = 15.
    """
    _header("EJERCICIO 2: Efecto de los taps en el período")

    configs = [
        ([4, 3],       "x^4 + x^3 + 1        primitivo"),
        ([4, 2],       "x^4 + x^2 + 1        no primitivo"),
        ([4, 1],       "x^4 + x + 1           no primitivo"),
        ([4, 3, 2, 1], "x^4 + x^3 + x^2 + x + 1  no primitivo"),
    ]
    max_p = (1 << 4) - 1

    print(f"\n  LFSR de 4 bits | semilla = 1111 | período máximo = {max_p}\n")
    print(f"  {'Polinomio':<44} {'Período':>8} {'¿Máximo?':>10}")
    print(f"  {'─'*44} {'─'*8} {'─'*10}")

    for taps, desc in configs:
        p  = LFSR(4, taps, 0b1111).compute_period()
        ok = "✔" if p == max_p else "✘"
        print(f"  {desc:<44} {p:>8} {ok:>10}")


# ─────────────────────────────────────────────────────────────────────────────
# EJERCICIO 3: Verificación de polinomio primitivo antes de cifrar
# ─────────────────────────────────────────────────────────────────────────────

def ejercicio_3_verificacion_primitivo() -> None:
    """
    Demuestra check_primitive() y la validación integrada en el cifrador.

    Con polinomio primitivo  → cifra y descifra correctamente.
    Con polinomio no primitivo → rechaza con el período real T en que
                                 se repitió la secuencia.
    """
    _header("EJERCICIO 3: Verificación de polinomio primitivo")

    mensaje = "Hola LFSR"

    # ── Primitivo ────────────────────────────────────────────────────────────
    print("\n  ── Polinomio PRIMITIVO: x^4 + x^3 + 1 ──")
    es_prim, periodo = check_primitive(4, [4, 3])
    print(f"  ¿Primitivo? {'✔ Sí' if es_prim else '✘ No'}  |  Período: {periodo}  |  Máximo: {(1<<4)-1}")

    try:
        c  = LFSRStreamCipher(n_bits=4, taps=[4, 3], key=0b1011)
        cx = c.encrypt(mensaje)
        print(f"  Cifrado:    {cx.hex()}")
        print(f"  Descifrado: '{c.decrypt(cx)}'  ✔")
    except ValueError as e:
        print(e)

    # ── No primitivo (T=6) ───────────────────────────────────────────────────
    print("\n  ── Polinomio NO PRIMITIVO: x^4 + x^2 + 1 ──")
    es_prim, periodo = check_primitive(4, [4, 2])
    print(f"  ¿Primitivo? {'✔ Sí' if es_prim else '✘ No'}  |  Período real: {periodo}")
    try:
        LFSRStreamCipher(n_bits=4, taps=[4, 2], key=0b1011).encrypt(mensaje)
    except ValueError as e:
        print(e)

    # ── No primitivo (T=5) ───────────────────────────────────────────────────
    print("\n  ── Polinomio NO PRIMITIVO: x^4 + x^3 + x^2 + x + 1 ──")
    es_prim, periodo = check_primitive(4, [4, 3, 2, 1])
    print(f"  ¿Primitivo? {'✔ Sí' if es_prim else '✘ No'}  |  Período real: {periodo}")
    try:
        LFSRStreamCipher(n_bits=4, taps=[4, 3, 2, 1], key=0b1011).encrypt(mensaje)
    except ValueError as e:
        print(e)


# ─────────────────────────────────────────────────────────────────────────────
# EJERCICIO 4: Cifrado y descifrado de flujo
# ─────────────────────────────────────────────────────────────────────────────

def ejercicio_4_cifrado_flujo() -> None:
    """
    Cifra y descifra un mensaje con LFSRStreamCipher.
    Demuestra también que cambiar un solo bit de la clave produce texto ilegible.
    """
    _header("EJERCICIO 4: Cifrado de flujo — cifrar y descifrar")

    cipher  = LFSRStreamCipher(n_bits=16, taps=[16, 15, 13, 4], key=0xACE1)
    mensaje = "Hola! LFSR es fascinante."

    print(f"\n  Configuración: 16 bits | taps=[16,15,13,4] | clave=0xACE1")
    print(f"  Polinomio: x^16 + x^15 + x^13 + x^4 + 1  (primitivo)")

    cifrado    = cipher.encrypt(mensaje)
    descifrado = cipher.decrypt(cifrado)

    print(f"\n  Original:   '{mensaje}'")
    print(f"  Cifrado:    {cifrado.hex()}")
    print(f"  Descifrado: '{descifrado}'  {'✔' if descifrado == mensaje else '✘'}")

    # Clave incorrecta — 1 bit de diferencia
    cipher_bad = LFSRStreamCipher(n_bits=16, taps=[16, 15, 13, 4], key=0xACE2)
    try:
        preview = cipher_bad.decrypt(cifrado)[:20]
    except UnicodeDecodeError:
        preview = "(bytes indecodificables)"
    print(f"\n  Con clave incorrecta (0xACE2, 1 bit de diferencia):")
    print(f"  Resultado: '{preview}...'  ← ilegible sin la clave correcta")


# ─────────────────────────────────────────────────────────────────────────────
# EJERCICIO 5: Tabla de polinomios primitivos de referencia
# ─────────────────────────────────────────────────────────────────────────────

def ejercicio_5_tabla_primitivos() -> None:
    """
    Verifica experimentalmente que los polinomios primitivos conocidos
    alcanzan el período máximo 2^n − 1.
    """
    _header("EJERCICIO 5: Tabla de polinomios primitivos de referencia")

    primitivos = [
        (2,  [2, 1],             "x^2 + x + 1"),
        (3,  [3, 2],             "x^3 + x^2 + 1"),
        (4,  [4, 3],             "x^4 + x^3 + 1"),
        (5,  [5, 3],             "x^5 + x^3 + 1"),
        (6,  [6, 5],             "x^6 + x^5 + 1"),
        (7,  [7, 6],             "x^7 + x^6 + 1"),
        (8,  [8, 6, 5, 4],       "x^8 + x^6 + x^5 + x^4 + 1"),
        (10, [10, 7],            "x^10 + x^7 + 1"),
        (12, [12, 11, 10, 4],    "x^12 + x^11 + x^10 + x^4 + 1"),
        (16, [16, 15, 13, 4],    "x^16 + x^15 + x^13 + x^4 + 1"),
    ]

    print(f"\n  {'n':>4} │ {'Polinomio':<38} │ {'Esperado':>12} │ {'Real':>12} │ OK")
    print(f"  {'─'*4}─┼─{'─'*38}─┼─{'─'*12}─┼─{'─'*12}─┼─{'─'*3}")

    for n, taps, desc in primitivos:
        expected = (1 << n) - 1
        actual   = LFSR(n, taps, 1).compute_period()
        ok       = "✔" if actual == expected else "✘"
        print(f"  {n:>4} │ {desc:<38} │ {expected:>12,} │ {actual:>12,} │ {ok}")
