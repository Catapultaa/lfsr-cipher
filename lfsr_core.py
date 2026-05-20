"""
lfsr_core.py
────────────
Lógica pura del cifrador LFSR. Sin prints, sin ejercicios.

Clases:
    LFSR                      — registro de desplazamiento (Fibonacci)
    LFSRPseudorandomGenerator — agrupa bits del LFSR en bytes
    LFSRStreamCipher          — cifrador/descifrador de flujo XOR

Funciones:
    check_primitive(n_bits, taps)   → (bool, int)
    require_primitive(n_bits, taps) → None | raises ValueError
"""

from typing import List, Tuple
import math


# ─────────────────────────────────────────────────────────────────────────────
# LFSR
# ─────────────────────────────────────────────────────────────────────────────

class LFSR:
    """
    Registro de desplazamiento con retroalimentación lineal (configuración Fibonacci).

    Estructura para n=4, taps=[4,3]  (polinomio x^4 + x^3 + 1):

        ┌────┬────┬────┬────┐
        │ b3 │ b2 │ b1 │ b0 │ ──► salida (b0)
        └──┬─┴──┬─┴────┴────┘
           │    │
           └─XOR┘ ──► nuevo b3 (retroalimentación)

    Convención de taps:
        Los taps son los exponentes del polinomio, sin el término independiente.
        x^4 + x^3 + 1  →  taps=[4, 3]   (el "+1" es siempre implícito)

    Período máximo:
        2^n − 1, alcanzable solo con polinomios primitivos sobre GF(2).
        Con cualquier otro polinomio el período es menor y la secuencia
        se vuelve predecible antes.
    """

    def __init__(self, n_bits: int, taps: List[int], seed: int):
        """
        Args:
            n_bits: Número de celdas / grado del polinomio.
            taps:   Exponentes del polinomio. Rango válido: [1, n_bits].
                    Ejemplo: [4, 3] para x^4 + x^3 + 1.
            seed:   Estado inicial. Debe ser distinto de 0 — si fuera 0,
                    la retroalimentación siempre sería 0 y el registro
                    quedaría atrapado para siempre.

        Raises:
            ValueError: Si seed == 0 o algún tap está fuera de rango.
        """
        if seed == 0:
            raise ValueError("La semilla no puede ser 0: el LFSR quedaría paralizado.")
        if not all(1 <= t <= n_bits for t in taps):
            raise ValueError(f"Todos los taps deben estar en [1, {n_bits}].")

        self.n_bits = n_bits
        self.taps   = sorted(taps, reverse=True)
        self.seed   = seed & ((1 << n_bits) - 1)   # truncar a n bits
        self.state  = self.seed
        self.output_sequence: List[int] = []

    # ── Propiedades ──────────────────────────────────────────────────────────

    @property
    def state_binary(self) -> str:
        """Estado actual como cadena binaria de longitud fija."""
        return format(self.state, f'0{self.n_bits}b')

    @property
    def tap_mask(self) -> int:
        """
        Máscara entera con un 1 en cada posición de tap.
        Tap i (1-indexed desde MSB) → bit en posición (n_bits − i).
        Permite calcular la retroalimentación con una sola operación AND.
        """
        mask = 0
        for tap in self.taps:
            mask |= (1 << (self.n_bits - tap))
        return mask

    # ── Operación ────────────────────────────────────────────────────────────

    def step(self) -> int:
        """
        Ejecuta un ciclo y devuelve el bit de salida.

        Pasos:
          1. El bit de salida es el LSB (b0) del estado actual.
          2. La retroalimentación es la paridad (XOR) de todos los bits en
             posiciones de tap — equivalente a contar cuántos están en 1 y
             tomar ese conteo módulo 2.
          3. El registro se desplaza un bit a la derecha.
          4. La retroalimentación entra por el MSB.

        Returns:
            int: 0 o 1.
        """
        output_bit = self.state & 1
        feedback   = bin(self.state & self.tap_mask).count('1') % 2
        self.state = (self.state >> 1) | (feedback << (self.n_bits - 1))
        self.output_sequence.append(output_bit)
        return output_bit

    def generate(self, n: int) -> List[int]:
        """Genera n bits ejecutando step() n veces."""
        return [self.step() for _ in range(n)]

    def compute_period(self) -> int:
        """
        Calcula el período real: número de pasos hasta que el estado
        vuelve exactamente al estado inicial (semilla).

        No modifica el estado del objeto.
        """
        saved      = self.state
        self.state = self.seed
        count      = 0
        while True:
            self.step()
            count += 1
            if self.state == self.seed or count > (1 << self.n_bits):
                break
        self.state = saved
        return count

    def reset(self) -> None:
        """Reinicia el registro a la semilla original."""
        self.state           = self.seed
        self.output_sequence = []

    def get_state_table(self, max_steps: int = None) -> List[Tuple]:
        """
        Devuelve la tabla de estados durante un período completo.

        Returns:
            Lista de (paso, estado_binario_antes, bit_salida).
            No modifica el estado del objeto.
        """
        saved      = self.state
        self.state = self.seed
        period     = self.compute_period()
        steps      = min(max_steps or period, period)
        self.state = self.seed

        table = []
        for i in range(steps):
            before = self.state_binary
            bit    = self.step()
            table.append((i + 1, before, bit))

        self.state = saved
        return table

    def __repr__(self) -> str:
        return (f"LFSR(n_bits={self.n_bits}, taps={self.taps}, "
                f"seed={self.seed:0{self.n_bits}b}, state={self.state_binary})")


# ─────────────────────────────────────────────────────────────────────────────
# GENERADOR PSEUDOALEATORIO
# ─────────────────────────────────────────────────────────────────────────────

class LFSRPseudorandomGenerator:
    """
    Agrupa bits del LFSR en bytes para usarlos como keystream.

    El cifrador de flujo necesita bytes (no bits sueltos), así que esta
    clase toma 8 bits consecutivos del LFSR y los combina en un entero
    de 8 bits (MSB primero).
    """

    def __init__(self, n_bits: int, taps: List[int], seed: int):
        self._lfsr = LFSR(n_bits, taps, seed)

    def next_byte(self) -> int:
        """Devuelve el próximo byte (0–255) del keystream."""
        byte_val = 0
        for bit in self._lfsr.generate(8):
            byte_val = (byte_val << 1) | bit
        return byte_val

    def generate_bytes(self, n: int) -> bytes:
        """Genera n bytes de keystream."""
        return bytes([self.next_byte() for _ in range(n)])


# ─────────────────────────────────────────────────────────────────────────────
# VERIFICACIÓN DE POLINOMIO PRIMITIVO
# ─────────────────────────────────────────────────────────────────────────────

def check_primitive(n_bits: int, taps: List[int]) -> Tuple[bool, int]:
    """
    Verifica experimentalmente si el polinomio es primitivo sobre GF(2).

    Un polinomio es primitivo si y solo si el LFSR recorre los 2^n − 1
    estados no nulos antes de repetirse. Se comprueba corriendo el LFSR
    con semilla=1 y midiendo cuántos pasos tarda en volver al inicio.

    Args:
        n_bits: Grado del polinomio.
        taps:   Exponentes (ej: [4, 3] para x^4 + x^3 + 1).

    Returns:
        (True,  2^n-1)  si ES primitivo.
        (False, T)      si NO lo es, donde T es el período real.
    """
    max_period = (1 << n_bits) - 1
    period     = LFSR(n_bits, taps, seed=1).compute_period()
    return (period == max_period), period


def require_primitive(n_bits: int, taps: List[int]) -> None:
    """
    Lanza ValueError si el polinomio NO es primitivo.

    El mensaje incluye:
      - El período real T en que se repitió la secuencia.
      - El período máximo que debería tener.
      - Una sugerencia de polinomio primitivo para el mismo n.

    Se llama automáticamente dentro de encrypt() y decrypt().
    """
    is_prim, period = check_primitive(n_bits, taps)
    if not is_prim:
        max_period = (1 << n_bits) - 1
        poly_str   = ' + '.join(f'x^{t}' for t in sorted(taps, reverse=True)) + ' + 1'
        raise ValueError(
            f"\n"
            f"  ✘ El polinomio {poly_str} NO es primitivo sobre GF(2).\n"
            f"\n"
            f"  Período real    : T = {period}\n"
            f"  Período máximo  : T = 2^{n_bits} − 1 = {max_period}\n"
            f"\n"
            f"  La secuencia se repite cada {period} bits en lugar de {max_period}.\n"
            f"  El keystream es predecible y el cifrado resulta débil.\n"
            f"\n"
            f"  Sugerencia para {n_bits} bits:\n"
            f"  {_suggest_primitive(n_bits)}"
        )


def _suggest_primitive(n_bits: int) -> str:
    """Polinomio primitivo conocido para n bits (tabla de referencia)."""
    table = {
        2:  "taps=[2,1]        →  x^2+x+1",
        3:  "taps=[3,2]        →  x^3+x^2+1",
        4:  "taps=[4,3]        →  x^4+x^3+1",
        5:  "taps=[5,3]        →  x^5+x^3+1",
        6:  "taps=[6,5]        →  x^6+x^5+1",
        7:  "taps=[7,6]        →  x^7+x^6+1",
        8:  "taps=[8,6,5,4]    →  x^8+x^6+x^5+x^4+1",
        10: "taps=[10,7]       →  x^10+x^7+1",
        12: "taps=[12,11,10,4] →  x^12+x^11+x^10+x^4+1",
        16: "taps=[16,15,13,4] →  x^16+x^15+x^13+x^4+1",
    }
    return table.get(n_bits, f"consulta una tabla de polinomios primitivos para n={n_bits}")


# ─────────────────────────────────────────────────────────────────────────────
# CIFRADOR DE FLUJO
# ─────────────────────────────────────────────────────────────────────────────

class LFSRStreamCipher:
    """
    Cifrador de flujo basado en LFSR.

    Principio de operación:
        cifrado:    C = P ⊕ K
        descifrado: P = C ⊕ K   ← misma operación, gracias a la simetría del XOR

    Donde K es el keystream generado por el LFSR inicializado con la clave.
    Tanto cifrado como descifrado regeneran K desde cero, por eso producen
    el mismo resultado.

    Requisito: el polinomio DEBE ser primitivo. Si no lo es, encrypt() y
    decrypt() lanzan ValueError antes de operar, indicando el período real T.

    ⚠️  Uso educativo. El LFSR simple es vulnerable al ataque de
    Berlekamp-Massey: con solo 2n bits observados se puede reconstruir
    la clave completa. En producción se combina con funciones no lineales.
    """

    def __init__(self, n_bits: int, taps: List[int], key: int):
        """
        Args:
            n_bits: Tamaño del LFSR en bits.
            taps:   Exponentes del polinomio.
            key:    Clave secreta (semilla del LFSR).
                    Nunca reutilizar la misma clave con textos diferentes.
        """
        self.n_bits = n_bits
        self.taps   = taps
        self.key    = key

    def _fresh_keystream(self, length: int) -> bytes:
        """Genera `length` bytes de keystream desde el inicio de la clave."""
        return LFSRPseudorandomGenerator(self.n_bits, self.taps, self.key).generate_bytes(length)

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, plaintext: str, encoding: str = 'utf-8') -> bytes:
        """
        Cifra un texto plano.

        Pasos:
          1. Verifica que el polinomio sea primitivo.
          2. Codifica el texto a bytes.
          3. Genera keystream de la misma longitud.
          4. Aplica XOR byte a byte.

        Args:
            plaintext: Texto a cifrar.
            encoding:  Codificación del texto (default: utf-8).

        Returns:
            bytes: Texto cifrado.

        Raises:
            ValueError: Si el polinomio no es primitivo.
        """
        require_primitive(self.n_bits, self.taps)
        plain_bytes = plaintext.encode(encoding)
        return self._xor_bytes(plain_bytes, self._fresh_keystream(len(plain_bytes)))

    def decrypt(self, ciphertext: bytes, encoding: str = 'utf-8') -> str:
        """
        Descifra bytes cifrados.

        Regenera exactamente el mismo keystream que en encrypt() y aplica
        XOR — deshaciendo el cifrado.

        Args:
            ciphertext: Bytes a descifrar.
            encoding:   Codificación del texto original.

        Returns:
            str: Texto descifrado.

        Raises:
            ValueError: Si el polinomio no es primitivo.
        """
        require_primitive(self.n_bits, self.taps)
        return self._xor_bytes(ciphertext, self._fresh_keystream(len(ciphertext))).decode(encoding)
