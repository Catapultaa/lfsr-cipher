"""
lfsr_core.py
────────────
Lógica del cifrador LFSR.

Clases:
    LFSR                      — registro de desplazamiento (Fibonacci)
    LFSRPseudorandomGenerator — agrupa bits del LFSR en bytes
    LFSRStreamCipher          — cifrador/descifrador de flujo XOR

Funciones:
    check_primitive(n_bits, taps)   → (bool, int)
    require_primitive(n_bits, taps) → None | raises ValueError
"""

from typing import List, Tuple


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
        2^n − 1, alcanzable solo con polinomios primitivos.
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

        Lanza:
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
        """
        Retorna el estado actual del registro como cadena binaria de ancho fijo.

        La cadena se rellena con ceros por la izquierda hasta exactamente
        ``n_bits`` caracteres. El índice 0 corresponde al bit más significativo
        (x¹, posición de entrada de retroalimentación); el índice ``n_bits − 1``
        corresponde al bit menos significativo (xⁿ, posición de salida).

        Esta propiedad es de solo lectura y no avanza ni muta el registro.

        Retorna:
            str: Representación binaria de ``self.state`` rellenada con ceros,
                 siempre de ``n_bits`` caracteres. Ejemplo: state=6, n_bits=4
                 produce ``'0110'``.
        """
        return format(self.state, f'0{self.n_bits}b')

    @property
    def tap_mask(self) -> int:
        """
        Máscara entera con un 1 en cada posición de tap activa.

        Tap i (1-indexed desde MSB) → bit en posición (n_bits − i).
        Permite calcular la retroalimentación con una sola operación AND.

        Con esta máscara, el bit de retroalimentación XOR se reduce a una sola
        expresión: ``bin(state & tap_mask).count('1') % 2``, evitando un
        bucle explícito sobre las posiciones de tap en cada ciclo de reloj.

        Retorna:
            int: Máscara cuyos bits activos corresponden a las posiciones de tap
                 del polinomio de retroalimentación. El valor se deriva
                 exclusivamente de ``self.taps`` y ``self.n_bits``, y se
                 recalcula en cada acceso.
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

        Retorna:
            int: 0 o 1.
        """
        output_bit = self.state & 1
        feedback   = bin(self.state & self.tap_mask).count('1') % 2
        self.state = (self.state >> 1) | (feedback << (self.n_bits - 1))
        self.output_sequence.append(output_bit)
        return output_bit

    def generate(self, n: int) -> List[int]:
        """
        Avanza el registro ``n`` pasos y retorna los bits de salida recolectados.

        Llama a :py:meth:`step` exactamente ``n`` veces en secuencia. Cada
        llamada muta ``self.state`` y agrega a ``self.output_sequence``. Los
        bits se retornan en el orden en que fueron producidos.

        Args:
            n (int): Número de ciclos de reloj a ejecutar. Cero es válido y
                     produce una lista vacía.

        Retorna:
            List[int]: Lista ordenada de ``n`` bits de salida (cada uno 0 o 1),
                       donde el índice 0 es el primer bit emitido.
        """
        return [self.step() for _ in range(n)]

    def compute_period(self) -> int:
        """
        Calcula el período real de la secuencia LFSR.

        Calcula el período real: número de pasos hasta que el estado
        vuelve exactamente al estado inicial (semilla).

        No modifica el estado del objeto.

        El método guarda el ``self.state`` actual, reinicia a ``self.seed``
        y avanza el registro paso a paso hasta que el estado regresa a la
        semilla (o se supera el límite máximo de ``2^n_bits`` pasos, como
        protección contra polinomios degenerados). El estado original se
        restaura tras la medición.

        Retorna:
            int: El período T tal que, tras exactamente T pasos a partir de
                 ``self.seed``, el registro vuelve a ``self.seed``.
                 Para un polinomio primitivo, T = 2^n_bits − 1.
                 Para un polinomio no primitivo, T < 2^n_bits − 1.

        Nota:
            ``self.output_sequence`` se extiende como efecto secundario de
            las llamadas internas a ``step()``, pero se sobreescribe cuando
            se restaura el estado; los llamadores no deben depender de su
            contenido tras el retorno de este método.
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
        """
        Reinicia el registro a su estado semilla original.

        Restaura ``self.state`` a ``self.seed`` y limpia
        ``self.output_sequence``. Tras esta llamada, el registro es
        indistinguible de una instancia recién construida con los mismos
        argumentos ``n_bits``, ``taps`` y ``seed``.

        Retorna:
            None
        """
        self.state           = self.seed
        self.output_sequence = []

    def get_state_table(self, max_steps: int = None) -> List[Tuple]:
        """
        Retorna la tabla de evolución de estados durante un período completo.

        Calcula la secuencia completa de estados del registro a partir de
        ``self.seed`` durante un período completo, o hasta ``max_steps`` pasos
        si se especifica. El objeto no se muta: ``self.state`` y
        ``self.output_sequence`` se guardan y restauran alrededor del cálculo.

        Args:
            max_steps (int | None): Número máximo de filas a incluir en la
                tabla. Cuando es ``None`` (valor predeterminado), se usa el
                período completo. Si se proporciona, la salida contiene
                ``min(max_steps, period)`` filas.

        Retorna:
            List[Tuple]: Lista ordenada de tuplas de tres elementos, una por paso:

                * ``paso`` (int)          — Índice de paso basado en 1.
                * ``estado_antes`` (str)  — Estado binario del registro *antes*
                  del paso, rellenado con ceros a ``n_bits`` caracteres.
                * ``bit_salida`` (int)    — Bit de salida producido en ese paso
                  (0 o 1).

        Nota:
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
        """
        Inicializa el generador construyendo el LFSR interno.

        Args:
            n_bits (int): Número de etapas del registro LFSR.
            taps (List[int]): Exponentes de los términos del polinomio de
                retroalimentación (excluyendo el término constante implícito
                ``+1``). Véase :py:class:`LFSR` para la convención de taps.
            seed (int): Estado inicial no nulo del LFSR.

        Lanza:
            ValueError: Propagado desde :py:class:`LFSR` si ``seed == 0``
                o si algún tap está fuera del rango ``[1, n_bits]``.
        """
        self._lfsr = LFSR(n_bits, taps, seed)

    def next_byte(self) -> int:
        """
        Retorna el siguiente byte del keystream consumiendo ocho bits de salida del LFSR.

        Llama a :py:meth:`LFSR.generate` para obtener ocho bits consecutivos y
        los ensambla en un entero usando orden de bits big-endian (MSB primero):
        el primer bit producido por el LFSR se convierte en el bit 7, y el
        octavo bit en el bit 0 del byte retornado.

        Retorna:
            int: Un entero en el rango cerrado [0, 255] que representa el
                 siguiente byte del keystream pseudoaleatorio.
        """
        byte_val = 0
        for bit in self._lfsr.generate(8):
            byte_val = (byte_val << 1) | bit
        return byte_val

    def generate_bytes(self, n: int) -> bytes:
        """
        Genera una secuencia contigua de ``n`` bytes del keystream.

        Llama a :py:meth:`next_byte` exactamente ``n`` veces en secuencia.
        Los bytes se producen en orden y se empaquetan en un objeto
        :class:`bytes`. El estado interno del LFSR avanza ``8 * n`` pasos.

        Args:
            n (int): Número de bytes del keystream a producir.
                     Cero es válido y retorna un objeto :class:`bytes` vacío.

        Retorna:
            bytes: Un objeto :class:`bytes` de longitud ``n`` que contiene
                   el keystream.
        """
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

    Retorna:
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
    """
    Retorna una sugerencia de polinomio primitivo legible para un grado dado.

    Busca ``n_bits`` en una tabla de referencia estática de polinomios
    primitivos conocidos sobre GF(2). La tabla cubre los tamaños de registro
    más comunes (de 2 a 16 bits).

    Args:
        n_bits (int): Grado del polinomio de retroalimentación / número de
                      etapas del registro.

    Retorna:
        str: Cadena descriptiva de la forma ``"taps=[…] → x^n+…+1"`` para
             los grados conocidos. Para grados no presentes en la tabla,
             retorna una cadena genérica que indica al llamador que consulte
             una referencia externa.

    Nota:
        Esta es una función auxiliar privada destinada exclusivamente al uso
        por :py:func:`require_primitive`. La tabla es un subconjunto estático
        de la lista completa de polinomios primitivos sobre GF(2); para grados
        no listados debe consultarse una fuente externa autorizada.
    """
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

        Retorna:
            bytes: Texto cifrado.

        Lanza:
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

        Retorna:
            str: Texto descifrado.

        Lanza:
            ValueError: Si el polinomio no es primitivo.
        """
        require_primitive(self.n_bits, self.taps)
        return self._xor_bytes(ciphertext, self._fresh_keystream(len(ciphertext))).decode(encoding)
