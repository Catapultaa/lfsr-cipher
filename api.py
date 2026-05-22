"""
api.py
──────
Backend FastAPI que expone :mod:`lfsr_core` como API REST y sirve el
frontend de una sola página (``index.html``).

Arquitectura
────────────
Toda la lógica criptográfica se delega a :mod:`lfsr_core`. Este módulo es
responsable únicamente del transporte HTTP, la validación de entradas mediante
Pydantic y la serialización de resultados a JSON.

Convención de representación de estado
────────────────────────────────────────
El frontend JavaScript representa el estado del registro como un arreglo de
enteros con el bit más significativo primero (ej.: el estado de 4 bits
0b1011 se envía como ``[1, 0, 1, 1]``). Las funciones auxiliares
:func:`arr_to_int` e :func:`int_to_arr` traducen entre esta representación
y el :class:`int` de Python utilizado por :mod:`lfsr_core`.

Endpoints
─────────
* ``POST /api/check-primitive`` — verificación de primitividad del polinomio.
* ``POST /api/step``            — un ciclo de reloj del LFSR.
* ``POST /api/encrypt``         — cifrado XOR completo + descifrado con arreglos de bits.
* ``GET  /``                    — sirve ``index.html``.

Uso
───
    uvicorn api:app --reload
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List

from lfsr_core import LFSR, check_primitive, LFSRPseudorandomGenerator

app = FastAPI(title="LFSR Cipher")


# ── Conversión entre array JS (MSB-first) y entero Python ────────────────────

def arr_to_int(arr: List[int]) -> int:
    """
    Convierte un arreglo binario con MSB primero a un entero de Python.

    Args:
        arr (List[int]): Lista ordenada de bits donde ``arr[0]`` es el bit
            más significativo. Se espera que cada elemento sea 0 o 1.

    Retorna:
        int: El entero cuya representación binaria es igual a la concatenación
             de los elementos de ``arr``. Retorna ``0`` para una lista vacía.

    Ejemplo:
        ``arr_to_int([1, 0, 1, 1])`` → ``11``  (binario ``1011``).
    """
    return int("".join(map(str, arr)), 2) if arr else 0

def int_to_arr(val: int, n: int) -> List[int]:
    """
    Convierte un entero de Python a un arreglo binario de ancho fijo con MSB primero.

    Args:
        val (int): Entero no negativo a convertir.
        n   (int): Longitud de salida deseada en bits. El resultado se rellena
                   con ceros por la izquierda si ``val`` tiene menos de ``n``
                   bits significativos.

    Retorna:
        List[int]: Lista de exactamente ``n`` enteros (cada uno 0 o 1) con
                   ``resultado[0]`` siendo el bit más significativo.

    Ejemplo:
        ``int_to_arr(11, 4)`` → ``[1, 0, 1, 1]``  (binario ``1011``).
    """
    return [int(b) for b in format(val, f"0{n}b")]

def bytes_to_bits(data: bytes) -> List[int]:
    """
    Convierte una cadena de bytes a una lista plana de bits en orden MSB primero.

    Cada byte se expande a 8 bits: el bit 7 (más significativo) se coloca
    primero y el bit 0 (menos significativo) al final. Los bits de bytes
    consecutivos se concatenan en el orden en que aparecen en ``data``.

    Args:
        data (bytes): Cadena de bytes de cualquier longitud.

    Retorna:
        List[int]: Lista de ``len(data) * 8`` enteros (cada uno 0 o 1).

    Ejemplo:
        ``bytes_to_bits(b'\\x48')``  (0x48 = 0b01001000)
        → ``[0, 1, 0, 0, 1, 0, 0, 0]``.
    """
    return [(byte >> k) & 1 for byte in data for k in range(7, -1, -1)]


# ── Esquemas Pydantic ─────────────────────────────────────────────────────────

class PrimitiveReq(BaseModel):
    """
    Esquema de solicitud para el endpoint ``/api/check-primitive``.

    Atributos:
        n_bits (int): Grado del polinomio / número de etapas del LFSR.
            Debe ser un entero positivo.
        taps (List[int]): Exponentes de los términos del polinomio de
            retroalimentación, excluyendo el término constante implícito
            ``+1``. Cada tap debe satisfacer ``1 ≤ tap ≤ n_bits``.
    """

    n_bits: int
    taps: List[int]

class StepReq(BaseModel):
    """
    Esquema de solicitud para el endpoint ``/api/step``.

    Atributos:
        state (List[int]): Estado actual del registro LFSR como arreglo
            binario con MSB primero. Su longitud define implícitamente
            ``n_bits``. Todos los elementos deben ser 0 o 1; el entero
            codificado debe ser distinto de cero.
        taps (List[int]): Exponentes de los términos del polinomio de
            retroalimentación. Cada tap debe satisfacer
            ``1 ≤ tap ≤ len(state)``.
    """

    state: List[int]   # array MSB-first, misma convención que el JS
    taps: List[int]

class EncryptReq(BaseModel):
    """
    Esquema de solicitud para el endpoint ``/api/encrypt``.

    Atributos:
        plaintext (str): Texto UTF-8 a cifrar.
        seed (List[int]): Estado inicial del LFSR como arreglo binario con
            MSB primero. Su longitud define implícitamente ``n_bits``. El
            entero codificado debe ser distinto de cero.
        taps (List[int]): Exponentes de los términos del polinomio de
            retroalimentación. Cada tap debe satisfacer
            ``1 ≤ tap ≤ len(seed)``.
    """

    plaintext: str
    seed: List[int]    # array MSB-first
    taps: List[int]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/api/check-primitive")
def api_check_primitive(req: PrimitiveReq):
    """
    Verifica si un polinomio de retroalimentación es primitivo sobre GF(2).

    Delega a :py:func:`lfsr_core.check_primitive`, que ejecuta el LFSR con
    ``seed=1`` y mide el período real. Un polinomio es primitivo si y solo
    si el período es igual a 2^n_bits − 1.

    Args:
        req (PrimitiveReq): Cuerpo de solicitud validado que contiene
            ``n_bits`` y ``taps``.

    Retorna:
        dict: Objeto JSON con tres claves:

            * ``is_primitive`` (bool) — ``True`` cuando el período es máximo.
            * ``period`` (int)        — Período real medido T.
            * ``max_period`` (int)    — Máximo teórico 2^n_bits − 1.

    Lanza:
        HTTPException 400: Si :py:func:`lfsr_core.check_primitive` lanza
            :class:`ValueError` (ej.: un tap está fuera del rango válido).
    """
    try:
        is_prim, period = check_primitive(req.n_bits, req.taps)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "is_primitive": is_prim,
        "period":       period,
        "max_period":   (1 << req.n_bits) - 1,
    }


@app.post("/api/step")
def api_step(req: StepReq):
    """
    Avanza el LFSR exactamente un ciclo de reloj.

    Equivale a LFSR.step() — un ciclo del registro.

    Recibe el estado actual como array MSB-first, aplica un paso usando
    la lógica de lfsr_core.LFSR y devuelve el nuevo estado, el bit de
    salida y el bit de retroalimentación.

    Se construye una instancia nueva de :py:class:`lfsr_core.LFSR` a partir
    del estado suministrado en cada llamada; no se mantiene estado de sesión
    en el servidor.

    Args:
        req (StepReq): Cuerpo de solicitud validado que contiene ``state``
            (arreglo binario con MSB primero) y ``taps`` (exponentes del
            polinomio).

    Retorna:
        dict: Objeto JSON con tres claves:

            * ``new_state`` (List[int]) — Estado del registro tras el paso,
              como arreglo binario con MSB primero de la misma longitud que
              ``req.state``.
            * ``out_bit`` (int)         — Bit de salida emitido durante este
              paso (0 o 1).
            * ``fb`` (int)             — Bit de retroalimentación insertado
              en la posición MSB (0 o 1).

    Lanza:
        HTTPException 400: Si el entero de estado codificado es cero, o si
            :py:class:`lfsr_core.LFSR` lanza :class:`ValueError`.
    """
    n = len(req.state)
    state_int = arr_to_int(req.state)
    if state_int == 0:
        raise HTTPException(400, "Estado 0 inválido.")
    try:
        lfsr = LFSR(n, req.taps, state_int)
        out_bit = lfsr.step()
        fb = (lfsr.state >> (n - 1)) & 1   # nuevo MSB = retroalimentación
        return {
            "new_state": int_to_arr(lfsr.state, n),
            "out_bit":   out_bit,
            "fb":        fb,
        }
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/encrypt")
def api_encrypt(req: EncryptReq):
    """
    Cifra un texto plano y verifica el descifrado, retornando arreglos de bits paralelos.

    Equivale a LFSRStreamCipher.encrypt() + decrypt().

    Usa LFSRPseudorandomGenerator directamente para evitar la validación
    de primitivo (ya la hace el frontend antes de llamar este endpoint).

    Se crean dos instancias independientes de
    :py:class:`lfsr_core.LFSRPseudorandomGenerator` — una para cifrado y
    otra para descifrado — cada una con la misma semilla, de modo que
    producen el mismo keystream. La salida descifrada sirve como verificación
    de integridad de ida y vuelta visible en el frontend.

    Args:
        req (EncryptReq): Cuerpo de solicitud validado que contiene
            ``plaintext`` (texto UTF-8), ``seed`` (arreglo binario con MSB
            primero) y ``taps`` (exponentes del polinomio).

    Retorna:
        dict: Objeto JSON con cuatro arreglos de bits paralelos (cada uno
        ``List[int]`` de 0s y 1s, longitud = ``len(plaintext_utf8) * 8``):

            * ``plain_bits``   — Bytes del texto plano expandidos a bits.
            * ``keystream``    — Bytes del keystream LFSR expandidos a bits.
            * ``cipher_bits``  — Bytes del texto cifrado XOR expandidos a bits.
            * ``decoded_bits`` — Descifrado de ida y vuelta expandido a bits
              (debe ser igual a ``plain_bits``).

    Lanza:
        HTTPException 400: Si el entero de semilla codificado es cero, o si
            :py:class:`lfsr_core.LFSRPseudorandomGenerator` lanza
            :class:`ValueError`.
    """
    n_bits   = len(req.seed)
    seed_int = arr_to_int(req.seed)
    if seed_int == 0:
        raise HTTPException(400, "Semilla 0 inválida.")
    try:
        plain_bytes = req.plaintext.encode("utf-8")

        gen = LFSRPseudorandomGenerator(n_bits, req.taps, seed_int)
        ks  = gen.generate_bytes(len(plain_bytes))

        ciph = bytes(p ^ k for p, k in zip(plain_bytes, ks))

        gen2 = LFSRPseudorandomGenerator(n_bits, req.taps, seed_int)
        dec  = bytes(c ^ k for c, k in zip(ciph, gen2.generate_bytes(len(ciph))))

        return {
            "plain_bits":   bytes_to_bits(plain_bytes),
            "keystream":    bytes_to_bits(ks),
            "cipher_bits":  bytes_to_bits(ciph),
            "decoded_bits": bytes_to_bits(dec),
        }
    except ValueError as e:
        raise HTTPException(400, str(e))


# ── Servir frontend ───────────────────────────────────────────────────────────

@app.get("/")
def frontend():
    """
    Sirve el frontend de la aplicación de una sola página.

    Retorna el archivo ``index.html`` ubicado en el mismo directorio que
    este módulo. Toda la lógica del cifrado se ejecuta en el navegador
    mediante llamadas fetch a los endpoints anteriores; esta ruta
    simplemente entrega el paquete HTML/CSS/JS.

    Retorna:
        FileResponse: Respuesta HTTP 200 cuyo cuerpo contiene el contenido
            de ``index.html`` con tipo MIME ``text/html``.
    """
    return FileResponse("index.html")
