"""
api.py
──────
Backend FastAPI — expone lfsr_core.py como API REST y sirve index.html.

Arrancar:  uvicorn api:app --reload
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List

from lfsr_core import LFSR, check_primitive, LFSRPseudorandomGenerator

app = FastAPI(title="LFSR Cipher")


# ── Conversión entre array JS (MSB-first) y entero Python ────────────────────

def arr_to_int(arr: List[int]) -> int:
    return int("".join(map(str, arr)), 2) if arr else 0

def int_to_arr(val: int, n: int) -> List[int]:
    return [int(b) for b in format(val, f"0{n}b")]

def bytes_to_bits(data: bytes) -> List[int]:
    return [(byte >> k) & 1 for byte in data for k in range(7, -1, -1)]


# ── Esquemas Pydantic ─────────────────────────────────────────────────────────

class PrimitiveReq(BaseModel):
    n_bits: int
    taps: List[int]

class StepReq(BaseModel):
    state: List[int]   # array MSB-first, misma convención que el JS
    taps: List[int]

class EncryptReq(BaseModel):
    plaintext: str
    seed: List[int]    # array MSB-first
    taps: List[int]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/api/check-primitive")
def api_check_primitive(req: PrimitiveReq):
    """Equivale a lfsr_core.check_primitive()."""
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
    Equivale a LFSR.step() — un ciclo del registro.

    Recibe el estado actual como array MSB-first, aplica un paso usando
    la lógica de lfsr_core.LFSR y devuelve el nuevo estado, el bit de
    salida y el bit de retroalimentación.
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
    Equivale a LFSRStreamCipher.encrypt() + decrypt().

    Usa LFSRPseudorandomGenerator directamente para evitar la validación
    de primitivo (ya la hace el frontend antes de llamar este endpoint).
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
    return FileResponse("index.html")
