# LFSR Cipher — Visualizador interactivo

Visualizador paso a paso de un cifrador de flujo basado en LFSR (Linear Feedback Shift Register). La lógica corre en Python y se expone al frontend mediante una API REST en FastAPI.

---

## Cómo correr

**Requisitos:** Python 3.8+

### 1. Instalar dependencias

```bash
pip install fastapi "uvicorn[standard]"
```

### 2. Arrancar el servidor

Desde la carpeta del proyecto:

```bash
uvicorn api:app --reload
```

### 3. Abrir en el navegador

```
http://localhost:8000
```

> El archivo `index.html` **no funciona abriéndolo directamente** como `file://` — necesita el servidor corriendo para llamar a la API.

---

## Estructura del proyecto

```
lfsr_cipher/
├── lfsr_core.py   # Lógica del LFSR (registro, generador, cifrador, verificación de primitivo)
├── api.py         # Backend FastAPI — expone lfsr_core.py como endpoints REST
├── index.html     # Frontend — visualizador interactivo
├── ejercicios.py  # Demostraciones en consola
└── main.py        # Ejecuta todos los ejercicios en secuencia
```

---

## Cómo funciona

### LFSR (Linear Feedback Shift Register)

Un LFSR es un registro de *n* celdas que en cada paso:

1. Emite el bit del extremo derecho como salida (keystream)
2. Desplaza todos los bits una posición a la derecha
3. Calcula el nuevo bit de entrada como el XOR de las celdas en las posiciones *tap*

La secuencia generada depende completamente de la **semilla** (estado inicial) y los **taps** (posiciones del polinomio generador).

### Polinomio primitivo

Para que el LFSR recorra todos los `2ⁿ − 1` estados posibles antes de repetirse, el polinomio definido por los taps debe ser **primitivo sobre GF(2)**. Si no lo es, el keystream se repite antes y el cifrado se debilita. El visualizador verifica esto automáticamente.

### Cifrado de flujo

```
cifrado:    C = P ⊕ K
descifrado: P = C ⊕ K
```

El keystream `K` se genera con el LFSR a partir de la semilla. La misma operación XOR cifra y descifra. La seguridad depende de que la semilla permanezca secreta.

> ⚠️ El LFSR simple es vulnerable al ataque de Berlekamp-Massey: con solo `2n` bits del keystream observados se puede reconstruir la clave completa. Este proyecto es de uso educativo.

---

## API

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/` | Sirve el frontend |
| `POST` | `/api/check-primitive` | Verifica si el polinomio es primitivo |
| `POST` | `/api/step` | Ejecuta un paso del LFSR |
| `POST` | `/api/encrypt` | Cifra un texto y devuelve los bits de cada etapa |

---

## Demostración en consola

Para correr los ejercicios de ejemplo sin el frontend:

```bash
python main.py
```

---

