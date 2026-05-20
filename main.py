"""
main.py
───────
Corre todos los ejercicios de ejemplo en secuencia.
"""

from ejercicios import (
    ejercicio_1_tabla_de_estados,
    ejercicio_2_efecto_de_los_taps,
    ejercicio_3_verificacion_primitivo,
    ejercicio_4_cifrado_flujo,
    ejercicio_5_tabla_primitivos,
)


def main() -> None:
    print("╔" + "═" * 68 + "╗")
    print("║" + " LFSR Cipher — Cifrador de Flujo ".center(68) + "║")
    print("╚" + "═" * 68 + "╝")

    ejercicio_1_tabla_de_estados()
    ejercicio_2_efecto_de_los_taps()
    ejercicio_3_verificacion_primitivo()
    ejercicio_4_cifrado_flujo()
    ejercicio_5_tabla_primitivos()

    print("\n" + "═" * 68)
    print("  FIN")
    print("═" * 68 + "\n")


if __name__ == "__main__":
    main()
