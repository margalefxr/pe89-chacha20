"""
Demostracion: por que NO se reutiliza (clave, nonce).

El propio enunciado cifra los mensajes de la Parte 1 y la Parte 2 con la
MISMA clave y el MISMO nonce. Este script demuestra el ataque que eso permite:
un atacante que solo ve los dos textos cifrados y conoce (o adivina) uno de
los textos planos recupera el otro SIN conocer la clave.

    C1 = P1 XOR K
    C2 = P2 XOR K          (mismo keystream K)
    C1 XOR C2 = P1 XOR P2  -> la clave desaparece
    P2 = C1 XOR C2 XOR P1
"""

from chacha20_tool import CLAVE, NONCE, TEXTO_PLANO_P1, TEXTO_CIFRADO_P2, cifrar


def xor(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte hasta la longitud del mas corto."""
    return bytes(x ^ y for x, y in zip(a, b))


if __name__ == "__main__":
    p1 = TEXTO_PLANO_P1.encode("utf-8")
    c1 = cifrar(p1, CLAVE, NONCE)  # lo que el atacante intercepta (1)
    c2 = TEXTO_CIFRADO_P2          # lo que el atacante intercepta (2)

    # 1) Fuga visible a simple vista: prefijo comun en los cifrados
    comunes = 0
    while comunes < min(len(c1), len(c2)) and c1[comunes] == c2[comunes]:
        comunes += 1
    print(f"Bytes iniciales identicos en C1 y C2: {comunes}")
    print("-> Un observador ya sabe que ambos mensajes empiezan igual.\n")

    # 2) Ataque de texto plano conocido, sin usar la clave
    recuperado = xor(xor(c1, c2), p1)
    print(f"P2 recuperado SIN la clave: {recuperado.decode('utf-8', errors='replace')}")
    print(f"(limitado a {len(recuperado)} bytes, la longitud del texto plano conocido)")
