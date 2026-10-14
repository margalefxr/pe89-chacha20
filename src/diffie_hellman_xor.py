"""
RA2 - C2: Intercambio Diffie-Hellman + cifrado/descifrado con XOR
Autor: Xavier Margalef Riestra

La introduccion de la PE 89.1 evalua el RA2 con "la ejecucion de un
intercambio Diffie-Hellman, la obtencion de una clave compartida y su
utilizacion para cifrar y descifrar un mensaje mediante XOR".

Enfoque MSA: solo libreria estandar de Python (pow, secrets, hashlib).
Sin dependencias nuevas = sin superficie extra de cadena de suministro.

Flujo:
  1. Alice y Bob acuerdan p y g publicos (grupo MODP de 2048 bits, RFC 3526).
  2. Cada uno genera un secreto privado (a, b) con 'secrets' (CSPRNG).
  3. Intercambian sus valores publicos A = g^a mod p, B = g^b mod p.
  4. Cada uno calcula el mismo secreto compartido: s = B^a = A^b mod p.
  5. Del secreto se deriva un keystream del tamano del mensaje (SHAKE-256).
  6. Cifrado y descifrado: mensaje XOR keystream (la misma operacion).
"""

import hashlib
import secrets

# Grupo 14 de RFC 3526: primo seguro de 2048 bits, generador g = 2.
# Se usa un grupo estandarizado en vez de uno "inventado": evita primos debiles.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2


def generar_par_claves() -> tuple[int, int]:
    """Devuelve (privada, publica). La privada nunca sale del equipo."""
    privada = secrets.randbelow(P - 3) + 2          # rango [2, p-2]
    publica = pow(G, privada, P)                    # g^privada mod p
    return privada, publica


def validar_publica(publica: int) -> None:
    """Rechaza valores publicos triviales (1, p-1...) que fuerzan un secreto predecible."""
    if not 2 <= publica <= P - 2:
        raise ValueError("Valor publico fuera de rango: posible manipulacion")


def calcular_secreto(privada_propia: int, publica_ajena: int) -> int:
    """s = publica_ajena ^ privada_propia mod p."""
    validar_publica(publica_ajena)
    return pow(publica_ajena, privada_propia, P)


def derivar_keystream(secreto: int, longitud: int) -> bytes:
    """
    Convierte el secreto (un numero de 2048 bits) en tantos bytes como mida el mensaje.

    Se usa SHAKE-256 (funcion de salida extensible) en vez de repetir la clave:
    repetir una clave en XOR equivale a reutilizar keystream (el mismo fallo
    que reutilizar nonce en ChaCha20).
    """
    secreto_bytes = secreto.to_bytes((P.bit_length() + 7) // 8, "big")
    return hashlib.shake_256(secreto_bytes).digest(longitud)


def xor(datos: bytes, keystream: bytes) -> bytes:
    """Cifra o descifra: la XOR es su propia inversa."""
    return bytes(d ^ k for d, k in zip(datos, keystream, strict=True))


if __name__ == "__main__":
    print("=" * 70)
    print("RA2 - Diffie-Hellman + XOR")
    print("=" * 70)

    # 1-3. Cada parte genera sus claves y publica la parte publica
    a_priv, a_pub = generar_par_claves()   # Alice
    b_priv, b_pub = generar_par_claves()   # Bob
    print(f"Parametros publicos : p = MODP 2048 bits (RFC 3526), g = {G}")
    print(f"Publica de Alice (A): {hex(a_pub)[:34]}...")
    print(f"Publica de Bob   (B): {hex(b_pub)[:34]}...")

    # 4. Cada uno calcula el secreto con su privada y la publica del otro
    s_alice = calcular_secreto(a_priv, b_pub)
    s_bob = calcular_secreto(b_priv, a_pub)
    print(f"Secreto Alice == secreto Bob: {s_alice == s_bob}")
    if s_alice != s_bob:
        raise SystemExit("ERROR: los secretos no coinciden")

    # 5-6. Alice cifra, Bob descifra
    mensaje = "Este es un mensaje secreto que quiero cifrar".encode("utf-8")
    ks_alice = derivar_keystream(s_alice, len(mensaje))
    cifrado = xor(mensaje, ks_alice)
    print(f"Mensaje             : {mensaje.decode()}")
    print(f"Cifrado XOR (hex)   : {cifrado.hex()}")

    ks_bob = derivar_keystream(s_bob, len(cifrado))
    descifrado = xor(cifrado, ks_bob)
    print(f"Descifrado por Bob  : {descifrado.decode()}")
    if descifrado != mensaje:
        raise SystemExit("ERROR: el descifrado no devuelve el mensaje original")
    print("Verificacion        : OK")
    print("\nNota: los valores cambian en cada ejecucion (claves privadas aleatorias).")
