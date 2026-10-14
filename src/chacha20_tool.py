"""
PE 89.1 - Fundamentos ChaCha20
Autor: Xavier Margalef Riestra

Herramienta minima de cifrado/descifrado con ChaCha20 (PyCryptodome).

Enfoque MSA: tres funciones pequenas, una responsabilidad cada una,
sin clases ni abstracciones que el ejercicio no necesita.

  - cifrar()               -> Parte 1
  - descifrar()            -> Parte 2
  - descifrar_desde()      -> Extra (resincronizar keystream con seek)

AVISO: la clave y el nonce estan escritos en el codigo porque los fija el
enunciado. En un entorno real NUNCA se hardcodea una clave (ver README,
seccion "Buenas practicas").
"""

from Crypto.Cipher import ChaCha20

# ---------------------------------------------------------------------------
# Parametros fijados por el enunciado
# ---------------------------------------------------------------------------
CLAVE = b'z\xe8~"\xcayW\x14g\x18+\x1c+\xf9\x80\x06P\x9ej\x888\xb4G\xdf\xe4\xc50,\x8dY\x80\x19'
NONCE = b'\xd6\x7f6\xc7\xe8i*\xa4'

TEXTO_PLANO_P1 = "Este es un mensaje secreto que quiero cifrar"

TEXTO_CIFRADO_P2 = (
    b'Ehq0\x83\xcb\x8fo\xab\xed\xd0S\x06\xcc\xbb\xecw\xe9\xec(\x1f\xc5E\xdb'
    b'\x88\x18`W\xc3yQn\xad3\xec.\x08\x92\x8d\x8e\xbb%\x8f\x1a\xa6\xc9=\x15\x0f5\xaa'
)

# Mensaje recibido al que le faltan los 8 primeros bytes
TEXTO_CIFRADO_EXTRA = (
    b"\xad\xe2\x9a[C\xca\xa9\xadn\xf9\xaa)\x13\xc2X\x9e\x89\x19`C\xc4n\x1em"
    b"\xf8?\xe7|\x0b\xd3\xdc\x8f\xacd\x85\x0c\xb8\xc3'\x1a\x12>"
)
BYTES_PERDIDOS = 8


# ---------------------------------------------------------------------------
# Funciones
# ---------------------------------------------------------------------------
def _validar_parametros(clave: bytes, nonce: bytes) -> None:
    """Falla pronto y con un mensaje claro si los parametros no son validos."""
    if len(clave) != 32:
        raise ValueError(f"La clave debe tener 32 bytes (256 bits); tiene {len(clave)}")
    if len(nonce) not in (8, 12, 24):
        raise ValueError(f"El nonce debe tener 8, 12 o 24 bytes; tiene {len(nonce)}")


def cifrar(texto_plano: bytes, clave: bytes, nonce: bytes) -> bytes:
    """Cifra con ChaCha20. Devuelve el texto cifrado en bytes."""
    _validar_parametros(clave, nonce)
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    return cipher.encrypt(texto_plano)


def descifrar(texto_cifrado: bytes, clave: bytes, nonce: bytes) -> bytes:
    """
    Descifra con ChaCha20.

    En un cifrado de flujo descifrar es la misma operacion que cifrar
    (texto XOR keystream). Se usa decrypt() igualmente por legibilidad.
    Importante: hay que crear un objeto cipher NUEVO. El de cifrado tiene el
    contador avanzado y PyCryptodome no permite usarlo para descifrar
    (lanza TypeError).
    """
    _validar_parametros(clave, nonce)
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    return cipher.decrypt(texto_cifrado)


def descifrar_desde(texto_cifrado: bytes, clave: bytes, nonce: bytes, posicion: int) -> bytes:
    """
    Descifra un fragmento que empieza en 'posicion' bytes del mensaje original.

    seek(posicion) adelanta el keystream exactamente esos bytes, de forma que
    el receptor vuelve a estar sincronizado con el emisor.
    """
    _validar_parametros(clave, nonce)
    cipher = ChaCha20.new(key=clave, nonce=nonce)
    cipher.seek(posicion)
    return cipher.decrypt(texto_cifrado)


# ---------------------------------------------------------------------------
# Ejecucion del ejercicio
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("PARTE 1 - Cifrado")
    print("=" * 70)
    cifrado = cifrar(TEXTO_PLANO_P1.encode("utf-8"), CLAVE, NONCE)
    print(f"Texto plano            : {TEXTO_PLANO_P1}")
    print(f"Tamano del nonce       : {len(NONCE)} bytes ({len(NONCE) * 8} bits)")
    print(f"Texto cifrado (bytes)  : {cifrado}")
    print(f"Texto cifrado (hex)    : {cifrado.hex()}")

    # Comprobacion de ida y vuelta: si no vuelve el original, algo esta mal
    assert descifrar(cifrado, CLAVE, NONCE).decode("utf-8") == TEXTO_PLANO_P1
    print("Verificacion ida/vuelta: OK")

    print()
    print("=" * 70)
    print("PARTE 2 - Descifrado")
    print("=" * 70)
    plano_p2 = descifrar(TEXTO_CIFRADO_P2, CLAVE, NONCE)
    print(f"Texto plano resultante : {plano_p2.decode('utf-8')}")

    print()
    print("=" * 70)
    print("EXTRA - Sincronizacion del keystream (seek)")
    print("=" * 70)
    sin_seek = descifrar(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE)
    print(f"Sin seek (desincronizado): {sin_seek}")
    con_seek = descifrar_desde(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE, BYTES_PERDIDOS)
    print(f"Con seek({BYTES_PERDIDOS})  (sincronizado): {con_seek.decode('utf-8')}")
    print(f"Nota: los {BYTES_PERDIDOS} primeros caracteres se han perdido y no son recuperables.")
