"""
Pruebas minimas con unittest (libreria estandar: cero dependencias extra).

Ejecutar desde la raiz del repo:
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from chacha20_tool import (  # noqa: E402
    BYTES_PERDIDOS, CLAVE, NONCE, TEXTO_CIFRADO_EXTRA, TEXTO_CIFRADO_P2,
    TEXTO_PLANO_P1, cifrar, descifrar, descifrar_desde,
)

# Valor de referencia publicado en "Codigo P1" del enunciado
CIFRADO_ESPERADO_HEX = (
    "4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057"
    "c379516ead33ec2e08929f92b8778a0d"
)


class TestChaCha20(unittest.TestCase):

    def test_parte1_coincide_con_referencia(self):
        cifrado = cifrar(TEXTO_PLANO_P1.encode(), CLAVE, NONCE)
        self.assertEqual(cifrado.hex(), CIFRADO_ESPERADO_HEX)

    def test_ida_y_vuelta(self):
        msg = "prueba áéí ñ 123".encode()
        self.assertEqual(descifrar(cifrar(msg, CLAVE, NONCE), CLAVE, NONCE), msg)

    def test_parte2(self):
        plano = descifrar(TEXTO_CIFRADO_P2, CLAVE, NONCE).decode()
        self.assertEqual(plano, "Este es un mensaje secreto que quiero que descifres")

    def test_extra_seek(self):
        plano = descifrar_desde(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE, BYTES_PERDIDOS).decode()
        self.assertEqual(plano, "saje ha sufrido un error en la transmision")

    def test_extra_sin_seek_falla(self):
        with self.assertRaises(UnicodeDecodeError):
            descifrar(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE).decode()

    def test_nonce_invalido(self):
        with self.assertRaises(ValueError):
            cifrar(b"x", CLAVE, b"\x00" * 16)

    def test_clave_invalida(self):
        with self.assertRaises(ValueError):
            cifrar(b"x", b"\x00" * 16, NONCE)


if __name__ == "__main__":
    unittest.main()
