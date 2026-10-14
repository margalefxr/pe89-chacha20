"""
Pruebas con unittest (libreria estandar). Ejecutar: python -m unittest -v
"""

import unittest

from chacha20_tool import (
    BYTES_PERDIDOS, CLAVE, NONCE, TEXTO_CIFRADO_EXTRA, TEXTO_CIFRADO_P2,
    TEXTO_PLANO_P1, cifrar, descifrar, descifrar_desde, xor,
)
from diffie_hellman_xor import (
    P, calcular_secreto, derivar_keystream, generar_par_claves,
    xor as xor_estricto,
)

# Referencia publicada en "Codigo P1" del enunciado
CIFRADO_ESPERADO_HEX = (
    "4568713083cb8f6fabedd05306ccbbec77e9ec281fc545db88186057"
    "c379516ead33ec2e08929f92b8778a0d"
)


class TestChaCha20(unittest.TestCase):

    def test_parte1_coincide_con_referencia(self):
        self.assertEqual(cifrar(TEXTO_PLANO_P1.encode(), CLAVE, NONCE).hex(), CIFRADO_ESPERADO_HEX)

    def test_parte2(self):
        plano = descifrar(TEXTO_CIFRADO_P2, CLAVE, NONCE).decode()
        self.assertEqual(plano, "Este es un mensaje secreto que quiero que descifres")

    def test_extra_seek(self):
        plano = descifrar_desde(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE, BYTES_PERDIDOS).decode()
        self.assertEqual(plano, "saje ha sufrido un error en la transmision")

    def test_extra_sin_seek_falla(self):
        with self.assertRaises(UnicodeDecodeError):
            descifrar(TEXTO_CIFRADO_EXTRA, CLAVE, NONCE).decode()

    def test_nonce_16_bytes_rechazado(self):
        with self.assertRaises(ValueError):
            cifrar(b"x", CLAVE, b"\x00" * 16)

    def test_clave_invalida(self):
        with self.assertRaises(ValueError):
            cifrar(b"x", b"\x00" * 16, NONCE)

    def test_reutilizar_nonce_revela_p2(self):
        c1 = cifrar(TEXTO_PLANO_P1.encode(), CLAVE, NONCE)
        p2 = xor(xor(c1, TEXTO_CIFRADO_P2), TEXTO_PLANO_P1.encode())
        self.assertTrue(p2.startswith(b"Este es un mensaje secreto que quiero que de"))


class TestDiffieHellman(unittest.TestCase):

    def test_misma_clave_y_xor(self):
        a_priv, a_pub = generar_par_claves()
        b_priv, b_pub = generar_par_claves()
        s_a, s_b = calcular_secreto(a_priv, b_pub), calcular_secreto(b_priv, a_pub)
        self.assertEqual(s_a, s_b)
        msg = "mensaje de prueba".encode()
        cifrado = xor_estricto(msg, derivar_keystream(s_a, len(msg)))
        self.assertEqual(xor_estricto(cifrado, derivar_keystream(s_b, len(msg))), msg)

    def test_rechaza_publica_trivial(self):
        a_priv, _ = generar_par_claves()
        for mala in (0, 1, P - 1, P):
            with self.assertRaises(ValueError):
                calcular_secreto(a_priv, mala)


if __name__ == "__main__":
    unittest.main()
