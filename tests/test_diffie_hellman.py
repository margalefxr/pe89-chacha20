"""Pruebas de la parte RA2 (Diffie-Hellman + XOR)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from diffie_hellman_xor import (  # noqa: E402
    P, calcular_secreto, derivar_keystream, generar_par_claves, xor,
)


class TestDiffieHellman(unittest.TestCase):

    def test_ambas_partes_obtienen_el_mismo_secreto(self):
        a_priv, a_pub = generar_par_claves()
        b_priv, b_pub = generar_par_claves()
        self.assertEqual(calcular_secreto(a_priv, b_pub), calcular_secreto(b_priv, a_pub))

    def test_cifrar_y_descifrar_xor(self):
        a_priv, a_pub = generar_par_claves()
        b_priv, b_pub = generar_par_claves()
        msg = "mensaje de prueba ñ".encode()
        cifrado = xor(msg, derivar_keystream(calcular_secreto(a_priv, b_pub), len(msg)))
        self.assertNotEqual(cifrado, msg)
        plano = xor(cifrado, derivar_keystream(calcular_secreto(b_priv, a_pub), len(cifrado)))
        self.assertEqual(plano, msg)

    def test_secreto_distinto_en_cada_intercambio(self):
        a1, _ = generar_par_claves()
        a2, _ = generar_par_claves()
        self.assertNotEqual(a1, a2)

    def test_rechaza_publica_trivial(self):
        a_priv, _ = generar_par_claves()
        for mala in (0, 1, P - 1, P):
            with self.assertRaises(ValueError):
                calcular_secreto(a_priv, mala)


if __name__ == "__main__":
    unittest.main()
