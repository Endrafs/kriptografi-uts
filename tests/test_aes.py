
import unittest
import os

from cryptography.exceptions import InvalidTag

from src.main import (
    generate_key,
    encrypt_message,
    decrypt_message
)


class TestAESGCM(unittest.TestCase):

    def setUp(self):
        self.key = generate_key()
        self.nonce = os.urandom(12)
        self.plaintext = "ILHAM FIRMANSYAH - UTS KRIPTOGRAFI"

        self.ciphertext, self.tag = encrypt_message(
            self.plaintext,
            self.key,
            self.nonce
        )

    def test_encryption_and_decryption(self):
        decrypted = decrypt_message(
            self.ciphertext,
            self.tag,
            self.key,
            self.nonce
        )

        self.assertEqual(decrypted, self.plaintext)

    def test_ciphertext_tampering(self):
        modified = bytearray(self.ciphertext)
        modified[0] ^= 1

        with self.assertRaises(InvalidTag):
            decrypt_message(
                bytes(modified),
                self.tag,
                self.key,
                self.nonce
            )

    def test_tag_tampering(self):
        modified_tag = bytearray(self.tag)
        modified_tag[0] ^= 1

        with self.assertRaises(InvalidTag):
            decrypt_message(
                self.ciphertext,
                bytes(modified_tag),
                self.key,
                self.nonce
            )

    # Untuk menambahkan pengujian untuk kunci yang salah dan nonce yang salah
    def test_wrong_key(self):
        wrong_key = bytes(
            [self.key[0] ^ 1]
        ) + self.key[1:]

        with self.assertRaises(InvalidTag):
            decrypt_message(
                self.ciphertext,
                self.tag,
                wrong_key,
                self.nonce
            )

    def test_wrong_nonce(self):
        wrong_nonce = bytes(
            [self.nonce[0] ^ 1]
        ) + self.nonce[1:]

        with self.assertRaises(InvalidTag):
            decrypt_message(
                self.ciphertext,
                self.tag,
                self.key,
                wrong_nonce
            )

if __name__ == "__main__":
    unittest.main()
