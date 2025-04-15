import unittest
from rsa import generate_keys, encrypt, decrypt, modinv, gcd, generate_primes

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.public, self.private = generate_keys()

    def test_single_character_encryption(self):
        char = "A"
        encrypted = encrypt(char, self.public)
        self.assertIsInstance(encrypted, list)
        self.assertEqual(len(encrypted), 1)
        self.assertNotEqual(encrypted[0], ord(char))

    def test_decrypt_known_cipher(self):
        msg = "B"
        encrypted = encrypt(msg, self.public)
        decrypted = decrypt(encrypted, self.private)
        self.assertEqual(decrypted, msg)

    def test_different_messages_produce_different_ciphers(self):
        encrypted1 = encrypt("hello", self.public)
        encrypted2 = encrypt("world", self.public)
        self.assertNotEqual(encrypted1, encrypted2)

    def test_same_message_different_keys(self):
        pub2, priv2 = generate_keys()
        msg = "abc"
        cipher1 = encrypt(msg, self.public)
        cipher2 = encrypt(msg, pub2)
        self.assertNotEqual(cipher1, cipher2)

    def test_modinv(self):
        self.assertEqual(modinv(3, 11), 4)
        self.assertEqual(modinv(10, 17), 12)

    def test_modinv_negative_result(self):
        self.assertEqual(modinv(7, 40), 23)

    def test_gcd_basic(self):
        self.assertEqual(gcd(54, 24), 6)

    def test_gcd_coprime(self):
        self.assertEqual(gcd(101, 10), 1)

    def test_generate_primes_output_type(self):
        primes = generate_primes(100)
        self.assertTrue(isinstance(primes, list))
        self.assertTrue(all(isinstance(p, int) for p in primes))

    def test_generate_primes_edge_cases(self):
        self.assertEqual(generate_primes(1), [])
        self.assertEqual(generate_primes(2), [2])

    def test_ciphertext_is_not_plaintext(self):
        msg = "rsa"
        encrypted = encrypt(msg, self.public)
        for i, ch in enumerate(msg):
            self.assertNotEqual(ord(ch), encrypted[i])

    def test_known_encrypt_decrypt_values(self):
        pub, priv = ((17, 3233), (2753, 3233))
        encrypted = [encrypt(c, pub)[0] for c in "HI"]
        self.assertEqual(encrypted, [3000, 1486])
        decrypted = ''.join([decrypt([c], priv) for c in encrypted])
        self.assertEqual(decrypted, "HI")


    def test_empty_string(self):
        encrypted = encrypt("", self.public)
        decrypted = decrypt(encrypted, self.private)
        self.assertEqual(decrypted, "")

    def test_special_characters(self):
        msg = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/"
        encrypted = encrypt(msg, self.public)
        decrypted = decrypt(encrypted, self.private)
        self.assertEqual(decrypted, msg)

    def test_unicode_characters(self):
        msg = "Привет мир"
        encrypted = encrypt(msg, self.public)
        decrypted = decrypt(encrypted, self.private)
        self.assertEqual(decrypted, msg)

    def test_large_message(self):
        msg = "A" * 100
        encrypted = encrypt(msg, self.public)
        decrypted = decrypt(encrypted, self.private)
        self.assertEqual(decrypted, msg)

    def test_key_generation_produces_different_keys(self):
        keys = set()
        for _ in range(10):
            pub, _ = generate_keys()
            keys.add(pub)
        self.assertGreater(len(keys), 1)

if __name__ == '__main__':
    unittest.main()
