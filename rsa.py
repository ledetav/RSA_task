import random

def generate_primes(limit=10**6):
    sieve = [True] * (limit + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i*i : limit+1 : i] = [False] * len(range(i*i, limit+1, i))
    return [x for x, is_prime in enumerate(sieve) if is_prime]

PRIMES = generate_primes()

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys():
    p = random.choice(PRIMES)
    q = random.choice(PRIMES)
    while q == p:
        q = random.choice(PRIMES)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        for candidate in range(3, phi, 2):
            if gcd(candidate, phi) == 1:
                e = candidate
                break
    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt(msg, pubkey):
    e, n = pubkey
    return [pow(ord(char), e, n) for char in msg]

def decrypt(cipher, privkey):
    d, n = privkey
    return ''.join([chr(pow(char, d, n)) for char in cipher])
