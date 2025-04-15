from rsa import generate_keys, encrypt, decrypt

def main():
    public, private = generate_keys()
    message = "Hello, RSA!"
    print("Original message:", message)

    encrypted = encrypt(message, public)
    print("Encrypted:", encrypted)

    decrypted = decrypt(encrypted, private)
    print("Decrypted:", decrypted)

if __name__ == '__main__':
    main()
