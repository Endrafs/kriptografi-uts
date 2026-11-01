
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# AES-256-GCM configuration
KEY_SIZE = 256
NONCE_SIZE = 12  # 96 bits
TAG_SIZE = 16    # 128 bits


def generate_key() -> bytes:
    """Generate a random AES-256 key."""
    return AESGCM.generate_key(bit_length=KEY_SIZE)


def encrypt_message(
    plaintext: str,
    key: bytes,
    nonce: bytes
) -> tuple[bytes, bytes]:
    """Encrypt plaintext and return ciphertext and authentication tag."""

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be exactly 12 bytes.")

    aesgcm = AESGCM(key)

    encrypted_data = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    # The library returns ciphertext followed by a 16-byte tag.
    ciphertext = encrypted_data[:-TAG_SIZE]
    authentication_tag = encrypted_data[-TAG_SIZE:]

    return ciphertext, authentication_tag


def decrypt_message(
    ciphertext: bytes,
    authentication_tag: bytes,
    key: bytes,
    nonce: bytes
) -> str:
    """Authenticate and decrypt ciphertext."""

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be exactly 12 bytes.")

    if len(authentication_tag) != TAG_SIZE:
        raise ValueError("Authentication tag must be 16 bytes.")

    aesgcm = AESGCM(key)

    encrypted_data = ciphertext + authentication_tag

    plaintext = aesgcm.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return plaintext.decode("utf-8")


def main():
    print("=" * 55)
    print("       AES-256-GCM ENCRYPTION & DECRYPTION")
    print("=" * 55)

    # Test plaintext (not confidential data)
    plaintext = "ILHAM FIRMANSYAH - UTS KRIPTOGRAFI"

    # Generate a new key and nonce for this encryption
    key = generate_key()
    nonce = os.urandom(NONCE_SIZE)

    print("\n[1] PLAINTEXT")
    print("Text :", plaintext)
    print("Bytes:", plaintext.encode("utf-8").hex())

    print("\n[2] KEY INFORMATION")
    print("Algorithm   : AES-256-GCM")
    print("Key size    :", len(key) * 8, "bits")
    print("Nonce size  :", len(nonce) * 8, "bits")
    print("Tag size    :", TAG_SIZE * 8, "bits")

    # Encryption
    ciphertext, tag = encrypt_message(
        plaintext,
        key,
        nonce
    )

    print("\n[3] ENCRYPTION RESULT")
    print("Nonce      :", nonce.hex().upper())
    print("Ciphertext :", ciphertext.hex().upper())
    print("Auth Tag   :", tag.hex().upper())

    # Decryption
    print("\n[4] DECRYPTION RESULT")

    try:
        decrypted_text = decrypt_message(
            ciphertext,
            tag,
            key,
            nonce
        )

        print("Decrypted  :", decrypted_text)

        # Verification
        print("\n[5] VERIFICATION")

        if decrypted_text == plaintext:
            print("Status     : SUCCESS")
            print("Verification: PLAINTEXT MATCH")
        else:
            print("Status     : FAILED")

    except InvalidTag:
        print("Status: Authentication failed!")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()
