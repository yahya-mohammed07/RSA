import hashlib
from math import gcd


def string_to_ascii(input_string):
    ascii_values = [ord(char) for char in input_string]
    print(f"\n🔹 ASCII Values: {ascii_values}")
    return " ".join(str(x) for x in ascii_values)


def sha256_hash(decimal):
    decimal_bytes = str(decimal).encode()
    sha256 = hashlib.sha256(decimal_bytes).hexdigest()
    hash_int = int(sha256, 16)
    
    print(f"\n🔹 SHA-256 Hash (Hex): {sha256}")
    print(f"🔹 SHA-256 Hash (Decimal): {hash_int}")
    
    return hash_int


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    
    mod_inv = x % phi
    print(f"\n🔹 Modular Inverse of {e} mod {phi}: {mod_inv}")
    
    return mod_inv


def generate_keys():
    """Generate RSA public and private keys."""
    print("\n--- 🔑 RSA Key Generation ---")

    p = 1009  # Prime number
    q = 1013  # Another prime number
    print(f"🔹 Prime p: {p}")
    print(f"🔹 Prime q: {q}")

    n = p * q
    phi = (p - 1) * (q - 1)

    print(f"🔹 RSA Modulus (n = p * q): {n}")
    print(f"🔹 Euler's Totient (φ(n) = (p-1) * (q-1)): {phi}")

    e = 65537  # Commonly used public exponent
    if e >= phi:
        e = 17  # Fallback to a smaller prime
    while gcd(e, phi) != 1:
        e += 2

    print(f"🔹 Public Exponent (e): {e}")

    d = mod_inverse(e, phi)

    print(f"🔹 Private Exponent (d): {d}")

    print(f"\n✅ Public Key: (n={n}, e={e})")
    print(f"✅ Private Key: (n={n}, d={d})")

    return (n, e), (n, d)


def sign_hash(hash_value, private_key):
    """Sign a hash using the RSA private key: S = H^d mod n."""
    n, d = private_key
    small_hash = hash_value % n  # Ensure hash fits in modulus

    print(f"\n--- ✍️ Signing Hash ---")
    print(f"🔹 Original Hash: {hash_value}")
    print(f"🔹 Hash Reduced Modulo n: {small_hash}")

    signature = pow(small_hash, d, n)

    print(f"🔹 Signature (H^d mod n): {signature}")

    return signature, small_hash


def verify_signature(signature, hash_value, public_key):
    """Verify the signature using the RSA public key: H' = S^e mod n."""
    n, e = public_key
    recovered_hash = pow(signature, e, n)

    print(f"\n--- ✅ Signature Verification ---")
    print(f"🔹 Signature: {signature}")
    print(f"🔹 Recovered Hash (S^e mod n): {recovered_hash}")
    print(f"🔹 Original Hash Modulo n: {hash_value % n}")

    return recovered_hash == (hash_value % n)


def main():
    input_string = "Yahya"
    print(f"\n📝 Input String: {input_string}")

    decimal = string_to_ascii(input_string)
    hash_value = sha256_hash(decimal)

    public_key, private_key = generate_keys()

    # Sign the hash
    signature, hash_mod_n = sign_hash(hash_value, private_key)
    print(f"\n🔹 Final Signature: {signature}")

    # Verify the signature
    if verify_signature(signature, hash_value, public_key):
        print("\n✅ Signature verification successful! The message is authentic. 🎉")
    else:
        print("\n❌ Signature verification failed! 🚨")


if __name__ == "__main__":
    main()
