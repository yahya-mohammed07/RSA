import hashlib
from primeGen import generateLargePrime


def string_to_ascii(input_string):
  return " ".join(str(ord(char)) for char in input_string)  # Join with spaces


def sha256_hash(decimal):
  """Convert a decimal to its SHA-256 hash representation as an integer."""
  decimal_bytes = str(decimal).encode()
  sha256 = hashlib.sha256(decimal_bytes).hexdigest()
  hash_int = int(sha256, 16)
  return hash_int


def extended_gcd(a, b):
  """Extended Euclidean Algorithm to find gcd and coefficients."""
  if a == 0:
    return b, 0, 1
  else:
    gcd, x, y = extended_gcd(b % a, a)
    return gcd, y - (b // a) * x, x


def mod_inverse(e, phi):
  """Calculate the modular multiplicative inverse of e modulo phi."""
  gcd, x, y = extended_gcd(e, phi)
  if gcd != 1:
    raise ValueError("Modular inverse does not exist")
  else:
    return x % phi


def generate_keys(key_size=2048):
  """Generate RSA public and private keys, showing the math."""
  print("\n--- RSA Key Generation ---")

  # 1. Generate two large prime numbers p and q
  print("Generating prime p...")
  p = generateLargePrime()
  print(f"p = {p}")

  print("Generating prime q...")
  q = generateLargePrime()
  print(f"q = {q}")

  # 2. Compute n = p * q
  n = p * q
  print(f"n = p * q = {n}")

  # 3. Compute phi(n) = (p-1) * (q-1)
  phi = (p - 1) * (q - 1)
  print(f"φ(n) = (p-1) * (q-1) = {phi}")

  # 4. Choose e such that 1 < e < phi and gcd(e, phi) = 1
  e = 65537  # Common choice for efficiency
  print(f"e = {e}")

  # 5. Compute d such that d ≡ e^(-1) (mod phi)
  d = mod_inverse(e, phi)
  print(f"d = e^(-1) mod φ(n) = {d}")

  # Verify: (d * e) % phi = 1
  verification = (d * e) % phi
  print(f"Verification: (d * e) mod φ(n) = {verification} (should be 1)")

  # Public key: (n, e), Private key: (n, d)
  public_key = (n, e)  # tuple
  private_key = (n, d)  # tuple

  print("\nPublic key (n, e) generated: ", public_key)
  print("\nPrivate key (n, d) generated: ", private_key)

  return public_key, private_key


def encrypt(message, public_key):
  """Encrypt a message using RSA: C = M^e mod n."""
  n, e = public_key

  # Check if message is smaller than n
  if message >= n:
    raise ValueError("Message is too large for the given key size")

  # Encrypt: C = M^e mod n
  encrypted = pow(message, e, n)
  print(f"\n--- RSA Encryption ---")
  print(f"M = {message}")
  print(f"C = M^e mod n = {message}^{e} mod {n} = {encrypted}")

  return encrypted


def decrypt(ciphertext, private_key):
  """Decrypt a message using RSA: M = C^d mod n."""
  n, d = private_key

  # Decrypt: M = C^d mod n
  decrypted = pow(ciphertext, d, n)
  print(f"\n--- RSA Decryption ---")
  print(f"C = {ciphertext}")
  print(f"M = C^d mod n = {ciphertext}^{d} mod {n} = {decrypted}")

  return decrypted


def main():
  # Get user input
  input_string = input("Enter a string to encrypt: ")

  # Step 1: Convert string to decimal
  decimal = string_to_ascii(input_string)
  print(f"\nStep 1: String to Decimal\n{decimal}")

  # Step 2: Convert decimal to SHA-256 hash
  hash_value = sha256_hash(decimal)
  print(f"\nStep 2: Decimal to SHA-256 hash (as integer)\n{hash_value}")

  # Generate RSA keys
  public_key, private_key = generate_keys(key_size=2048)

  # Step 3: Encrypt the hash value using RSA
  sig = encrypt(hash_value, public_key)
  print(f"\nStep 3: Encrypted hash\n{sig}")

  # Step 4: Decrypt the encrypted value
  decrypted = decrypt(sig, private_key)
  print(f"\nStep 4: Decrypted hash\n{decrypted}")

  # Verify that the decryption was successful
  if decrypted == hash_value:
    print("\nVerification successful! The decrypted value matches the original hash.")
  else:
    print("\nVerification failed! The decrypted value does not match the original hash.")

  # Display original string for reference
  print(
      f"\nOriginal string: {input_string} Thus the message was successfully singed!")


if __name__ == "__main__":
  main()
