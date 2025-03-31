import hashlib
import random
from math import gcd


def string_to_ascii(input_string):
  return " ".join(str(ord(char)) for char in input_string)  # Join with spaces


def sha256_hash(decimal):
  """Convert a decimal to its full SHA-256 hash representation as an integer."""
  decimal_bytes = str(decimal).encode()
  sha256 = hashlib.sha256(decimal_bytes).hexdigest()
  hash_int = int(sha256, 16)
  return hash_int


def is_prime(n):
  """Simple primality test."""
  if n <= 1:
    return False
  if n <= 3:
    return True
  if n % 2 == 0 or n % 3 == 0:
    return False
  i = 5
  while i * i <= n:
    if n % i == 0 or n % (i + 2) == 0:
      return False
    i += 6
  return True


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


def generate_keys():
  """Generate RSA public and private keys with medium-sized primes."""
  print("\n--- RSA Key Generation ---")

  # 1. Generate two prime numbers p and q
  # For demonstration, use fixed primes to ensure consistency
  print("Using predetermined prime p...")
  p = 1009  # Small prime for demonstration
  print(f"p = {p}")

  print("Using predetermined prime q...")
  q = 1013  # Small prime for demonstration
  print(f"q = {q}")

  # 2. Compute n = p * q
  n = p * q
  print(f"n = p * q = {n}")

  # 3. Compute phi(n) = (p-1) * (q-1)
  phi = (p - 1) * (q - 1)
  print(f"φ(n) = (p-1) * (q-1) = {phi}")

  # 4. Choose e such that 1 < e < phi and gcd(e, phi) = 1
  e = 65537  # Common choice
  # If e is too large for our small primes, find a smaller one
  if e >= phi:
    e = 17  # Smaller prime commonly used

  # Make sure e is coprime with phi
  while gcd(e, phi) != 1:
    e += 2
  print(f"e = {e}")

  # 5. Compute d such that d ≡ e^(-1) (mod phi)
  d = mod_inverse(e, phi)
  print(f"d = e^(-1) mod φ(n) = {d}")

  # Verify: (d * e) % phi = 1
  verification = (d * e) % phi
  print(f"Verification: (d * e) mod φ(n) = {verification} (should be 1)")

  # Public key: (n, e), Private key: (n, d)
  public_key = (n, e)
  private_key = (n, d)

  print("\nPublic key (n, e) generated: ", public_key)
  print("\nPrivate key (n, d) generated: ", private_key)

  return public_key, private_key


def sign_hash(hash_value, public_key):
  """Sign a hash using RSA: S = H^d mod n."""
  n, e = public_key

  # For demonstration, we'll use a smaller hash to fit within our small n
  # Take the hash modulo n
  small_hash = hash_value % n
  print(f"Original hash: {hash_value}")
  print(f"Hash reduced modulo n: {small_hash}")

  # Sign: S = H^d mod n
  signature = pow(small_hash, e, n)
  print(f"\n--- RSA Signing ---")
  print(f"Signing hash mod n = {small_hash}")
  print(
      f"Signature = (Hash mod n)^d mod n = {small_hash}^{e} mod {n} = {signature}")

  return signature, small_hash


def verify_signature(signature, hash_mod_n, private_key):
  """Verify a signature using RSA: H' = S^d mod n, then check if H' = H mod n."""
  n, d = private_key

  # Verify: H' = S^e mod n
  recovered_hash = pow(signature, d, n)
  print(f"\n--- RSA Verification ---")
  print(f"Signature = {signature}")
  print(
      f"Recovered hash = Signature^d mod n = {signature}^{d} mod {n} = {recovered_hash}")
  print(f"Original hash mod n = {hash_mod_n}")

  # Verify that the verification was successful
  if recovered_hash == hash_mod_n:
    print("\nSignature verification successful! The recovered hash matches the original hash mod n.")
  else:
    print("\nSignature verification failed! The recovered hash does not match the original hash mod n.")

  return recovered_hash


def main():
  # Set input string to "Yahya"
  input_string = "Yahya"
  print(f"Using input string: {input_string}")

  # Step 1: Convert string to decimal
  decimal = string_to_ascii(input_string)
  print(f"\nStep 1: String to Decimal\n{decimal}")

  # Step 2: Convert decimal to full SHA-256 hash
  hash_value = sha256_hash(decimal)
  print(f"\nStep 2: Decimal to full SHA-256 hash (as integer)\n{hash_value}")
  print(f"SHA-256 hash bit length: {hash_value.bit_length()} bits")

  # Generate RSA keys with appropriate size
  public_key, private_key = generate_keys()
  n, _ = public_key
  print(f"RSA modulus n bit length: {n.bit_length()} bits")

  # Step 3: Sign the hash value using RSA private key
  signature, hash_mod_n = sign_hash(hash_value, public_key)
  print(f"\nStep 3: Generated signature\n{signature}")

  # Step 4: Verify the signature using RSA public key
  recovered_hash = verify_signature(signature, hash_mod_n, private_key)

  # Display original string for reference
  print(f"\nOriginal string: {input_string}")
  if recovered_hash == hash_mod_n:
    print("The message was successfully signed and verified!")
  else:
    print("The message signing verification failed!")


if __name__ == "__main__":
  main()
