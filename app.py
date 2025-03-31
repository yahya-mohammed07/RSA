import hashlib
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives import serialization


def string_to_decimal(input_string):
  return " ".join(str(ord(char)) for char in input_string)  # Join with spaces


def sha256_hash(decimal):
  """Convert a decimal to its SHA-256 hash representation as an integer."""
  # Convert decimal to bytes
  decimal_bytes = str(decimal).encode()
  # Calculate SHA-256 hash
  sha256 = hashlib.sha256(decimal_bytes).hexdigest()
  # Convert hash to an integer
  hash_int = int(sha256, 16)
  return hash_int


def generate_keys():
  """Generate RSA public and private keys."""
  private_key = rsa.generate_private_key(
      public_exponent=65537,  # e
      key_size=2048
  )
  public_key = private_key.public_key()
  return private_key, public_key


def encrypt_hash(hash_value, public_key):
  """Encrypt a hash value using RSA public key."""
  # Convert hash to bytes (ensure it's properly sized for encryption)
  hash_bytes = hash_value.to_bytes(
      (hash_value.bit_length() + 7) // 8, byteorder='big')

  # Encrypt using OAEP padding
  encrypted = public_key.encrypt(
      hash_bytes,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return encrypted


def decrypt_hash(encrypted, private_key):
  """Decrypt an encrypted value using RSA private key."""
  # Decrypt the message
  decrypted_bytes = private_key.decrypt(
      encrypted,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  # Convert back to integer
  decrypted = int.from_bytes(decrypted_bytes, byteorder='big')
  return decrypted


def main():
  # Get user input
  input_string = input("Enter a string to encrypt: ")

  # Step 1: Convert string to decimal
  decimal = string_to_decimal(input_string)
  print(f"\nStep 1: String to Decimal\n{decimal}")

  # Step 2: Convert decimal to SHA-256 hash
  hash_value = sha256_hash(decimal)
  print(f"\nStep 2: Decimal to SHA-256 hash (as integer)\n{hash_value}")

  # Generate RSA keys
  print("\nGenerating RSA keys...")
  private_key, public_key = generate_keys()

  pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  print(pem.decode('utf-8'))

  pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
  )
  print(pem.decode('utf-8'))

  # Step 3: Encrypt the hash value
  print("\nEncrypting hash...")
  encrypted = encrypt_hash(hash_value, public_key)
  print(f"\nStep 3: Encrypted hash (in bytes)\n{encrypted.hex()}")

  # Step 4: Decrypt the encrypted value
  print("\nDecrypting hash...")
  decrypted = decrypt_hash(encrypted, private_key)
  print(f"\nStep 4: Decrypted hash\n{decrypted}")

  # Verify that the decrypted value matches the original hash
  if decrypted == hash_value:
    print("\nVerification successful! The decrypted value matches the original hash.")
  else:
    print("\nVerification failed! The decrypted value does not match the original hash.")

  # Display original string for reference
  print(f"\nOriginal string: {input_string}")


if __name__ == "__main__":
  main()
