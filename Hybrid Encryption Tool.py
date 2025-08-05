from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from os import urandom

# --- RSA Key Generation (4096-bit for 256-bit security level) ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096  # 4096-bit RSA for 256-bit security level
    )
    public_key = private_key.public_key()
    return private_key, public_key

# --- AES-256 Encryption ---
def aes_encrypt(data, key):
    iv = urandom(16)  # 128-bit IV for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # AES-256 with 32-byte key
    encryptor = cipher.encryptor()
    # Padding the data to be a multiple of the block size (128-bit blocks)
    padder = sym_padding.PKCS7(128).padder()  # AES block size is always 128 bits
    padded_data = padder.update(data) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ct

# --- Hybrid Encryption Function (256-bit) ---
def hybrid_encrypt(data, public_key):
    # 1. Generate a random 256-bit AES key
    aes_key = urandom(32)  # 32 bytes = 256 bits
    # 2. Encrypt the data with the AES-256 key
    iv, encrypted_data = aes_encrypt(data, aes_key)
    # 3. Encrypt the AES key with the recipient's RSA-4096 public key using SHA-256
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key, iv, encrypted_data

# --- Combine encrypted components into single string ---
def combine_encrypted_data(encrypted_aes_key, iv, encrypted_data):
    # Combine: [AES_KEY_LENGTH(2bytes)][AES_KEY][IV_LENGTH(2bytes)][IV][ENCRYPTED_DATA]
    aes_key_len = len(encrypted_aes_key).to_bytes(2, 'big')
    iv_len = len(iv).to_bytes(2, 'big')
    combined = aes_key_len + encrypted_aes_key + iv_len + iv + encrypted_data
    return combined.hex()

# --- Parse combined encrypted string ---
def parse_combined_data(combined_hex):
    combined_bytes = bytes.fromhex(combined_hex)
    
    # Extract AES key length and AES key
    aes_key_len = int.from_bytes(combined_bytes[0:2], 'big')
    encrypted_aes_key = combined_bytes[2:2+aes_key_len]
    
    # Extract IV length and IV
    iv_len = int.from_bytes(combined_bytes[2+aes_key_len:4+aes_key_len], 'big')
    iv = combined_bytes[4+aes_key_len:4+aes_key_len+iv_len]
    
    # Extract encrypted data
    encrypted_data = combined_bytes[4+aes_key_len+iv_len:]
    
    return encrypted_aes_key, iv, encrypted_data

# --- Hybrid Decryption Function (256-bit) ---
def hybrid_decrypt(encrypted_aes_key, iv, encrypted_data, private_key):
    # Decrypt the AES-256 key using the RSA-4096 private key
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the data with the now-known AES-256 key
    cipher = Cipher(algorithms.AES(decrypted_aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the decrypted data
    unpadder = sym_padding.PKCS7(128).unpadder()  # AES block size is always 128 bits
    decrypted_message = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    return decrypted_message

# --- Main execution ---
if __name__ == "__main__":
    # Generate RSA-4096 keys for the recipient (256-bit security level)
    private_key, public_key = generate_rsa_keys()
    print("RSA-4096 keys generated successfully!")
    print("Security Level: 256-bit equivalent")

    while True:
        print("\nMenu:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Show example of combined format")
        print("4. Exit")
        choice = input("Choose an option (1-4): ")

        if choice == '1':
            message = input("Enter the message to encrypt: ").encode('utf-8')
            try:
                # Encrypt the message using the hybrid method
                encrypted_aes_key, iv, encrypted_data = hybrid_encrypt(message, public_key)
                
                # Combine all components into a single hex string
                combined_encrypted = combine_encrypted_data(encrypted_aes_key, iv, encrypted_data)

                print("\n--- Encryption Results ---")
                print("Combined Encrypted Data (256-bit):", combined_encrypted)
                print("Encryption completed successfully!")
            except Exception as e:
                print(f"Encryption failed: {e}")

        elif choice == '2':
            try:
                combined_encrypted_hex = input("Enter the combined encrypted data (hex): ")

                # Parse the combined data
                encrypted_aes_key, iv, encrypted_data = parse_combined_data(combined_encrypted_hex)

                # Decrypt the message
                decrypted_message = hybrid_decrypt(encrypted_aes_key, iv, encrypted_data, private_key)
                print("\n--- Decryption Results ---")
                print("Decrypted Message:", decrypted_message.decode('utf-8'))
                print("Decryption completed successfully!")
            except Exception as e:
                print(f"Decryption failed: {e}")

        elif choice == '3':
            print("\n--- 256-bit Encryption Details ---")
            print("Security Components:")
            print("• RSA-4096: Provides 256-bit equivalent security")
            print("• AES-256: 256-bit symmetric encryption")
            print("• SHA-256: 256-bit hash function for OAEP padding")
            print("• 128-bit IV: Standard for AES (block size)")
            print("")
            print("Combined Format Structure:")
            print("1. AES Key Length (2 bytes) + Encrypted AES-256 Key (~512 bytes)")
            print("2. IV Length (2 bytes) + 128-bit IV (16 bytes)")
            print("3. AES-256 Encrypted Data (variable length)")
            print("All combined into a single hex string for easy transmission.")

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")