from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
import base64
import os

# Load private key from old_private_key.pem
def load_private_key():
    with open('old_private_key.pem', 'rb') as f:
        private_key_data = f.read()
        private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
    return private_key

# Load public key from new_public_key.pem
def load_public_key():
    with open('new_public_key.pem', 'rb') as f:
        public_key_data = f.read()
        public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
    return public_key

# Helper method to decrypt a file with the given private key
def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = private_key.decrypt(
        base64.b64decode(encrypted_data),
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data

# Helper method to encrypt data with the given public key
def encrypt_data(data, public_key):
    encrypted_data = public_key.encrypt(
        data,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data

def main():
    # Load the private and public keys
    private_key = load_private_key()
    public_key = load_public_key()

    # Create new_user_profiles directory 
    os.makedirs('new_user_profiles', exist_ok=True)

    # Decrypt each file in user_profiles directory
    for file_name in os.listdir('user_profiles'):
        encrypted_file_path = os.path.join('user_profiles', file_name)
        decrypted_data = decrypt_file(encrypted_file_path, private_key)

        # Encrypt the decrypted data using the new public key
        encrypted_data = encrypt_data(decrypted_data, public_key)
        
        # Save encrypted data to new_user_profiles directory
        new_file_path = os.path.join('new_user_profiles', f'encrypted_{file_name}')
        with open(new_file_path, 'wb') as f:
            f.write(encrypted_data)

    print("Decryption and re-encryption completed successfully.")

if __name__ == "__main__":
    main()
