from cryptography.hazmat.primitives import serialization
import OpenSSL

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key




# Generate a private and public key pair
# 65537 = 0x10001 in hexadecimal representation
# used in the generation of an RSA key pair

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()



# serialize the keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the keys to files
with open("private_key.pem", "wb") as private_file:
    private_file.write(private_pem)

with open("public_key.pem", "wb") as public_file:
    public_file.write(public_pem)
    
    
    
def verify_signature(public_key_path, data, signature):
    # Load the public key from file
    with open(public_key_path, "rb") as key_file:
        public_pem = key_file.read()

    public_key = load_pem_public_key(public_pem)

    try:
        # Verify the signature
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# create signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def create_signature(private_key_path, data):
    # Load the private key from file
    with open(private_key_path, "rb") as key_file:
        private_pem = key_file.read()

    private_key = serialization.load_pem_private_key(private_pem, password=None)

    # Generate the signature
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

# Example usage
data_to_sign = b"Hello, this is the data to be signed."
signature = create_signature("private_key.pem", data_to_sign)

print(signature)


# Example usage
is_valid = verify_signature("public_key.pem", data_to_sign, signature)

print(is_valid)