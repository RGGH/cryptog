import streamlit as st
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key



def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)

    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_pem)


def create_signature(private_key_path, data):
    with open(private_key_path, "rb") as key_file:
        private_pem = key_file.read()

    private_key = serialization.load_pem_private_key(private_pem, password=None)

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(public_key_path, data, signature):
    with open(public_key_path, "rb") as key_file:
        public_pem = key_file.read()

    public_key = load_pem_public_key(public_pem)

    try:
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
 
# Streamlit app
st.title("Digital Signature Verification Demo")
st.header("Secure File Transfer")


from digital_signature_page import show_digital_signature_page


# Create a navigation menu in the sidebar
menu_selection = st.sidebar.selectbox("Navigation", ["Home", "Digital Signature Process"])

# Handle navigation selection
if menu_selection == "Home":
    # Display the home page
    st.header("")
    # Add your content for the home page

elif menu_selection == "Digital Signature Process":
    # Call the function to show the digital signature process page
    show_digital_signature_page()


# Generate Key Pair
st.subheader("1. Generate Key Pair")
if st.button("Generate Key Pair"):
    generate_key_pair()
    st.success("Key pair generated and saved to files.")

# Choose File to Sign
st.subheader("2. Choose File to Sign")
uploaded_file = st.file_uploader("Upload a file", type=["txt", "pdf"])

if uploaded_file is not None:
    file_contents = uploaded_file.read()
    st.success("File uploaded successfully.")

    # Calculate Hash
    st.subheader("3. Calculate Hash")
    file_hash = hashes.Hash(hashes.SHA256())
    file_hash.update(file_contents)
    file_hash_digest = file_hash.finalize()
    st.write("Original Hash:", file_hash_digest.hex())

    # Sign File
    st.subheader("4. Create Digital Signature")
    if st.button("Create Signature"):
        signature = create_signature("private_key.pem", file_hash_digest)
        st.success("Digital signature created.")
        st.write("Signature:", signature.hex())

# Verify Signature
st.subheader("5. Recipient Verifies Signature")
file_to_verify = st.file_uploader("Upload the file to verify", type=["txt", "pdf"])
signature_to_verify = st.text_input("Enter the digital signature to verify")
st.info("The digital signatures should match ")

if st.button("Verify Signature") and file_to_verify is not None and signature_to_verify:
    file_to_verify_contents = file_to_verify.read()

    file_to_verify_hash = hashes.Hash(hashes.SHA256())
    file_to_verify_hash.update(file_to_verify_contents)
    file_to_verify_hash_digest = file_to_verify_hash.finalize()

    is_valid = verify_signature("public_key.pem", file_to_verify_hash_digest, bytes.fromhex(signature_to_verify))
    if is_valid:
        st.success("Signature is valid. The file has not been tampered with.")
        st.subheader("5. Compare Hashes")
        st.write("Original Hash:", file_hash_digest.hex())
        st.write("Recipient's Hash:", file_to_verify_hash_digest.hex())
        if file_to_verify_hash_digest == file_hash_digest:
            st.success("Hashes match. The file is authentic.")
        else:
            st.error("Hashes do not match. The file may have been tampered with.")
    else:
        st.error("Signature is not valid. The file may have been tampered with.")

st.sidebar.markdown("---")

st.sidebar.markdown("The digital signature is basically a one-way hash (or message digest) \
                     of the original data that was encrypted with the signer's private key.")
# Summary of steps
st.sidebar.subheader("Steps:")
st.sidebar.markdown("1. The sender generates a key pair.")
st.sidebar.markdown("2. The sender chooses a text file and calculates its hash.")
st.sidebar.markdown("3. The sender creates a digital signature based on the calculated hash.")
st.sidebar.markdown("4. The recipient receives the file and the digital signature.")
st.sidebar.markdown("5. The recipient uses their public key to verify and remove the digital signature.")
st.sidebar.markdown("6. The recipient calculates the hash of their copy of the file.")
st.sidebar.markdown("7. The recipient compares the calculated hash with the signed hash to check for tampering.")


#
st.sidebar.markdown("---")
st.sidebar.markdown("[redandgreen.co.uk](https://redandgreen.co.uk)")
st.sidebar.markdown("[findthatbit.com](https://findthatbit.com)")
st.sidebar.markdown("[Digital Signatures](https://www.youtube.com/watch?v=Us_Og3JeXiI&t=1251s)")

