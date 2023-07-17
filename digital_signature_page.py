import streamlit as st

def show_digital_signature_page():
    # Define the text content for the digital signature process page
    text_content = """
    # Digital Signature Process
    
    The digital signature process involves the following steps:
    
    1. The sender generates a key pair.
    2. The sender chooses a text file and calculates its hash.
    3. The sender creates a digital signature based on the calculated hash.
    4. The recipient receives the file and the digital signature.
    5. The recipient uses their public key to verify and remove the digital signature.
    6. The recipient calculates the hash of their copy of the file.
    7. The recipient compares the calculated hash with the signed hash to check for tampering.
    
    This process ensures the integrity and authenticity of the transferred file.
    """

    # # Display the digital signature process page
    # st.title("Digital Signature Process")
    st.markdown(text_content)
