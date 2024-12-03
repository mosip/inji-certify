import os
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import base58

def pem_to_eddsa_multibase(pem_str, prefix='z'):
    """
    Convert PEM to EdDSA and then to multibase
    """
    try:
        # Load PEM public key
        public_key = serialization.load_pem_public_key(pem_str.encode())
        
        # Convert to EdDSA raw bytes
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Prepend multicodec prefix for Ed25519 (0xed01)
        multicodec_bytes = bytes.fromhex('ed01')
        final_bytes = multicodec_bytes + raw_bytes
        
        # Convert to base58btc with prefix
        return prefix + base58.b58encode(final_bytes).decode('utf-8')
    except Exception as e:
        print(f"Error converting to multibase: {str(e)}")
        raise

def multibase_to_eddsa_key(multibase_str):
    """
    Convert multibase back to EdDSA public key
    """
    try:
        # Remove prefix
        base58_str = multibase_str[1:]
        
        # Decode base58 to raw bytes
        decoded = base58.b58decode(base58_str)
        
        # Remove multicodec prefix (first 2 bytes)
        raw_bytes = decoded[2:]
        
        # Create EdDSA public key object
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as e:
        print(f"Error converting from multibase: {str(e)}")
        raise

def load_pem_file(file_path):
    """
    Load the PEM file containing the public key
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    with open(file_path, 'r') as pem_file:
        return pem_file.read()

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Convert a PEM public key to and from multibase encoding")
    parser.add_argument("pem_file", help="Path to the PEM file containing the public key")
    args = parser.parse_args()
    
    # Load the public key from the PEM file
    try:
        pem_str = load_pem_file(args.pem_file)
        print(f"Loaded PEM public key from: {args.pem_file}")
        
        # Convert to multibase
        multibase = pem_to_eddsa_multibase(pem_str)
        print("Multibase:", multibase)

        # Convert back and verify length
        recovered_key = multibase_to_eddsa_key(multibase)
        raw_bytes = recovered_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print("Raw key length:", len(raw_bytes))  # Should be 32 bytes
        print("Raw key hex:", raw_bytes.hex())

        # Verify the original key bytes
        original_key = serialization.load_pem_public_key(pem_str.encode())
        original_bytes = original_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print("Original key length:", len(original_bytes))  # Should be 32 bytes
        print("Original key hex:", original_bytes.hex())

        # Verify they match
        print("Keys match:", raw_bytes == original_bytes)
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
