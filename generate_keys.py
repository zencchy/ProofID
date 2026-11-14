from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# Generate the issuer's private key
private_key = Ed25519PrivateKey.generate()

# Derive the matching public key
public_key = private_key.public_key()

# Save the private key
with open("issuer_private.pem", "wb") as file:
    file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Save the public key
with open("issuer_public.pem", "wb") as file:
    file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("ProofID issuer keys generated successfully!")