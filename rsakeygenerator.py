from Crypto.PublicKey import RSA

# Generate a 2048-bit RSA key pair
rsa_key = RSA.generate(2048)

# Export and save the private key
with open("recipient_private_key.pem", "wb") as f:
    f.write(rsa_key.export_key())

# Export and save the public key
with open("recipient_public_key.pem", "wb") as f:
    f.write(rsa_key.publickey().export_key())

print("RSA key pair generated and saved as 'recipient_private_key.pem' and 'recipient_public_key.pem'")