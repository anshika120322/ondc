from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder

signing_key = SigningKey.generate()
signing_pub = signing_key.verify_key.encode(Base64Encoder).decode('utf-8')
encr_key = PrivateKey.generate()
encr_pub = encr_key.public_key.encode(Base64Encoder).decode('utf-8')

print('Valid ED25519 Keys:')
print('=' * 80)
print(f'signing_public_key: {signing_pub}')
print(f'encryption_public_key: {encr_pub}')
print('=' * 80)
