import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# 假设您的PEM格式公钥存储在一个名为public_key_pem的字符串中
public_key_pem = b"""-----BEGIN PUBLIC KEY-----
xxxx
-----END PUBLIC KEY-----"""

public_key = serialization.load_pem_public_key(
    public_key_pem,
    backend=default_backend()
)


# This should be the license key that you're cryptographically verifying
LICENSE_KEY = \
"""key/xxx.yyy"""

# Split license key to obtain signing data and signature, then parse data
# and decode base64url encoded values
signing_data, enc_sig = LICENSE_KEY.split(".")
signing_prefix, enc_key = signing_data.split("/")
key = base64.urlsafe_b64decode(enc_key)
print(f'key data: {key}')

signature = base64.urlsafe_b64decode(enc_sig)


hash_algorithm = hashes.SHA256()
message = bytes(signing_data, encoding='utf-8')
# 一步验证签名
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
          mgf=padding.MGF1(hash_algorithm),
          salt_length=padding.PSS.MAX_LENGTH
        ),
        hash_algorithm
    )
    print("Signature is valid.")
except Exception as e:
    print("Signature is invalid:", e)
