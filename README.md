# license check

## 签名

* RSA_2048_PKCS1_PSS_SIGN_V2

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend

# 生成RSA密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# 使用私钥对消息进行PSS签名
hash_algorithm = hashes.SHA256()
message = b"Hello, I am a message."
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hash_algorithm),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hash_algorithm
)
```


## keygen-sh signing data example

```
{
    "account": {
        "id": "756b9494-78a0-46df-bb17-5a897d36886c"
    },
    "product": {
        "id": "ff2779c0-e4a3-4eff-851a-5581ddd1ccef"
    },
    "policy": {
        "id": "39fe6179-5833-4b64-8989-b0b65e154999",
        "duration": 604800
    },
    "user": null,
    "license": {
        "id": "e811f938-a86a-407f-a001-b77e8d58e968",
        "created": "2023-06-25T07:36:03.707Z",
        "expiry": "2023-07-02T07:36:03.708Z"
    }
}
```