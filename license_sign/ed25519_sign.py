import base64
import json
import ed25519


def gen_key_file():
    # 生成公钥和私钥对
    private_key, public_key = ed25519.create_keypair()

    # 将公钥和私钥转换为Base64编码，以便于存储和传输
    private_key_base64 = base64.b64encode(private_key.to_bytes()).decode('utf-8')
    public_key_base64 = base64.b64encode(public_key.to_bytes()).decode('utf-8')

    # 将Base64编码的公钥和私钥保存到文件中
    with open("private_key.txt", "w") as private_key_file:
        private_key_file.write(private_key_base64)

    with open("public_key.txt", "w") as public_key_file:
        public_key_file.write(public_key_base64)


class ED25519Signer(object):
    def __init__(self, private_key_bytes: bytes):
        self.private_key = ed25519.SigningKey(private_key_bytes)

    @staticmethod
    def prefix() -> str:
        return 'key'

    def sign(self, message: str):
        """签名
        """
        message_bytes = bytes(message, encoding='utf-8')
        enc_data_bytes = base64.urlsafe_b64encode(message_bytes)
        prefix_bytes = bytes(self.prefix(), encoding='utf-8')

        signature_bytes = self.private_key.sign(prefix_bytes + b'/' + enc_data_bytes)
        return (f'{self.prefix()}/{str(enc_data_bytes, encoding="utf-8")}'
                f'.{str(base64.urlsafe_b64encode(signature_bytes), encoding="utf-8")}')


class ED25519Verifier(object):
    def __init__(self, public_key_bytes: bytes):
        self.public_key = ed25519.VerifyingKey(public_key_bytes)

    def verify(self, license_key: str) -> bool:
        """
        """
        prefix_bytes, key_bytes, sig_bytes = self.parse_license(license_key)
        try:
            self.public_key.verify(sig_bytes, prefix_bytes+b'/'+base64.urlsafe_b64encode(key_bytes))
        except ed25519.BadSignatureError:
            return False
        else:
            return True

    @staticmethod
    def parse_license(license_key: str):
        signing_data, enc_sig = license_key.split(".")
        signing_prefix, enc_key = license_key.split("/")

        prefix = bytes(signing_prefix, encoding='utf-8')
        sig = base64.urlsafe_b64decode(enc_sig)
        key = base64.urlsafe_b64decode(enc_key)
        return prefix, key, sig


def read_key_file(file_path) -> bytes:
    # 从文件中读取Base64编码的公钥和私钥
    with open(file_path, "r") as key_file:
        key_base64 = key_file.read()

    # 将Base64编码的公钥和私钥转换回原始格式
    key_bytes = base64.b64decode(key_base64)
    return key_bytes


if __name__ == "__main__":
    # gen_key_file()

    private_key_bytes = read_key_file('private_key.txt')
    signer = ED25519Signer(private_key_bytes)
    data = {
        'user': 'sg'
    }
    message = json.dumps(data)

    license_key = signer.sign(message)
    print(license_key)

    public_key_bytes = read_key_file('public_key.txt')
    verifier = ED25519Verifier(public_key_bytes)
    print(verifier.verify(license_key))
