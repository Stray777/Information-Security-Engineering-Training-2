from model import CaesarCipher, KeywordCipher


class Controller:
    def __init__(self):
        self.caesar_cipher = None
        self.keyword_cipher = None

    def set_caesar_key(self, key: int):
        self.caesar_cipher = CaesarCipher(key)

    def set_keyword_key(self, key: str):
        self.keyword_cipher = KeywordCipher(key)

    def encrypt_caesar(self, text: str) -> str:
        return self.caesar_cipher.encrypt(text)

    def encrypt_keyword(self, text: str) -> str:
        return self.keyword_cipher.encrypt(text)

    def decrypt_caesar(self, text: str) -> str:
        return
