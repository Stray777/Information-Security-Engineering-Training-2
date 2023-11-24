import string


class CaesarCipher:
    def __init__(self, key: int):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    def encrypt(self, text: str) -> str:
        """加密"""
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                if is_upper:
                    encrypted_char = chr((ord(char) + self.key - ord('A')) % 26 + ord('A'))
                else:
                    encrypted_char = chr((ord(char) + self.key - ord('a')) % 26 + ord('a'))
                result += encrypted_char
            else:
                result += char
        self.__cipher_text = result
        return result

    def decrypt(self, text: str) -> str:
        """解密"""
        self.key = -self.key
        self.__plain_text = self.encrypt(text)
        self.key = -self.key
        return self.__plain_text

    def get_ciphertext(self):
        """获取密文"""
        return self.__cipher_text

    def get_plaintext(self):
        """获取明文"""
        return self.__plain_text


class KeywordCipher:
    def __init__(self, key: str):
        self.key = key
        self.__plain_text = ""
        self.__cipher_text = ""

    def generate_alphabet(self):
        # 生成关键字字母表
        keyword = self.key.upper()
        alphabet = list(string.ascii_uppercase)
        keyword_set = set(keyword)
        keyword_alphabet = [char for char in keyword + ''.join(alphabet) if char not in keyword_set]
        return keyword_alphabet

    def encrypt(self, plaintext: str) -> str:
        # 生成关键字字母表
        keyword_alphabet = self.generate_alphabet()

        # 加密
        ciphertext = ''
        for char in plaintext.upper():
            if char in string.ascii_uppercase:
                index = string.ascii_uppercase.index(char)
                ciphertext += keyword_alphabet[index]
            else:
                ciphertext += char
        self.__cipher_text = ciphertext

        return self.__cipher_text

    def decrypt(self, ciphertext: str) -> str:
        # 生成关键字字母表
        keyword_alphabet = self.generate_alphabet()

        # 解密
        plaintext = ''
        for char in ciphertext.upper():
            if char in string.ascii_uppercase:
                try:
                    index = keyword_alphabet.index(char)
                    plaintext += string.ascii_uppercase[index]
                except ValueError:
                    # 如果 char 不在关键字字母表中，直接添加到明文中
                    plaintext += char
            else:
                plaintext += char
        self.__plain_text = plaintext

        return self.__plain_text

    def get_plaintext(self) -> str:
        return self.__plain_text

    def get_ciphertext(self) -> str:
        return self.__cipher_text
