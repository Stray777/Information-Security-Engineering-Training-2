import string
from sympy import totient
import math


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


class RSA:
    # 明文,写入即固定，其后加解密的结果都写入ciphertext
    __plaintext = "plaintext"
    # 密文
    __ciphertext = "ciphertext"
    # 以下为加密过程需要输入的数字，prime_p,prime_q为偶数，prime_p与prime_q相乘得到n，e与n互质。
    prime_p = 0
    prime_q = 0
    key_e = 0
    # 以下为解密过程需要输入的数字
    decrypt_key_n = 0
    decrypt_key_d = 0
    # 以下为加密完成后得到的两个密钥
    key_n = 0
    key_d = 0

    def __init__(self, keys):
        # 使用空格作为分隔符将字符串拆分为子字符串
        keys_as_strings = keys.split(";")
        if len(keys_as_strings) == 3:
            self.prime_p, self.prime_q, self.key_e = map(int, keys_as_strings)
        elif len(keys_as_strings) == 2:
            self.decrypt_key_d, self.decrypt_key_n = map(int, keys_as_strings)
        else:
            raise ValueError("ERROR:Value error")
        # 将子字符串转换为整数列表

    @staticmethod
    def _mod_inverse_(public_key_e, euler_n):  # 计算最小模反函数
        private_key_d = 1
        while 1:
            if (private_key_d * public_key_e - 1) % euler_n == 0:
                return private_key_d
            else:
                private_key_d += 1

    @staticmethod
    def _if_prime_(number):  # 判断数字是否为质数
        if number < 0:
            return 0
        counter = 0
        for i in range(1, number + 1):
            if number % i == 0:
                counter += 1
        if counter == 2:
            return 1
        else:
            return 0

    @staticmethod
    def _are_coprime_(euler_n, public_key_e):  # 判断两数是否互质
        return math.gcd(euler_n, public_key_e) == 1

    def _get_public_key_n_(self):  # 获取p，q，获取其乘积，即公钥n
        public_key_n = self.prime_p * self.prime_q
        self.key_n = public_key_n

    def _get_public_key_e_(self, public_key_n):  # 获取公钥e，并判断其是否与n的欧拉函数互质，参数为公钥n
        euler_n = totient(public_key_n)
        if self._are_coprime_(euler_n, self.key_e):  # 判断是否互质
            self.key_e = self.key_e
        else:
            raise ValueError("ERROR:This number is not coprime with the public key n")

    def get_plaintext(self):
        return self.__plaintext

    def get_ciphertext(self):
        return self.__ciphertext

    def _get_private_key_(self, euler_n):  # 获取私钥d，其为e关于n的欧拉函数的模反函数
        self.key_d = self._mod_inverse_(self.key_e, euler_n)

    def _encrypt_char_(self, plain_char):  # 加密单个字符
        plain_char_num = ord(plain_char)
        cipher_char_num = (plain_char_num ** self.key_e) % self.key_n
        return chr(cipher_char_num)

    def _decrypt_char_(self, cipher_char):  # 解密单个字符
        cipher_char_num = ord(cipher_char)
        plain_char_num = (cipher_char_num ** self.decrypt_key_d) % self.decrypt_key_n
        return chr(plain_char_num)

    def encrypt(self, plaintext):  # 加密字符串
        if self._if_prime_(self.prime_p) == 0 or self._if_prime_(
                self.prime_q) == 0 or self.prime_q <= 1 or self.prime_p <= 1 or self.key_e <= 1:  # 分别判断两数是否为质数
            raise ValueError("ERROR:Value error!")
        self._get_public_key_n_()
        if not self._are_coprime_(totient(self.key_n), self.key_e):
            raise ValueError("ERROR:Value error!")
        self._get_public_key_e_(self.key_n)
        self._get_private_key_(totient(self.key_n))
        ciphertext = ""
        for char in plaintext:
            ciphertext += self._encrypt_char_(char)
        self.__ciphertext = ciphertext
        return ciphertext

    def decrypt(self, ciphertext):  # 解密字符串
        plaintext = ""
        for char in ciphertext:
            if char == '\n':
                continue
            plaintext += self._decrypt_char_(char)
        self.__plaintext = plaintext
        return plaintext
