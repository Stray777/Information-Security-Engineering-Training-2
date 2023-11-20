class CaesarCipher:
    def __init__(self, shift: int):
        self.shift = shift

    def encrypt(self, text: str) -> str:
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                if is_upper:
                    encrypted_char = chr((ord(char) + self.shift - ord('A')) % 26 + ord('A'))
                else:
                    encrypted_char = chr((ord(char) + self.shift - ord('a')) % 26 + ord('a'))
                result += encrypted_char
            else:
                result += char
        return result

    def decrypt(self, text: str) -> str:
        self.shift = -self.shift
        return self.encrypt(text)

