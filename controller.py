from model import *
from tkinter import filedialog, messagebox
import tkinter as tk


class Controller:
    def __init__(self, view):
        self.view = view
        self.view.set_button_file1(self.open_file)
        self.view.set_button_file2(self.open_file)
        self.view.set_button_encrypt(self.encrypt_on_button_click)
        self.view.set_button_decrypt(self.decrypt_on_button_click)

    def encrypt_on_button_click(self):
        """加密按钮"""
        option = self.view.combobox_algorithm.get()
        key = self.view.entry_key1.get().strip('\n')
        if option == "Select an algorithm":
            messagebox.showerror("错误", "请选择具体算法后再点击")
        elif option == "CaesarCipher":
            try:
                key = int(key)
            except ValueError as e:
                messagebox.showerror("错误", f"CaesarCipher的key应为数字\n\n{e}")
                return None
            caesar_cipher = CaesarCipher(key)
            self.encrypt(caesar_cipher)
        elif option == "KeywordCipher":
            keyword_cipher = KeywordCipher(key)
            self.encrypt(keyword_cipher)
        elif option == "RSA":
            rsa = RSA(key)
            self.encrypt(rsa)
        elif option == "PlayfairCipher":
            playfair = PlayfairCipher(key)
            self.encrypt(playfair)
        elif option == "VigenereCipher":
            vigenere = VigenereCipher(key)
            self.encrypt(vigenere)
        elif option == "PermutationCipher":
            permutation = PermutationCipher(key)
            self.encrypt(permutation)
        elif option == "AutokeyCipher":
            autokey = AutokeyCipher(key)
            self.encrypt(autokey)
        elif option == "RC4":
            rc4 = RC4(key)
            self.encrypt(rc4)
        elif option == "ColumnPermutationCipher":
            column = ColumnPermutationCipher(key)
            self.encrypt(column)
        elif option == "DesCipher":
            des = DesCipher(key)
            self.encrypt(des)

    def decrypt_on_button_click(self):
        """解密按钮"""
        option = self.view.combobox_algorithm2.get()
        key = self.view.entry_key2.get().strip('\n')
        if option == "Select an algorithm":
            messagebox.showerror("错误", "请选择具体算法后再点击")
        elif option == "CaesarCipher":
            try:
                key = int(key)
            except ValueError as e:
                messagebox.showerror("错误", f"CaesarCipher的key应为数字\n\n{e}")
                return None
            caesar_cipher = CaesarCipher(key)
            self.decrypt(caesar_cipher)
        elif option == "KeywordCipher":
            keyword_cipher = KeywordCipher(key)
            self.decrypt(keyword_cipher)
        elif option == "RSA":
            rsa = RSA(key)
            self.decrypt(rsa)
        elif option == "PlayfairCipher":
            playfair = PlayfairCipher(key)
            self.decrypt(playfair)
        elif option == "VigenereCipher":
            vigenere = VigenereCipher(key)
            self.decrypt(vigenere)
        elif option == "PermutationCipher":
            permutation = PermutationCipher(key)
            self.decrypt(permutation)
        elif option == "AutokeyCipher":
            autokey = AutokeyCipher(key)
            self.decrypt(autokey)
        elif option == "RC4":
            rc4 = RC4(key)
            self.decrypt(rc4)
        elif option == "ColumnPermutationCipher":
            column = ColumnPermutationCipher(key)
            self.decrypt(column)
        elif option == "DesCipher":
            des = DesCipher(key)
            self.decrypt(des)

    def open_file(self, button_id: int):
        """打开文本文件"""
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as file:
                content = file.read()
                if button_id == 1:
                    self.view.text_plaintext.delete(1.0, tk.END)
                    self.view.text_plaintext.insert(tk.END, content)
                elif button_id == 2:
                    self.view.text_ciphertext.delete(1.0, tk.END)
                    self.view.text_ciphertext.insert(tk.END, content)

    def run_view(self):
        self.view.root.mainloop()

    def encrypt(self, algorithm):
        plain_text = self.view.text_plaintext.get("1.0", "end").strip('\n')
        cipher_text = algorithm.encrypt(plain_text)
        if isinstance(algorithm, RSA):
            d = algorithm.key_d
            n = algorithm.key_n
            self.view.pop_up_window("结果", "明文", f"密钥d:{d}\n密钥n:{n}\n密文:{cipher_text}", "关闭")
        else:
            self.view.pop_up_window("结果", "密文", cipher_text, "关闭")

    def decrypt(self, algorithm):
        cipher_text = self.view.text_ciphertext.get("1.0", "end").strip('\n')
        plain_text = algorithm.decrypt(cipher_text)
        self.view.pop_up_window("结果", "明文", plain_text, "关闭")
