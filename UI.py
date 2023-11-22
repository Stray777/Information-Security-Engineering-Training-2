import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
from Algorithm.CaesarCipher import CaesarCipher
from Algorithm.KeywordCipher import KeywordCipher


class UI:
    def __init__(self, root):
        self.root = root
        # 主界面标题
        self.root.title("加解密实践")
        # 设置窗口大小和居中
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"800x600+{(self.screen_width - 800) // 2}+{(self.screen_height - 600) // 2}")

        # 创建容器
        self.frame1 = tk.Frame(self.root, bd=2, relief=tk.GROOVE, padx=15, pady=15)
        self.frame2 = tk.Frame(self.root, bd=2, relief=tk.GROOVE, padx=15, pady=15)
        self.frame1.pack(side="left", padx=15)
        self.frame2.pack(side="right", padx=15)

        # 容器1
        self.label_encrypt = tk.Label(self.frame1, text="加密", font=("Helvetica", 20, "bold"))
        self.label_encrypt.grid(row=0, column=0, padx=10)
        self.label_plaintext = tk.Label(self.frame1, text="Plaintext")
        self.label_plaintext.grid(row=1, column=0)
        self.text_plaintext = tk.Text(self.frame1, height=10, width=30)
        self.text_plaintext.grid(row=1, column=1)
        self.label_file = tk.Label(self.frame1, text="File")
        self.label_file.grid(row=2, column=0)
        self.button_file = tk.Button(self.frame1, text="Select File", command=self.encrypt_open_file)
        self.button_file.grid(row=2, column=1, pady=10)
        self.label_key = tk.Label(self.frame1, text="KEY")
        self.label_key.grid(row=3, column=0)
        self.entry_key = tk.Entry(self.frame1)
        self.entry_key.grid(row=3, column=1)
        self.label_encrypt_algorithm = tk.Label(self.frame1, text="Encrypt Algorithm")
        self.label_encrypt_algorithm.grid(row=4, column=0, pady=10)
        self.options_algorithm = ["CaesarCipher", "KeywordCipher"]
        self.selected_algorithm = None
        self.combobox_algorithm = ttk.Combobox(self.frame1, values=self.options_algorithm, state="readonly")
        self.combobox_algorithm.bind("<<ComboboxSelected>>", self.algorithm_select)
        self.combobox_algorithm.set("Select an algorithm")
        self.combobox_algorithm.grid(row=4, column=1)
        self.button_algorithm = tk.Button(self.frame1, text="Encrypt", command=self.on_button_algorithm_click)
        self.button_algorithm.grid(row=5, column=1)

        # 容器2
        self.label_decrypt = tk.Label(self.frame2, text="解密", font=("Helvetica", 20, "bold"))
        self.label_decrypt.grid(row=0, column=0)
        self.label_ciphertext = tk.Label(self.frame2, text="Ciphertext")
        self.label_ciphertext.grid(row=1, column=0)
        self.text_ciphertext = tk.Text(self.frame2, height=10, width=30)
        self.text_ciphertext.grid(row=1, column=1)
        self.label_file2 = tk.Label(self.frame2, text="File")
        self.label_file2.grid(row=2, column=0)
        self.button_file2 = tk.Button(self.frame2, text="Select File", command=self.decrypt_open_file)
        self.button_file2.grid(row=2, column=1, pady=10)
        self.label_key2 = tk.Label(self.frame2, text="KEY")
        self.label_key2.grid(row=3, column=0)
        self.entry_key2 = tk.Entry(self.frame2)
        self.entry_key2.grid(row=3, column=1)
        self.label_decrypt_algorithm = tk.Label(self.frame2, text="Decrypt Algorithm")
        self.label_decrypt_algorithm.grid(row=4, column=0, pady=10)
        self.decrypt_options_algorithm = ["CaesarCipher", "KeywordCipher"]
        self.decrypt_selected_algorithm = None
        self.combobox_algorithm2 = ttk.Combobox(self.frame2, values=self.decrypt_options_algorithm, state="readonly")
        self.combobox_algorithm2.bind("<<ComboboxSelected>>", self.decrypt_algorithm_select)
        self.combobox_algorithm2.set("Select an algorithm")
        self.combobox_algorithm2.grid(row=4, column=1)
        self.button_algorithm2 = tk.Button(self.frame2, text="Decrypt", command=self.decrypt_on_button_algorithm_click)
        self.button_algorithm2.grid(row=5, column=1)

    def pop_up_window(self, title='', label_text='', content='', button_text='') -> None:
        """弹窗"""
        # 弹窗主窗口
        toplevel = tk.Toplevel(self.root)
        toplevel.title(title)
        toplevel.geometry(f"400x250+{(self.screen_width - 400) // 2}+{(self.screen_height - 250) // 2}")

        # 组件
        label = tk.Label(toplevel, text=label_text)
        label.pack(pady='5')
        text = tk.Text(toplevel, height=10, width=30)
        text.delete(1.0, tk.END)
        text.insert(tk.END, content)
        text.pack()
        button = tk.Button(toplevel, text=button_text, command=toplevel.destroy)
        button.pack(pady='5')

    def on_button_algorithm_click(self):
        """加密按钮"""
        key = self.entry_key.get()
        try:
            self.selected_algorithm(key)
        except TypeError as e:
            messagebox.showerror("错误", f"请选择具体算法后再点击\n{e}")

    def decrypt_on_button_algorithm_click(self):
        """解密按钮"""
        key = self.entry_key2.get()
        try:
            self.decrypt_selected_algorithm(key)
        except TypeError as e:
            messagebox.showerror("错误", f"请选择具体算法后再点击\n{e}")

    def encrypt_open_file(self):
        """打开文本文件"""
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as file:
                content = file.read()
                self.text_plaintext.delete(1.0, tk.END)
                self.text_plaintext.insert(tk.END, content)
        else:
            messagebox.showerror("打开文件错误", "文件类型需要为txt文件")

    def decrypt_open_file(self):
        """打开文本文件"""
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as file:
                content = file.read()
                self.text_ciphertext.delete(1.0, tk.END)
                self.text_ciphertext.insert(tk.END, content)
        else:
            messagebox.showerror("打开文件错误", "文件类型需要为txt文件")

    def algorithm_select(self, event):
        if event:
            selected_item = self.combobox_algorithm.get()
            algorithm_options = {
                "CaesarCipher": self.caesar_cipher_encrypt,
                "KeywordCipher": self.keyword_cipher_encrypt
            }
            self.selected_algorithm = algorithm_options.get(selected_item)

    def decrypt_algorithm_select(self, event):
        if event:
            selected_item = self.combobox_algorithm2.get()
            algorithm_options = {
                "CaesarCipher": self.caesar_cipher_decrypt,
                "KeywordCipher": self.keyword_cipher_decrypt
            }
            self.decrypt_selected_algorithm = algorithm_options.get(selected_item)

    def caesar_cipher_encrypt(self, key):
        """凯撒密码加密"""
        try:
            key = int(key)
            algorithm = CaesarCipher(key)
            algorithm.plain_text = self.text_plaintext.get("1.0", "end")
            algorithm.encrypt(algorithm.plain_text)
            self.pop_up_window("结果", "密文", algorithm.cipher_text, "关闭")
        except ValueError as e:
            messagebox.showerror("错误", f"CaesarCipher的key应为数字\n{e}")

    def caesar_cipher_decrypt(self, key):
        """凯撒密码解密"""
        try:
            key = int(key)
            algorithm = CaesarCipher(key)
            algorithm.cipher_text = self.text_ciphertext.get("1.0", "end")
            algorithm.decrypt(algorithm.cipher_text)
            self.pop_up_window("结果", "明文", algorithm.plain_text, "关闭")
        except ValueError as e:
            messagebox.showerror("错误", f"CaesarCipher的key应为数字\n{e}")

    def keyword_cipher_encrypt(self, key: str):
        """关键词密码加密"""
        algorithm = KeywordCipher(key)
        cipher_text = algorithm.keyword_cipher_encrypt(self.text_plaintext.get("1.0", "end"))
        self.pop_up_window("结果", "密文", cipher_text, "关闭")

    def keyword_cipher_decrypt(self, key: str):
        """关键词密码解密"""
        algorithm = KeywordCipher(key)
        plain_text = algorithm.keyword_cipher_decrypt(self.text_ciphertext.get("1.0", "end"))
        self.pop_up_window("结果", "明文", plain_text, "关闭")
