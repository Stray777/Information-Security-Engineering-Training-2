import tkinter as tk
from tkinter import messagebox
from tkinter import ttk


class View:
    def __init__(self):
        self.root = tk.Tk()
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
        self.button_file1 = tk.Button(self.frame1, text="Select File")
        self.button_file1.grid(row=2, column=1, pady=10)
        self.label_key = tk.Label(self.frame1, text="KEY")
        self.label_key.grid(row=3, column=0)
        self.entry_key1 = tk.Entry(self.frame1)
        self.entry_key1.grid(row=3, column=1)
        self.label_encrypt_algorithm = tk.Label(self.frame1, text="Encrypt algorithm")
        self.label_encrypt_algorithm.grid(row=4, column=0, pady=10)
        self.encrypt_options = [
            "CaesarCipher",
            "KeywordCipher",
            "RSA",
            "PlayfairCipher",
            "VigenereCipher",
            "PermutationCipher",
            "ColumnPermutationCipher",
            "AutokeyCipher",
            "RC4",
        ]
        self.combobox_algorithm = ttk.Combobox(self.frame1, values=self.encrypt_options, state="readonly")
        self.combobox_algorithm.bind("<<ComboboxSelected>>", self.encrypt_options_tips)
        self.combobox_algorithm.set("Select an algorithm")
        self.combobox_algorithm.grid(row=4, column=1)
        self.button_encrypt = tk.Button(self.frame1, text="Encrypt")
        self.button_encrypt.grid(row=5, column=1)

        # 容器2
        self.label_decrypt = tk.Label(self.frame2, text="解密", font=("Helvetica", 20, "bold"))
        self.label_decrypt.grid(row=0, column=0)
        self.label_ciphertext = tk.Label(self.frame2, text="Ciphertext")
        self.label_ciphertext.grid(row=1, column=0)
        self.text_ciphertext = tk.Text(self.frame2, height=10, width=30)
        self.text_ciphertext.grid(row=1, column=1)
        self.label_file2 = tk.Label(self.frame2, text="File")
        self.label_file2.grid(row=2, column=0)
        self.button_file2 = tk.Button(self.frame2, text="Select File")
        self.button_file2.grid(row=2, column=1, pady=10)
        self.label_key2 = tk.Label(self.frame2, text="KEY")
        self.label_key2.grid(row=3, column=0)
        self.entry_key2 = tk.Entry(self.frame2)
        self.entry_key2.grid(row=3, column=1)
        self.label_decrypt_algorithm = tk.Label(self.frame2, text="Decrypt algorithm")
        self.label_decrypt_algorithm.grid(row=4, column=0, pady=10)
        self.decrypt_options = [
            "CaesarCipher",
            "KeywordCipher",
            "RSA",
            "PlayfairCipher",
            "VigenereCipher",
            "PermutationCipher",
            "ColumnPermutationCipher",
            "AutokeyCipher",
            "RC4"
        ]
        self.combobox_algorithm2 = ttk.Combobox(self.frame2, values=self.decrypt_options, state="readonly")
        self.combobox_algorithm2.bind("<<ComboboxSelected>>", self.decrypt_options_tips)
        self.combobox_algorithm2.set("Select an algorithm")
        self.combobox_algorithm2.grid(row=4, column=1)
        self.button_decrypt = tk.Button(self.frame2, text="Decrypt")
        self.button_decrypt.grid(row=5, column=1)

    def set_button_encrypt(self, command):
        self.button_encrypt.configure(command=command)

    def set_button_decrypt(self, command):
        self.button_decrypt.configure(command=command)

    def set_button_file1(self, command):
        self.button_file1.configure(command=lambda: command(1))

    def set_button_file2(self, command):
        self.button_file2.configure(command=lambda: command(2))

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

    def encrypt_options_tips(self, _=None):
        selected_item = self.combobox_algorithm.get()
        if selected_item == "RSA":
            messagebox.showinfo("RSA提醒", "每个值需要以分号( ; )隔开\nprime_p;prime_q;key_e\n如: 23;19;17")
        elif selected_item == "ColumnPermutationCipher":
            messagebox.showinfo("ColumnPermutationCipher提醒", "每个值需要以分号( ; )隔开\n如: 2;0;1")

    def decrypt_options_tips(self, _=None):
        selected_item = self.combobox_algorithm2.get()
        if selected_item == "RSA":
            messagebox.showinfo("RSA提醒", "每个值需要以分号( ; )隔开\nkey_d;key_n\n如: 233;437")
        elif selected_item == "ColumnPermutationCipher":
            messagebox.showinfo("ColumnPermutationCipher提醒", "每个值需要以分号( ; )隔开\n如: 2;0;1")
