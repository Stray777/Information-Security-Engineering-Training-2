import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox


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
        self.button_file = tk.Button(self.frame1, text="Select File", command=self.open_file)
        self.button_file.grid(row=2, column=1, pady=10)

        # 容器2
        self.label_decrypt = tk.Label(self.frame2, text="解密", font=("Helvetica", 20, "bold"))
        self.label_decrypt.grid(row=0, column=0)

    def open_file(self):
        """打开文本文件"""
        filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as file:
                content = file.read()
                self.text_plaintext.delete(1.0, tk.END)
                self.text_plaintext.insert(tk.END, content)
        else:
            messagebox.showerror("打开文件错误", "文件类型需要为txt文件")
