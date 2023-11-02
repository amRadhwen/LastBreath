import tkinter as tk
from tkinter import filedialog
from Enctryptor import Encryptor

class GuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor")

        self.encryptor = Encryptor()
        
        self.folder_path = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Enter Folder Name:").pack()
        tk.Entry(self.root, textvariable=self.folder_path).pack()
        
        tk.Button(self.root, text="Encrypt", command=self.encrypt).pack()
        tk.Button(self.root, text="Decrypt", command=self.decrypt).pack()

    def encrypt(self):
        folder_path = self.folder_path.get()
        self.encryptor.generate_key_pair()
        self.encryptor.encrypt_files_in_folder(folder_path)

    def decrypt(self):
        folder_path = self.folder_path.get()
        self.encryptor.decrypt_files_in_folder(folder_path)
    
