import tkinter as tk
from tkinter import filedialog
from Encryptor import Encryptor  # Assuming the Encryptor class is in a separate file

class GuiApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption and Decryption")

        self.encryptor = Encryptor()
        self.folder_path = ""

        self.folder_label = tk.Label(root, text="Folder Directory:")
        self.folder_label.pack()

        self.folder_entry = tk.Entry(root, width=50)
        self.folder_entry.pack()

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_folder)
        self.browse_button.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_files)
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_files)
        
        self.encrypt_button.pack(side=tk.LEFT)
        self.decrypt_button.pack(side=tk.RIGHT)

    def browse_folder(self):
        self.folder_path = filedialog.askdirectory()
        self.folder_entry.delete(0, tk.END)
        self.folder_entry.insert(0, self.folder_path)

    def encrypt_files(self):
        if self.folder_path:
            self.encryptor.generate_key_pair()
            self.encryptor.encrypt_files_in_folder(self.folder_path)

    def decrypt_files(self):
        if self.folder_path:
            self.encryptor.decrypt_files_in_folder(self.folder_path)