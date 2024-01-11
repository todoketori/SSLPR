import os
import tkinter as tk
from tkinter import filedialog, messagebox, PanedWindow, Listbox, simpledialog
from cryptography.fernet import Fernet

class SecureApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure Encryption App")

        # Variables
        self.password = None
        self.is_encrypted = tk.BooleanVar()
        self.is_encrypted.set(False)
        self.encrypted_files = []

        # Menu
        menu_bar = tk.Menu(master)
        master.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Encrypt", command=self.encrypt_file)
        file_menu.add_command(label="Password Generator", command=self.generate_password)
        file_menu.add_command(label="Decrypt", command=self.enter_password)
        file_menu.add_command(label="Save to File", command=self.save_to_file)
        menu_bar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Admin Login", command=self.admin_login)
        settings_menu.add_command(label="Close App", command=self.close_app)
        settings_menu.add_command(label="Custom Settings", command=self.custom_settings)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)

        encrypted_files_button = tk.Button(master, text="Encrypted Files", command=self.show_encrypted_files)
        encrypted_files_button.pack()

        # Checkbutton
        check_button = tk.Checkbutton(master, text="Encrypted", variable=self.is_encrypted, state="disabled")
        check_button.pack()

        master.geometry("875x875")  # Set the initial size of the main frame

    def encrypt_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            if not self.password:
                messagebox.showwarning("Password Required", "Please generate a password first.")
                return

            with open(file_path, 'rb') as file:
                plaintext = file.read()

            cipher = Fernet(self.password)
            ciphertext = cipher.encrypt(plaintext)

            folder_path = filedialog.askdirectory(title="Select Folder to Save Encrypted File")
            if folder_path:
                encrypted_file_path = os.path.join(folder_path, f"encrypted_{os.path.basename(file_path)}")
                with open(encrypted_file_path, 'wb') as encrypted_file:
                    encrypted_file.write(ciphertext)

                self.is_encrypted.set(True)
                self.encrypted_files.append(encrypted_file_path)
                messagebox.showinfo("Encryption Successful", "File encrypted successfully.")

    def generate_password(self):
        self.password = Fernet.generate_key()
        messagebox.showinfo("Password Generated", "Password generated successfully.")

    def decrypt_file(self, file_path):
        if not self.password:
            messagebox.showwarning("Password Required", "Please generate a password first.")
            return

        with open(file_path, 'rb') as encrypted_file:
            ciphertext = encrypted_file.read()

        cipher = Fernet(self.password)
        try:
            decrypted_content = cipher.decrypt(ciphertext).decode('utf-8')
            self.is_encrypted.set(False)
            messagebox.showinfo("Decryption Successful", "File decrypted successfully.")

            decrypted_folder_path = os.path.join(os.path.dirname(file_path), "Decrypted")
            os.makedirs(decrypted_folder_path, exist_ok=True)
            decrypted_file_path = os.path.join(decrypted_folder_path, f"decrypted_{os.path.basename(file_path)}")
            with open(decrypted_file_path, 'w') as decrypted_file:
                decrypted_file.write(decrypted_content)

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Error: {e}")

    def enter_password(self):
        if not self.is_encrypted.get():
            messagebox.showinfo("Not Encrypted", "File is not encrypted.")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            password = simpledialog.askstring("Enter Password", "Enter the generated password:")
            if password:
                self.password = password.encode('utf-8')
                self.decrypt_file(file_path)

    def save_to_file(self):
        generated_password = self.password.decode('utf-8')
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])

        if file_path:
            with open(file_path, 'w') as file:
                file.write(f"Generated Password: {generated_password}")

    def admin_login(self):
        messagebox.showinfo("Admin Login", "Admin login functionality goes here.")

    def close_app(self):
        self.master.destroy()

    def custom_settings(self):
        # Use tkFileDialog.askdirectory to get the selected directory
        selected_directory = filedialog.askdirectory(title="Select Custom Settings Directory")

        if selected_directory:
            # Print or use the selected directory as needed
            print("Selected Directory:", selected_directory)

            # Add the provided code
            custom_window = tk.Toplevel(self.master)
            custom_window.title("Custom Settings")

            # Create a frame within the window
            custom_frame = tk.Frame(custom_window)
            self.customize_frame(custom_frame)
            custom_frame.pack(padx=10, pady=10)

            # Create a canvas within the frame
            custom_canvas = tk.Canvas(custom_frame)
            self.customize_canvas(custom_canvas)
            custom_canvas.pack()

    def show_encrypted_files(self):
        encrypted_files_window = tk.Toplevel(self.master)
        encrypted_files_window.title("Encrypted Files")

        paned_window = PanedWindow(encrypted_files_window, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        file_listbox = Listbox(paned_window)
        for file_path in self.encrypted_files:
            file_listbox.insert(tk.END, file_path)
        paned_window.add(file_listbox)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureApp(root)
    root.mainloop()
