# SAM'S PASSWORD MANAGER

# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 1: Import Statements and Initialization

import base64
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import keyring
import math
import os
import pyperclip
import random
import re
import string
from tkinter import *
from tkinter import BooleanVar
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import scrolledtext
import tkinter as tk
from tkinter import ttk

class MasterPasswordDialog(tk.simpledialog.Dialog):
    def __init__(self, parent, title=None):
        super().__init__(parent, title)

    def body(self, master):
        self.geometry("300x150")  # Set the dialog size
        tk.Label(master, text="Enter your master password:").grid(row=0)
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.grid(row=1)
        return self.password_entry  # Initial focus

    def apply(self):
        self.result = self.password_entry.get()
        
class PasswordManager:
    def __init__(self, app):
        self.app = app
        self.master_password_hash = self._check_master_password()
        self.encryption_key = self._get_encryption_key()

    def _hash_password(self, password):
        # Use bcrypt for hashing
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return hashed_password.decode() # Decode to string for storage

    def _get_encryption_key(self):
        # Check if key exists in keyring
        key = keyring.get_password("password_manager", "encryption_key")
        if key:
            return base64.urlsafe_b64decode(key) 
        else:
            # Generate a new key if it doesn't exist
            key = Fernet.generate_key()
            keyring.set_password("password_manager", "encryption_key", base64.urlsafe_b64encode(key).decode())
            return key
    
# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 2: The Master Password

    def _check_master_password(self):
        if not os.path.exists("master_password.txt"):
            master_password = simpledialog.askstring("Master Password", "Enter a master password:", show='*')
            app = tk.Tk()
            app.geometry("350x270")
            if master_password:
                with open("master_password.txt", "w") as f:
                    # Store hashed password using bcrypt
                    hashed_password = self._hash_password(master_password)  # Use the _hash_password method
                    f.write(hashed_password)
                messagebox.showinfo("Success", "Master password set!")
                return hashed_password  # Return hashed password as string
            else:
                exit()  # Exit if no master password is provided

        with open("master_password.txt", "r") as f:
            stored_hash = f.read()

        while True:
            #entered_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
            dialog = MasterPasswordDialog(self.app, title="Master Password") # 'app' is your main window
            entered_password = dialog.result
            
            if not entered_password:
                exit()  # Exit if no password is entered

            if bcrypt.checkpw(entered_password.encode(), stored_hash.encode()):  # Use bcrypt.checkpw for verification
                return stored_hash  # Correct password, proceed
            else:
                messagebox.showerror("Error", "Incorrect master password. Please try again.")

# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 3: Adding Passwords and Encryption

    def add(self):
        if self._verify_master_password(): #Verify Master Password Before Adding
            username = entryName.get()
            app_name = entryApp.get()
            password = entryPassword.get()

            if not username or not app_name or not password:
                messagebox.showerror("Error", "Please fill in all fields.")
                return

            # Encrypt the password
            f = Fernet(self.encryption_key)  # Create Fernet object
            encrypted_password = f.encrypt(password.encode()).decode()  # Encrypt and decode to string

            try:
                with open("passwords.txt", "a") as f:
                    f.write(f"{username} {encrypted_password} {app_name}\n")
                messagebox.showinfo("Success", "Password added successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Error adding password: {e}")
                
# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 4: Retrieving Passwords and Decryption

    def get(self):
        if self._verify_master_password():
            username = entryName.get()
            app_name = entryApp.get()

            if not username or not app_name:
                messagebox.showerror("Error", "Please enter both username and app name.")
                return

            passwords = {}
            try:
                with open("passwords.txt", 'r') as f:
                    for line in f:
                        u, p, a = line.strip().split(' ', 2)  # Split into 3 parts
                        passwords[u + " " + a] = p 
            except FileNotFoundError:
                messagebox.showinfo("Info", "No passwords stored yet.")
                return
            except Exception as e:
                messagebox.showerror("Error", f"Error reading passwords: {e}")
                return

            key_to_find = username + " " + app_name
            if key_to_find in passwords:
                encrypted_password = passwords[key_to_find]

                # Decrypt the password
                f = Fernet(self.encryption_key)
                try:
                    decrypted_password = f.decrypt(encrypted_password.encode()).decode()
                except Exception as e:
                    messagebox.showerror("Error", f"Decryption failed. Incorrect password or data corruption: {e}")
                    return
                
                # Copy to clipboard directly
                pyperclip.copy(decrypted_password)
                messagebox.showinfo("Password", f"Password for {username} in {app_name} copied to clipboard.") 
            else:
                messagebox.showinfo("Password", "No password found for this username/app combination.")
    
# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 5: Read and Decrypt Passwords
    
    def getlist(self):
        if self._verify_master_password():
            app_users = {}  # Dictionary to store app and corresponding usernames
            try:
                with open("passwords.txt", 'r') as f:
                    for line in f:
                        u, p, a = line.strip().split(' ', 2)
                        if a not in app_users:
                            app_users[a] = []  # Create a list for each app
                        app_users[a].append(u)  # Add username to the app's list
            except FileNotFoundError:
                messagebox.showinfo("Info", "No passwords stored yet.")
                return
            except Exception as e:
                messagebox.showerror("Error", f"Error reading passwords: {e}")
                return

            if not app_users:
                messagebox.showinfo("Info", "No passwords stored yet.")
                return

            sorted_apps = sorted(app_users.keys())  # Sort apps alphabetically

            mess = "List of apps and their respective usernames:\n"
            for app in sorted_apps:
                for name in app_users[app]:
                    mess += f"{app}:			{name}\n"  # Desired format

            list_window = tk.Toplevel(self.app)
            list_window.title("Usernames")
            text_area = scrolledtext.ScrolledText(list_window, wrap = tk.WORD, state = "normal")
            text_area.insert(tk.END, mess)
            text_area.config(state = "disabled")
            text_area.pack(expand = True, fill = "both")
        
# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 5: Deleting an Existing Password

    def delete(self):
        if self._verify_master_password():
            username = entryName.get()
            app_name = entryApp.get()

            if not username or not app_name:
                messagebox.showerror("Error", "Please enter both username and app name.")
                return

            try:
                with open("passwords.txt", "r") as f:
                    lines = f.readlines()

                with open("passwords.txt", "w") as f:
                    for line in lines:
                        u, p, a = line.strip().split(' ', 2)
                        if u != username or a != app_name:
                            f.write(line)  # Write the line back if it's not the one to delete
                
                messagebox.showinfo("Success", f"Password for {username} in {app_name} deleted successfully!")
            except FileNotFoundError:
                messagebox.showinfo("Info", "No passwords stored yet.")
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting password: {e}")
                
    def generate(self):
        os.system("python secure_password_generator.pyw")

# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 6: Master Password Verification and Hiding Passwords

    def _verify_master_password(self):
        while True:
            dialog = MasterPasswordDialog(app, title="Master Password")
            entered_password = dialog.result
            if not entered_password:
                return False  # Exit if no password is entered

            # Hash the entered password for comparison
            hashed_entered_password = bcrypt.hashpw(entered_password.encode(), bcrypt.gensalt())
            
            if bcrypt.checkpw(entered_password.encode(), self.master_password_hash.encode()):
                return True  # Correct password
            else:
                messagebox.showerror("Error", "Incorrect master password. Please try again.")  # Incorrect password

    def password_entry_changed(event):
        current_text = entryPassword.get()
        if len(current_text) > 0:
            entryPassword.config(show="")  # Show the last character
            entryPassword.delete(0, tk.END)  # Clear the entry box
            entryPassword.insert(0, "*" * (len(current_text) - 1) + current_text[-1])  # Re-populate with asterisks and last character
        else:
            entryPassword.config(show="*")  # If entry is empty, show asterisks
        
# ----------------------------------------------------------------------------------------------------------------------

# SEGMENT 7: GUI Setup and Main Loop

if __name__ == "__main__":
    app = tk.Tk()
    app.withdraw()
    app.geometry("330x200")
    app.title("Sam's Password Manager")
    password_manager = PasswordManager(app)
    
    if password_manager.master_password_hash: # Correct password
        app.deiconify()
    
    # App name block
    labelApp = tk.Label(app, text="APP NAME:")
    labelApp.grid(row=0, column=0, padx=10, pady=5)  
    entryApp = tk.Entry(app)
    entryApp.grid(row=0, column=1, columnspan=2, padx=10, pady=5)  

    # Username block
    labelName = tk.Label(app, text="USERNAME:")
    labelName.grid(row=1, column=0, padx=10, pady=5)
    entryName = tk.Entry(app)
    entryName.grid(row=1, column=1, columnspan=2, padx=10, pady=5)

    # Password block
    labelPassword = tk.Label(app, text="PASSWORD:")
    labelPassword.grid(row=2, column=0, padx=10, pady=5)
    entryPassword = tk.Entry(app, show="*")
    entryPassword.grid(row=2, column=1, columnspan=2, padx=10, pady=5)
    
    # Add button
    buttonAdd = tk.Button(app, text="Add", command=password_manager.add)
    buttonAdd.grid(row=4, column=2, columnspan=2, padx=10, pady=5, sticky="we")  # Adjusted row and columnspan

    # Get button
    buttonGet = tk.Button(app, text="Get", command=password_manager.get)
    buttonGet.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="we") # Adjusted row and columnspan

    # List Button
    buttonList = tk.Button(app, text="List", command=password_manager.getlist)
    buttonList.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="we")  # Adjusted row and columnspan

    # Delete button
    buttonDelete = tk.Button(app, text="Delete", command=password_manager.delete)
    buttonDelete.grid(row=5, column=2, columnspan=2, padx=10, pady=5, sticky="we") # Adjusted row and columnspanapp.mainloop()
    
    # Generate password
    buttonGenerate = tk.Button(app, text="Generate", command=password_manager.generate)
    buttonGenerate.grid(row=2, column=3, padx=17, sticky="W")
    
    app.mainloop()