import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import sqlite3
import bcrypt
import os
import re
import tkinter.ttk as ttk
import zlib  # For CRC32
import hashlib
import time

class DatabaseHandler:
    def __init__(self, db_name):
        self.db_name = db_name

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()

    def execute(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            return self.cursor
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Exception in _query: {e}")

def is_password_complex(password):
    pattern = r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}'
    return re.fullmatch(pattern, password) is not None

def calculate_sha256_checksum(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            for block in iter(lambda: file.read(4096), b''):
                sha256_hash.update(block)
        return sha256_hash.hexdigest()
    except IOError as e:
        print(f"Could not read file {file_path}: {e}")
        return None

def calculate_crc32_checksum_optimized(file_path):
    state = 0xFFFFFFFF
    try:
        with open(file_path, 'rb') as file:
            for block in iter(lambda: file.read(4096), b''):
                state = zlib.crc32(block, state)
        return state ^ 0xFFFFFFFF
    except IOError as e:
        print(f"Could not read file {file_path}: {e}")
        return None

def safe_database_operation(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None
        except Exception as e:
            print(f"Exception in database operation: {e}")
            return None
    return wrapper

@safe_database_operation
def execute_safe(query, params=()):
    # Your database execution logic
    pass

class IntegrityChecker:
    def __init__(self, username):
        self.username = username
        self.checked_files = {}  # Store file hashes {file_path: hash}

    def update_file_hash(self, file_path):
        checksum = calculate_sha256_checksum(file_path)
        if file_path in self.checked_files:
            if self.checked_files[file_path] != checksum:
                messagebox.showerror("Integrity Check Failed", f"The integrity of {file_path} has been compromised.")
        else:
            self.checked_files[file_path] = checksum
            messagebox.showinfo("Integrity Check Passed", f"The integrity of {file_path} is intact.")

def calculate_folder_checksum(folder_path):
    checksums = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_checksum = calculate_crc32_checksum_optimized(file_path)
                checksums.append((file_path, file_checksum))
            except IOError as e:
                print(f"Could not read file {file_path}: {e}")
    return checksums

def get_folder_details(folder_path):
    file_count = 0
    total_size = 0
    file_list = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_count += 1
            try:
                size = os.path.getsize(file_path)
                total_size += size
                file_list.append((file_path, size))
            except OSError as e:
                print(f"Could not get file size for {file_path}: {e}")

    return file_count, total_size, file_list

def create_registration_window():
    registration_window = tk.Toplevel(window)
    registration_window.title("Registration")

    label_username = tk.Label(registration_window, text="Enter your desired username:")
    label_username.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    username = tk.StringVar()
    entry_username = tk.Entry(registration_window, textvariable=username)
    entry_username.grid(row=0, column=1, padx=5, pady=5, sticky="e")

    label_password = tk.Label(registration_window, text="Enter your desired password:")
    label_password.grid(row=1, column=0, padx=5, pady=5, sticky="w")

    password = tk.StringVar()
    entry_password = tk.Entry(registration_window, textvariable=password, show='*')
    entry_password.grid(row=1, column=1, padx=5, pady=5, sticky="e")

    def register():
        if not username.get() or not password.get():
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        if not is_password_complex(password.get()):
            messagebox.showerror("Error", "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character (@$!%*?&), and be at least 8 characters long.")
            return

        password_hash = bcrypt.hashpw(password.get().encode(), bcrypt.gensalt())

        with DatabaseHandler('user_data.db') as db:
            db.execute("SELECT * FROM users WHERE username = ?", (username.get(),))
            result = db.cursor.fetchone()

            if result:
                messagebox.showerror("Error", "Username already exists. Please choose another username.")
            else:
                db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username.get(), password_hash))
                messagebox.showinfo("Success", "Registration successful. You can now log in.")
                registration_window.destroy()

    button_register = tk.Button(registration_window, text="Register", command=register)
    button_register.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

def login_user():
    username = simpledialog.askstring("Login", "Enter your username:")
    password = simpledialog.askstring("Login", "Enter your password:", show='*')

    if not username or not password:
        messagebox.showerror("Error", "Username and password cannot be empty.")
        return

    with DatabaseHandler('user_data.db') as db:
        db.execute("SELECT * FROM users WHERE username = ?", (username,))
        result = db.cursor.fetchone()

        if result and bcrypt.checkpw(password.encode(), result[1]):
            create_integrity_checker_window(username)
        else:
            messagebox.showerror("Error", "Invalid username or password.")

def create_integrity_checker_window(username):
    integrity_window = tk.Toplevel(window)
    integrity_window.title("Integrity Checker")

    frame_input = tk.Frame(integrity_window)
    frame_input.pack(fill=tk.X, padx=10, pady=10)

    label_path = tk.Label(frame_input, text="Select a file or folder to check:")
    label_path.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    selected_path = tk.StringVar()

    def browse_file():
        path = filedialog.askopenfilename()
        selected_path.set(path)

    def browse_folder():
        path = filedialog.askdirectory()
        selected_path.set(path)

    button_browse_file = tk.Button(frame_input, text="Browse File", command=browse_file)
    button_browse_file.grid(row=0, column=1, padx=5, pady=5, sticky="e")

    button_browse_folder = tk.Button(frame_input, text="Browse Folder", command=browse_folder)
    button_browse_folder.grid(row=0, column=2, padx=5, pady=5, sticky="e")

    label_selected_path = tk.Label(frame_input, textvariable=selected_path)
    label_selected_path.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

    def calculate_checksum():
        path = selected_path.get()
        if not path:
            messagebox.showerror("Error", "Please select a file or folder first.")
            return

        if os.path.isfile(path):
            checksum = calculate_sha256_checksum(path)
            messagebox.showinfo("Checksum", f"SHA-256 Checksum: {checksum}")
            report = f"File Integrity: {'Good' if checksum else 'Compromised'}"
            messagebox.showinfo("Integrity Report", report)
        elif os.path.isdir(path):
            file_count, total_size, file_list = get_folder_details(path)
            if file_list:
                messagebox.showinfo("Folder Details", f"Folder contains {file_count} files with a total size of {total_size} bytes.")
                integrity_report = "Integrity Report for Files:\n"
                for file_path, file_size in file_list:
                    checksum = calculate_sha256_checksum(file_path)
                    integrity_status = "Good" if checksum else "Compromised"
                    integrity_report += f"{file_path} - Size: {file_size} bytes, Integrity: {integrity_status}\n"
                messagebox.showinfo("Integrity Report", integrity_report)
            else:
                messagebox.showinfo("Folder Details", "No files found in the folder.")
        else:
            messagebox.showerror("Error", "Invalid file or folder path.")

    button_calculate = tk.Button(frame_input, text="Calculate Checksum", command=calculate_checksum)
    button_calculate.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

with DatabaseHandler('user_data.db') as db:
    db.execute('''CREATE TABLE IF NOT EXISTS users
                  (username TEXT PRIMARY KEY,
                   password TEXT NOT NULL);''')

window = tk.Tk()
window.title("Integrity Checker")

frame_main = tk.Frame(window)
frame_main.pack(padx=20, pady=20)

label_title = tk.Label(frame_main, text="Integrity Checker", font=("Helvetica", 18))
label_title.grid(row=0, column=0, columnspan=2, padx=5, pady=10)

button_register = tk.Button(frame_main, text="Register", command=create_registration_window)
button_register.grid(row=1, column=0, padx=5, pady=5, sticky="w")

button_login = tk.Button(frame_main, text="Login", command=login_user)
button_login.grid(row=1, column=1, padx=5, pady=5, sticky="e")

window.mainloop()
