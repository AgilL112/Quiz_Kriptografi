import tkinter as tk
from tkinter import filedialog, messagebox
import string
import numpy as np

def vigenere_encrypt(plaintext, key):
    key = key.lower()
    plaintext = plaintext.lower()
    key = (key * (len(plaintext) // len(key))) + key[:len(plaintext) % len(key)]
    ciphertext = ''.join([chr(((ord(p) - ord('a')) + (ord(k) - ord('a'))) % 26 + ord('a')) for p, k in zip(plaintext, key)])
    return ciphertext
def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    ciphertext = ciphertext.lower()
    key = (key * (len(ciphertext) // len(key))) + key[:len(ciphertext) % len(key)]
    plaintext = ''.join([chr(((ord(c) - ord('a')) - (ord(k) - ord('a'))) % 26 + ord('a')) for c, k in zip(ciphertext, key)])
    return plaintext
def create_playfair_matrix(key):
    key = ''.join(sorted(set(key), key=key.index))  
    key += ''.join([chr(i) for i in range(ord('a'), ord('z') + 1) if chr(i) not in key and chr(i) != 'j'])
    matrix = [key[i:i + 5] for i in range(0, 25, 5)]
    return matrix
def playfair_encrypt(plaintext, key):
    matrix = create_playfair_matrix(key.lower())
    plaintext = plaintext.lower().replace('j', 'i').replace(' ', '')
    if len(plaintext) % 2 != 0:
        plaintext += 'x'
    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i + 1]
        row_a, col_a = divmod(matrix.index(a), 5)
        row_b, col_b = divmod(matrix.index(b), 5)
        if row_a == row_b:
            ciphertext += matrix[row_a][(col_a + 1) % 5]
            ciphertext += matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            ciphertext += matrix[(row_a + 1) % 5][col_a]
            ciphertext += matrix[(row_b + 1) % 5][col_b]
        else:
            ciphertext += matrix[row_a][col_b]
            ciphertext += matrix[row_b][col_a]
    return ciphertext
def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key.lower())
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row_a, col_a = divmod(matrix.index(a), 5)
        row_b, col_b = divmod(matrix.index(b), 5)
        if row_a == row_b:
            plaintext += matrix[row_a][(col_a - 1) % 5]
            plaintext += matrix[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            plaintext += matrix[(row_a - 1) % 5][col_a]
            plaintext += matrix[(row_b - 1) % 5][col_b]
        else:
            plaintext += matrix[row_a][col_b]
            plaintext += matrix[row_b][col_a]
    return plaintext
def generate_hill_key_matrix(key):
    key_matrix = np.array([[ord(k) - ord('a') for k in key[i:i + 3]] for i in range(0, 9, 3)])
    return key_matrix
def hill_encrypt(plaintext, key):
    key_matrix = generate_hill_key_matrix(key.lower())
    plaintext = plaintext.lower().replace(' ', '')
    if len(plaintext) % 3 != 0:
        plaintext += 'x' * (3 - len(plaintext) % 3)
    ciphertext = ""
    for i in range(0, len(plaintext), 3):
        chunk = np.array([ord(p) - ord('a') for p in plaintext[i:i + 3]])
        encrypted_chunk = np.dot(key_matrix, chunk) % 26
        ciphertext += ''.join([chr(num + ord('a')) for num in encrypted_chunk])
    return ciphertext
def hill_decrypt(ciphertext, key):
    key_matrix = generate_hill_key_matrix(key.lower())
    key_matrix_inv = np.linalg.inv(key_matrix) * np.linalg.det(key_matrix)
    key_matrix_inv = np.round(key_matrix_inv).astype(int) % 26
    plaintext = ""
    for i in range(0, len(ciphertext), 3):
        chunk = np.array([ord(c) - ord('a') for c in ciphertext[i:i + 3]])
        decrypted_chunk = np.dot(key_matrix_inv, chunk) % 26
        plaintext += ''.join([chr(num + ord('a')) for num in decrypted_chunk])
    return plaintext
def process_encryption(cipher_type, action, input_text, key):
    if len(key) < 12:
        messagebox.showerror("Error", "Kunci harus minimal 12 karakter!")
        return
    if cipher_type == "Vigenère Cipher":
        if action == "Encrypt":
            return vigenere_encrypt(input_text, key)
        else:
            return vigenere_decrypt(input_text, key)
    elif cipher_type == "Playfair Cipher":
        if action == "Encrypt":
            return playfair_encrypt(input_text, key)
        else:
            return playfair_decrypt(input_text, key)
    elif cipher_type == "Hill Cipher":
        if action == "Encrypt":
            return hill_encrypt(input_text, key)
        else:
            return hill_decrypt(input_text, key)
    else:
        messagebox.showerror("Error", "Pilih cipher yang valid!")
        return
def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    with open(file_path, 'r') as file:
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, file.read())
def save_result(output_text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    with open(file_path, 'w') as file:
        file.write(output_text)

root = tk.Tk()
root.title("Cipher Encryption/Decryption")

cipher_label = tk.Label(root, text="Pilih Cipher:")
cipher_label.pack()
cipher_type = tk.StringVar(value="Vigenère Cipher")
cipher_menu = tk.OptionMenu(root, cipher_type, "Vigenère Cipher", "Playfair Cipher", "Hill Cipher")
cipher_menu.pack()

input_label = tk.Label(root, text="Input Teks:")
input_label.pack()
input_text = tk.Text(root, height=10)
input_text.pack()

browse_button = tk.Button(root, text="Browse File", command=browse_file)
browse_button.pack()

key_label = tk.Label(root, text="Input Kunci (Minimal 12 karakter):")
key_label.pack()
key_entry = tk.Entry(root, width=50)
key_entry.pack()

action_var = tk.StringVar(value="Encrypt")
encrypt_button = tk.Radiobutton(root, text="Encrypt", variable=action_var, value="Encrypt")
encrypt_button.pack()
decrypt_button = tk.Radiobutton(root, text="Decrypt", variable=action_var, value="Decrypt")
decrypt_button.pack()

def execute_process():
    input_val = input_text.get("1.0", tk.END).strip()
    key_val = key_entry.get().strip()
    result = process_encryption(cipher_type.get(), action_var.get(), input_val, key_val)
    if result:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

process_button = tk.Button(root, text="Proses", command=execute_process)
process_button.pack()

output_label = tk.Label(root, text="Hasil:")
output_label.pack()
output_text = tk.Text(root, height=10)
output_text.pack()

save_button = tk.Button(root, text="Save Hasil", command=lambda: save_result(output_text.get("1.0", tk.END)))
save_button.pack()

root.mainloop()

