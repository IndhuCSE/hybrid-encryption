import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from PIL import Image, ImageTk
import os
import json
import io
import fitz  # PyMuPDF

# Path to store image metadata
metadata_file_path = "image_metadata.json"

# Theme colors
primary_color = "#333333"  # Dark grey for background
accent_color = "#03A9F4"    # Light blue
text_color = "#FFFFFF"       # White for text
button_color = "#7dde3f"     # Light green
button_color2 = "#436a2a"    # Dark olive

# Store password for accessing decrypted images
decryption_password = None

# AES Encryption
def aes_encrypt(data):
    aes_key = get_random_bytes(32)  # 256-bit AES key
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return ciphertext, aes_key, cipher_aes.nonce

# AES Decryption
def aes_decrypt(ciphertext, aes_key, nonce):
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt(ciphertext)
    return plaintext

# RSA Encryption of AES Key
def rsa_encrypt_aes_key(aes_key, public_key_path):
    with open(public_key_path, 'rb') as f:
        recipient_public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

# RSA Decryption of AES Key
def rsa_decrypt_aes_key(encrypted_aes_key, private_key_path):
    with open(private_key_path, 'rb') as f:
        recipient_private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

# Function to ensure the 'encrypted_files' directory exists
def ensure_encrypted_dir():
    if not os.path.exists('encrypted_files'):
        os.makedirs('encrypted_files')

# Function to ensure the 'decrypted_files' directory exists
def ensure_decrypted_dir():
    if not os.path.exists('decrypted_files'):
        os.makedirs('decrypted_files')

# Load image metadata
def load_image_metadata():
    if os.path.exists(metadata_file_path):
        with open(metadata_file_path, 'r') as f:
            return json.load(f)
    return {}

# Save image metadata
def save_image_metadata(metadata):
    with open(metadata_file_path, 'w') as f:
        json.dump(metadata, f)

# GUI Functions
def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if file_path:
        label_file.config(text=f"Selected File: {file_path}")
        return file_path
    
    else:
        messagebox.showwarning("Warning", "No file selected!")
        return None

def encrypt_file():
    file_path = select_file()
    if file_path:
        public_key_path = filedialog.askopenfilename(title="Select Recipient's Public Key", filetypes=[("PEM Files", "*.pem")])
        if not public_key_path:
            messagebox.showwarning("Warning", "No public key file selected!")
            return

        loading_label.config(text="Encrypting...")

        with open(file_path, 'rb') as f:
            file_data = f.read()

        encrypted_data, aes_key, nonce = aes_encrypt(file_data)
        encrypted_aes_key = rsa_encrypt_aes_key(aes_key, public_key_path)
        
        file_extension = os.path.splitext(file_path)[1]
        
        ensure_encrypted_dir()

        encrypted_file_path = f"encrypted_files/{os.path.basename(file_path)}{file_extension}.enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(nonce + encrypted_data)
        
        encrypted_key_path = f"encrypted_files/{os.path.basename(file_path)}_key.enc"
        with open(encrypted_key_path, 'wb') as f:
            f.write(encrypted_aes_key)

        loading_label.config(text="Encryption Completed")
        messagebox.showinfo("Success", f"File Encrypted Successfully!\nEncrypted file saved at: {encrypted_file_path}\nEncrypted key saved at: {encrypted_key_path}")

def decrypt_file():
    enc_file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc")])
    key_file_path = filedialog.askopenfilename(title="Select Encrypted Key", filetypes=[("Encrypted Key Files", "*.enc")])
    private_key_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM Files", "*.pem")])

    if enc_file_path and key_file_path and private_key_path:
        loading_label.config(text="Decrypting...")

        with open(key_file_path, 'rb') as f:
            encrypted_aes_key = f.read()

        aes_key = rsa_decrypt_aes_key(encrypted_aes_key, private_key_path)

        with open(enc_file_path, 'rb') as f:
            nonce = f.read(16)
            encrypted_data = f.read()

        decrypted_data = aes_decrypt(encrypted_data, aes_key, nonce)

        decrypted_file_path = f"decrypted_files/{os.path.basename(enc_file_path)[:-4]}"
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        if decryption_password:
            entered_password = simpledialog.askstring("Password Required", "Enter the password to view this image:")
            if entered_password != decryption_password:
                messagebox.showerror("Error", "Incorrect password! Access denied.")
                return
        # Determine file type and display the image
        display_decrypted_image(decrypted_file_path)

        loading_label.config(text="Decryption Completed")
        messagebox.showinfo("Success", f"File Decrypted Successfully!\nDecrypted file saved at: {decrypted_file_path}")
    else:
        messagebox.showwarning("Warning", "Please select all required files!")

def display_decrypted_image(file_path):
    file_extension = os.path.splitext(file_path)[1].lower()

    # Clear previous images
    for widget in image_frame.winfo_children():
        widget.destroy()

    # Display based on file type
    if file_extension in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
        image = Image.open(file_path)
        image_tk = ImageTk.PhotoImage(image)
        image_label = tk.Label(image_frame, image=image_tk)
        image_label.image = image_tk  # Keep reference
        image_label.pack(pady=10)
    elif file_extension == '.pdf':
        images = extract_images_from_pdf(file_path)
        display_images(images)  # Display extracted PDF images
    else:
        label_preview.config(text="File format not supported for preview.")
        label_preview.pack()

# Extract images from PDF
def extract_images_from_pdf(pdf_path):
    images = []
    doc = fitz.open(pdf_path)
    for page in doc:
        for img_index in range(len(page.get_images(full=True))):
            xref = page.get_images(full=True)[img_index][0]
            base_image = doc.extract_image(xref)
            image_bytes = base_image["image"]
            images.append(image_bytes)
    return images

# Display images in GUI
def display_images(images):
    for img_data in images:
        image = Image.open(io.BytesIO(img_data))
        image_tk = ImageTk.PhotoImage(image)
        image_label = tk.Label(image_frame, image=image_tk)
        image_label.image = image_tk  # Keep reference to avoid garbage collection
        image_label.pack(pady=10)

def set_password():
    global decryption_password
    password = simpledialog.askstring("Set Password", "Enter a password to protect the decrypted images:")
    if password:
        decryption_password = password
        messagebox.showinfo("Password Set", "Decryption password has been set.")

def store_decrypted_image(image_path):
    if decryption_password:
        entered_password = simpledialog.askstring("Password Required", "Enter the password to store this image:")
        if entered_password == decryption_password:
            # Add functionality to store the image and update metadata
            messagebox.showinfo("Success", "Image stored successfully!")
        else:
            messagebox.showerror("Error", "Incorrect password!")
    else:
        messagebox.showwarning("Warning", "No password has been set.")

# Tkinter GUI Setup
root = tk.Tk()
root.title("AES-RSA Hybrid Encryption Tool ")
root.geometry("923x800")
root.configure(bg=primary_color)

frame = tk.Frame(root, bg=primary_color)
frame.pack(pady=20, padx=20, fill="both")

# Theme styles
label_title = tk.Label(frame, text="AES AND RSA Encryption", font=("Helvetica", 18, "bold"), bg=primary_color, fg=text_color)
label_title.grid(row=0, columnspan=2, pady=20)

label_file = tk.Label(frame, text="No File Selected", font=("Helvetica", 12, "bold"), bg=primary_color, fg=text_color)
label_file.grid(row=1, column=0, pady=10, sticky="w")

btn_encrypt = tk.Button(frame, text="Encrypt", command=encrypt_file, bg=button_color, fg="white", font=("Helvetica", 12, "bold"))
btn_encrypt.grid(row=2, column=0, padx=30, pady=30)

btn_decrypt = tk.Button(frame, text="Decrypt", command=decrypt_file, bg=button_color, fg="white", font=("Helvetica", 12, "bold"))
btn_decrypt.grid(row=2, column=1, padx=30, pady=30)

# Section for decrypted images
decrypted_frame = tk.Frame(root, bg=primary_color)
decrypted_frame.pack(pady=20, padx=20, fill="both")

label_decrypted_title = tk.Label(decrypted_frame, text="Decrypted Images Management", font=("Helvetica", 16, "bold"), bg=primary_color, fg=text_color)
label_decrypted_title.grid(row=0, columnspan=3, pady=20)

btn_store_image = tk.Button(decrypted_frame, text="Store Decrypted Image", command=lambda: store_decrypted_image("path_to_decrypted_image"), bg=button_color2, fg="white", font=("Helvetica", 12, "bold"))
btn_store_image.grid(row=1, column=0, padx=10, pady=10)

btn_set_password = tk.Button(decrypted_frame, text="Set Password", command=set_password, bg=button_color2, fg="white", font=("Helvetica", 12, "bold"))
btn_set_password.grid(row=1, column=1, padx=10, pady=10)

loading_label = tk.Label(root, text="", font=("Helvetica", 12), bg=primary_color, fg="gray")
loading_label.pack(pady=20)

label_preview = tk.Label(root, text="No Image Preview Available", font=("Helvetica", 12), bg=primary_color, fg=text_color)
label_preview.pack(pady=20)

image_frame = tk.Frame(root, bg=primary_color)
image_frame.pack(pady=20, padx=20, fill="both")

root.mainloop()
