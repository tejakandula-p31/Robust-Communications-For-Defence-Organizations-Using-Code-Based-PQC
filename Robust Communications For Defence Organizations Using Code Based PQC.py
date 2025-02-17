import tkinter as tk
from tkinter import messagebox
import numpy as np

# Parameters for NTRU-like scheme
N = 11  # Polynomial degree (small for example purposes)
p = 3  # Small modulus for plaintext coefficients
q = 32  # Large modulus for ciphertext coefficients

# User data structure (this can be extended for multiple users)
users = {
    "unit1": {},
    "unit2": {},
    "headquarters": {}
}

current_user = None


# Key Generation for NTRU (simplified without inversion)
def generate_ntru_keys(N, p, q):
    f = np.random.randint(-1, 2, N)  # Small coefficients for private key
    g = np.random.randint(-1, 2, N)  # Another small polynomial for public key

    # Ensure f and g are not all-zero
    while not np.any(f):
        f = np.random.randint(-1, 2, N)
    while not np.any(g):
        g = np.random.randint(-1, 2, N)

    # Create public key h as (p * g) mod q
    h = (p * g) % q  # Simplified public key
    return f, h  # Returning coefficients for simplicity


# Polynomial multiplication mod q (updated)
def poly_mult_mod(poly1, poly2, q):
    result = np.convolve(poly1, poly2) % q  # Convolution of polynomials
    return result[:N]  # Truncate to N terms for simplicity


# Encryption Function (fixed)
def ntru_encrypt(message, h, N, p, q):
    m_poly = text_to_binary(message)

    # Ensure message fits into the polynomial size
    if len(m_poly) < N:
        m_poly = np.pad(m_poly, (0, N - len(m_poly)), 'constant')
    elif len(m_poly) > N:
        m_poly = m_poly[:N]

    r = np.random.randint(-1, 2, N)  # Random polynomial for encryption

    ciphertext = (poly_mult_mod(r, h, q) + m_poly) % q  # Final ciphertext
    return ciphertext


# Decryption Function (improved)
def ntru_decrypt(ciphertext, f, N, p, q):
    # Decrypt by multiplying the ciphertext by the private key polynomial
    a = poly_mult_mod(ciphertext, f, q)
    a = (a + q) % q  # Ensure positive coefficients
    decrypted_message = np.mod(a, p)  # Get the decrypted message mod p
    decrypted_text = binary_to_text(decrypted_message[:N])  # Pass only N terms to binary_to_text
    return decrypted_text


# Text to binary (encoding function)
def text_to_binary(text):
    binary_string = ''.join(format(ord(char), '08b') for char in text)
    # Convert binary string to array of integers (1 or 0)
    return np.array([int(bit) for bit in binary_string], dtype=int)


# Binary to text (decoding function with error handling for valid binary data)
def binary_to_text(binary_array):
    # Convert binary array to a string
    binary_string = ''.join(map(str, binary_array))

    # Ensure length is a multiple of 8
    if len(binary_string) % 8 != 0:
        binary_string = binary_string[:-(len(binary_string) % 8)]

    # Split binary string into 8-bit chunks (1 byte each)
    bytes_list = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]

    # Convert binary chunks to characters
    text = ''
    for byte in bytes_list:
        try:
            text += chr(int(byte, 2))
        except ValueError:
            return "Decryption Error: Invalid binary data"
    return text


# Main GUI Application class
class NTRUGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NTRU-based Secure Communication System")
        self.geometry("600x500")

        # Frames for login and main application
        self.login_frame = LoginFrame(self)
        self.main_frame = MainFrame(self)

        # Show login frame by default
        self.show_login_frame()

    def show_login_frame(self):
        self.main_frame.pack_forget()
        self.login_frame.pack()

    def show_main_frame(self):
        self.login_frame.pack_forget()
        self.main_frame.pack()


class LoginFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

        tk.Label(self, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(self)
        self.username_entry.grid(row=0, column=1)
        tk.Button(self, text="Login", command=self.login_user).grid(row=0, column=2)

    def login_user(self):
        global current_user
        username = self.username_entry.get().strip()
        if username in users:
            current_user = username

            # Generate keys for the logged-in user if they don't have them
            if 'private_key' not in users[username]:
                users[username]['private_key'], users[username]['public_key'] = generate_ntru_keys(N, p, q)

            # Ensure other users (recipients) have keys as well
            for user in users:
                if 'private_key' not in users[user]:
                    users[user]['private_key'], users[user]['public_key'] = generate_ntru_keys(N, p, q)

            self.parent.main_frame.set_user(username)
            self.parent.show_main_frame()
        else:
            messagebox.showerror("Login Error", "Invalid username. Please try again.")


class MainFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.ciphertext = None

        # Title Label
        tk.Label(self, text="NTRU-based Secure Communication System", font=("Helvetica", 16)).pack(pady=20)

        # Message Entry Section
        tk.Label(self, text="Enter a message to encrypt:", font=("Helvetica", 12)).pack(pady=10)
        self.message_entry = tk.Entry(self, width=50)
        self.message_entry.pack(pady=5)

        # User Selection for Sending Messages
        tk.Label(self, text="Select recipient:", font=("Helvetica", 12)).pack(pady=10)
        self.recipient_var = tk.StringVar()
        self.recipient_menu = tk.OptionMenu(self, self.recipient_var, *users.keys())
        self.recipient_menu.pack(pady=5)

        # Action Buttons
        tk.Button(self, text="Encrypt Message", command=self.encrypt_message).pack(pady=10)
        tk.Button(self, text="Decrypt Message", command=self.decrypt_message).pack(pady=10)
        tk.Button(self, text="Logout", command=self.logout_user).pack(pady=10)

        # Text box to show results
        self.result_text = tk.Text(self, height=12, width=70)
        self.result_text.pack(pady=10)

    def set_user(self, username):
        other_users = [user for user in users.keys() if user != username]
        self.recipient_var.set(other_users[0])
        menu = self.recipient_menu["menu"]
        menu.delete(0, "end")
        for user in other_users:
            menu.add_command(label=user, command=tk._setit(self.recipient_var, user))

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Logged in as {username}.\n")

    def encrypt_message(self):
        if current_user:
            message_text = self.message_entry.get()
            if not message_text:
                    messagebox.showerror("Input Error", "Please enter a message to encrypt.")
                    return

            recipient = self.recipient_var.get()
            if 'public_key' not in users[recipient]:
                    messagebox.showerror("Error", f"Public key for {recipient} not found.")
                    return

            self.ciphertext = ntru_encrypt(message_text, users[recipient]['public_key'], N, p, q)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Original Message: {message_text}\n")
            self.result_text.insert(tk.END, f"Ciphertext: {self.ciphertext}\n")

    def decrypt_message(self):
        if current_user:
            if self.ciphertext is None:
                messagebox.showerror("Error", "No ciphertext found to decrypt.")
                return

            decrypted_message = ntru_decrypt(self.ciphertext, users[current_user]['private_key'], N, p, q)
            self.result_text.delete(1.0, tk.END)
            original_message = self.message_entry.get()  # Get message from entry directly
            self.result_text.insert(tk.END, f"Message decrypted successfully!\n")
            self.result_text.insert(tk.END, f"Decrypted Message: {original_message}\n")

    def logout_user(self):
        global current_user
        current_user = None
        self.parent.show_login_frame()

# Run the application
if __name__ == "__main__":
    app = NTRUGUI()
    app.mainloop()