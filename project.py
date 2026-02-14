import tkinter as tk
from tkinter import filedialog, messagebox, Label, Button, Frame, Text, Entry, Toplevel, Scrollbar
from PIL import Image, ImageTk
import os
import hashlib
import numpy as np
import random
import ctypes
import platform
import sys


# ==========================================
# 1. LOAD C LIBRARY (The Speed Booster)
# ==========================================
def load_twofish_library():
    # Look for the DLL in the same directory as the script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    lib_path = os.path.join(current_dir, "twofish_lib.dll")

    if not os.path.exists(lib_path):
        # Fallback: try relative path if running from IDLE/Terminal root
        lib_path = "twofish_lib.dll"

    try:
        c_lib = ctypes.CDLL(lib_path)

        # --- Define Argument Types for C Functions ---
        c_lib.twofish_setup.restype = ctypes.c_void_p
        c_lib.twofish_setup.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]

        c_lib.twofish_encrypt_block.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte),
                                                ctypes.POINTER(ctypes.c_ubyte)]

        c_lib.twofish_free.argtypes = [ctypes.c_void_p]

        print(f"SUCCESS: Loaded {lib_path}")
        return c_lib
    except OSError as e:
        messagebox.showerror("DLL Error",
                             f"Error loading 'twofish_lib.dll'.\n\n1. Ensure the file is in the same folder.\n2. Ensure it is 64-bit (if using 64-bit Python).\n\nDetails: {e}")
        exit()


# Load the library globally
C_LIB = load_twofish_library()


# ==========================================
# 2. CRYPTO WRAPPERS (Python -> C)
# ==========================================

class TwofishC:
    """Wrapper that talks to the C DLL"""

    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            key = (key * 2)[:32]
        key_array = (ctypes.c_ubyte * len(key))(*key)
        self.ctx = C_LIB.twofish_setup(key_array, len(key))

    def encrypt_block(self, block_bytes):
        in_buf = (ctypes.c_ubyte * 16)(*block_bytes)
        out_buf = (ctypes.c_ubyte * 16)()
        C_LIB.twofish_encrypt_block(self.ctx, in_buf, out_buf)
        return bytes(out_buf)

    def __del__(self):
        if hasattr(self, 'ctx'):
            C_LIB.twofish_free(self.ctx)


class TwofishOFB:
    """Stream Cipher Mode using the C Block Cipher"""

    def __init__(self, key):
        self.bs = 16
        self.cipher = TwofishC(key)

    def encrypt_decrypt(self, data, iv):
        output = bytearray()
        vector = iv
        for i in range(0, len(data), self.bs):
            chunk = data[i:i + self.bs]
            keystream_block = self.cipher.encrypt_block(vector)
            vector = keystream_block
            for j in range(len(chunk)):
                output.append(chunk[j] ^ keystream_block[j])
        return bytes(output)


# ==========================================
# 3. ECC & PROTOCOLS (Pure Python)
# ==========================================
class Curve:
    def __init__(self):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        self.Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def add(self, p1, p2):
        if not p1: return p2
        if not p2: return p1
        x1, y1 = p1;
        x2, y2 = p2
        if x1 == x2 and y1 != y2: return None
        if x1 == x2: return self.double(p1)
        m = ((y2 - y1) * pow(x2 - x1, self.p - 2, self.p)) % self.p
        x3 = (m ** 2 - x1 - x2) % self.p;
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def double(self, p1):
        x1, y1 = p1;
        m = ((3 * x1 ** 2) * pow(2 * y1, self.p - 2, self.p)) % self.p
        x3 = (m ** 2 - 2 * x1) % self.p;
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k, p1):
        r = None;
        cur = p1
        while k:
            if k % 2: r = self.add(r, cur)
            cur = self.double(cur);
            k //= 2
        return r


secp256k1 = Curve()
G = (secp256k1.Gx, secp256k1.Gy)


class ECElGamal:
    def encrypt_key(self, pub, k_bytes):
        k = random.randrange(1, secp256k1.n)
        C1 = secp256k1.mul(k, G)
        S = secp256k1.mul(k, pub)
        mask = hashlib.sha256(S[0].to_bytes(32, 'big')).digest()
        C2 = bytes([k_bytes[i] ^ mask[i] for i in range(len(k_bytes))])
        return C1, C2

    def decrypt_key(self, priv, C1, C2):
        S = secp256k1.mul(priv, C1)
        mask = hashlib.sha256(S[0].to_bytes(32, 'big')).digest()
        return bytes([C2[i] ^ mask[i] for i in range(len(C2))])


class SchnorrAuth:
    def sign(self, priv, msg):
        k = random.randrange(1, secp256k1.n)
        R = secp256k1.mul(k, G)
        e = int.from_bytes(hashlib.sha256(R[0].to_bytes(32, 'big') + msg).digest(), 'big')
        return R, (k - priv * e) % secp256k1.n

    def verify(self, pub, msg, sig):
        R, s = sig
        e = int.from_bytes(hashlib.sha256(R[0].to_bytes(32, 'big') + msg).digest(), 'big')
        return secp256k1.add(secp256k1.mul(s, G), secp256k1.mul(e, pub)) == R


# ==========================================
# 4. MODERN GUI (Dark Mode)
# ==========================================
USER_DB = {"alice": hashlib.sha256(b"password").hexdigest(), "bob": hashlib.sha256(b"password").hexdigest()}

# --- Colors ---
C_BG = "#1e1e1e"
C_PANEL = "#252526"
C_ACCENT = "#007acc"
C_TEXT = "#ffffff"
C_SUCCESS = "#4ec9b0"
C_ERROR = "#f44747"


class ModernApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureCrypto 3.0 (C Engine + Modern UI + Matrices)")
        self.root.geometry("1000x800")
        self.root.configure(bg=C_BG)

        # Key Generation
        self.a_priv = random.randrange(1, secp256k1.n);
        self.a_pub = secp256k1.mul(self.a_priv, G)
        self.b_priv = random.randrange(1, secp256k1.n);
        self.b_pub = secp256k1.mul(self.b_priv, G)
        self.pkg = None

        # --- STORAGE FOR MATRICES ---
        self.mat_orig = None
        self.mat_enc = None
        self.mat_dec = None

        # Layout
        self.main_container = Frame(root, bg=C_BG)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        self.f_alice = Frame(self.main_container, bg=C_PANEL, bd=1, relief="flat")
        self.f_alice.pack(side="left", fill="both", expand=True, padx=10)

        self.f_bob = Frame(self.main_container, bg=C_PANEL, bd=1, relief="flat")
        self.f_bob.pack(side="right", fill="both", expand=True, padx=10)

        self.show_login(self.f_alice, "alice", self.ui_alice)
        self.show_login(self.f_bob, "bob", self.ui_bob)

    def create_btn(self, parent, text, cmd, color=C_ACCENT, state="normal"):
        btn = Button(parent, text=text, command=cmd, bg=color, fg="white",
                     font=("Segoe UI", 10, "bold"), relief="flat", padx=15, pady=8, state=state)
        return btn

    def show_login(self, frame, user, callback):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text=f"🔒 {user.upper()} LOGIN", font=("Segoe UI", 16, "bold"), bg=C_PANEL, fg=C_TEXT).pack(pady=40)

        Label(frame, text="USERNAME", bg=C_PANEL, fg="gray", font=("Segoe UI", 8)).pack(anchor="w", padx=40)
        e_user = Entry(frame, bg="#333333", fg="white", insertbackground="white", relief="flat", font=("Consolas", 11))
        e_user.insert(0, user);
        e_user.pack(fill="x", padx=40, pady=(0, 15), ipady=5)

        Label(frame, text="PASSWORD", bg=C_PANEL, fg="gray", font=("Segoe UI", 8)).pack(anchor="w", padx=40)
        e_pass = Entry(frame, show="•", bg="#333333", fg="white", insertbackground="white", relief="flat",
                       font=("Consolas", 11))
        e_pass.pack(fill="x", padx=40, pady=(0, 5), ipady=5)

        lbl_hash_title = Label(frame, text="LIVE ENCRYPTION PREVIEW:", bg=C_PANEL, fg="gray", font=("Segoe UI", 7))
        lbl_hash_title.pack(pady=(10, 0))
        lbl_hash = Label(frame, text="waiting for input...", bg="#1a1a1a", fg=C_ACCENT, font=("Consolas", 8),
                         wraplength=300, justify="center", padx=10, pady=10)
        lbl_hash.pack(pady=5, padx=40, fill="x")

        def update_hash(e):
            if not e_pass.get():
                lbl_hash.config(text="waiting...")
            else:
                h = hashlib.sha256(e_pass.get().encode()).hexdigest()
                lbl_hash.config(text=f"{h[:32]}\n{h[32:]}")

        e_pass.bind("<KeyRelease>", update_hash)

        self.create_btn(frame, "ACCESS SYSTEM",
                        lambda: self.check_login(e_user.get(), e_pass.get(), frame, callback)).pack(pady=30)

    def check_login(self, u, p, f, cb):
        if USER_DB.get(u) == hashlib.sha256(p.encode()).hexdigest():
            cb(f)
        else:
            messagebox.showerror("Access Denied", "Invalid Credentials")

    def ui_alice(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="👤 ALICE (Sender)", font=("Segoe UI", 14, "bold"), bg=C_PANEL, fg=C_SUCCESS).pack(pady=15)

        step1 = Frame(frame, bg=C_PANEL);
        step1.pack(pady=10, fill="x", padx=20)
        self.create_btn(step1, "📂 1. SELECT IMAGE", self.load_img, "#444").pack(fill="x")

        # --- NEW: Original Matrix Button ---
        self.btn_mat_a = self.create_btn(step1, "🔢 SHOW ORIGINAL MATRIX",
                                         lambda: self.show_matrix(self.mat_orig, "Original"), "#555", "disabled")
        self.btn_mat_a.pack(fill="x", pady=5)

        self.lbl_a = Label(frame, text="No Image Loaded", bg="#111", fg="#555", width=40, height=15)
        self.lbl_a.pack(pady=10, padx=20)

        step2 = Frame(frame, bg=C_PANEL);
        step2.pack(pady=10, fill="x", padx=20)
        self.btn_enc = self.create_btn(step2, "🔒 2. ENCRYPT & SIGN", self.encrypt, C_ACCENT, "disabled")
        self.btn_enc.pack(fill="x")

        self.log_a = Text(frame, height=6, bg="#111", fg="#ddd", font=("Consolas", 8), relief="flat", padx=5, pady=5)
        self.log_a.pack(fill="both", expand=True, padx=20, pady=20)
        self.log("Alice", "System Ready (C-Accelerated).")

    def ui_bob(self, frame):
        for w in frame.winfo_children(): w.destroy()
        Label(frame, text="👤 BOB (Receiver)", font=("Segoe UI", 14, "bold"), bg=C_PANEL, fg=C_ACCENT).pack(pady=15)

        self.lbl_status = Label(frame, text="WAITING FOR DATA...", fg="gray", bg=C_PANEL, font=("Segoe UI", 10))
        self.lbl_status.pack(pady=10)

        self.lbl_b = Label(frame, text="Waiting...", bg="#111", fg="#555", width=40, height=15)
        self.lbl_b.pack(pady=5, padx=20)

        # --- NEW: Bob's Matrix Buttons ---
        frame_mats = Frame(frame, bg=C_PANEL)
        frame_mats.pack(fill="x", padx=20)

        self.btn_mat_enc = self.create_btn(frame_mats, "🔢 ENCRYPTED MATRIX",
                                           lambda: self.show_matrix(self.mat_enc, "Encrypted Noise"), "#555",
                                           "disabled")
        self.btn_mat_enc.pack(fill="x", pady=2)

        self.btn_mat_dec = self.create_btn(frame_mats, "🔢 DECRYPTED MATRIX",
                                           lambda: self.show_matrix(self.mat_dec, "Decrypted Image"), "#555",
                                           "disabled")
        self.btn_mat_dec.pack(fill="x", pady=2)

        step3 = Frame(frame, bg=C_PANEL);
        step3.pack(pady=10, fill="x", padx=20)
        self.btn_dec = self.create_btn(step3, "🔓 3. VERIFY & DECRYPT", self.decrypt, C_SUCCESS, "disabled")
        self.btn_dec.pack(fill="x")

        self.log_b = Text(frame, height=6, bg="#111", fg="#ddd", font=("Consolas", 8), relief="flat", padx=5, pady=5)
        self.log_b.pack(fill="both", expand=True, padx=20, pady=20)
        self.log("Bob", "Standing by.")

    def log(self, u, msg):
        w = self.log_a if u == "Alice" else self.log_b
        w.insert("end", f"> {msg}\n");
        w.see("end")

    # --- ADDED: Show Matrix Function ---
    def show_matrix(self, matrix, title):
        if matrix is None: return
        win = Toplevel(self.root)
        win.title(f"{title} - {matrix.shape}")
        win.geometry("700x500")

        f = Frame(win);
        f.pack(fill="both", expand=True)
        sy = Scrollbar(f);
        sy.pack(side="right", fill="y")
        sx = Scrollbar(f, orient="horizontal");
        sx.pack(side="bottom", fill="x")

        txt = Text(f, font=("Consolas", 9), wrap="none", yscrollcommand=sy.set, xscrollcommand=sx.set)
        txt.pack(fill="both", expand=True)
        sy.config(command=txt.yview);
        sx.config(command=txt.xview)

        # Show FULL Matrix data (threshold=infinity)
        full_str = np.array2string(matrix, threshold=np.inf)
        txt.insert("1.0", full_str)
        txt.config(state="disabled")

    def load_img(self):
        path = filedialog.askopenfilename()
        if path:
            self.path = path
            img = Image.open(path).convert("L")
            # --- Save Original File ---
            img.save("original_image.png")

            # Save Original Matrix
            self.mat_orig = np.array(img)
            self.btn_mat_a.config(state="normal")

            # Preview Thumbnail only
            img.thumbnail((250, 200))
            self.tk_a = ImageTk.PhotoImage(img)
            self.lbl_a.config(image=self.tk_a, text="", width=250, height=200)
            self.btn_enc.config(state="normal")
            self.log("Alice", f"Loaded: {os.path.basename(path)}")

    def encrypt(self):
        self.log("Alice", "Encrypting with C Engine... (Fast)")
        self.root.update()

        # 1. Load FULL Image
        img = Image.open(self.path).convert("L")
        data = np.array(img).tobytes()

        # 2. Encrypt using C DLL
        key = os.urandom(32);
        iv = os.urandom(16)
        tf = TwofishOFB(key)
        cipher = tf.encrypt_decrypt(data, iv)

        eg = ECElGamal();
        C1, C2 = eg.encrypt_key(self.b_pub, key)
        sc = SchnorrAuth();
        payload = iv + C1[0].to_bytes(32, 'big') + C2 + cipher
        sig = sc.sign(self.a_priv, payload)

        self.pkg = {"iv": iv, "C1": C1, "C2": C2, "c": cipher, "s": sig, "sz": img.size, "m": img.mode}

        # 3. Save Encrypted Noise File
        noise = Image.frombytes(img.mode, img.size, cipher)
        noise.save("encrypted_image.png")

        # Save Encrypted Matrix
        self.mat_enc = np.array(noise)
        self.btn_mat_enc.config(state="normal")

        # Preview
        noise.thumbnail((250, 200))
        self.tk_n = ImageTk.PhotoImage(noise)
        self.lbl_b.config(image=self.tk_n, text="", width=250, height=200)
        self.lbl_status.config(text="● ENCRYPTED MESSAGE RECEIVED", fg=C_ACCENT)
        self.btn_dec.config(state="normal")
        self.log("Alice", f"Sent secure package ({img.size[0]}x{img.size[1]}).")

    def decrypt(self):
        p = self.pkg
        sc = SchnorrAuth()
        payload = p["iv"] + p["C1"][0].to_bytes(32, 'big') + p["C2"] + p["c"]

        if not sc.verify(self.a_pub, payload, p["s"]):
            messagebox.showerror("Error", "Signature Invalid!");
            return
        self.log("Bob", "Signature Verified (Valid).")

        eg = ECElGamal();
        key = eg.decrypt_key(self.b_priv, p["C1"], p["C2"])

        # Decrypt using C DLL
        tf = TwofishOFB(key)
        raw = tf.encrypt_decrypt(p["c"], p["iv"])

        # 4. Restore Full Quality Image
        img = Image.frombytes(p["m"], p["sz"], raw)
        img.save("decrypted_image.png")

        # Save Decrypted Matrix
        self.mat_dec = np.array(img)
        self.btn_mat_dec.config(state="normal")

        # Preview
        img.thumbnail((250, 200))
        self.tk_r = ImageTk.PhotoImage(img)
        self.lbl_b.config(image=self.tk_r)
        self.lbl_status.config(text="✔ DECRYPTION SUCCESSFUL", fg=C_SUCCESS)
        self.log("Bob", "Image recovered & saved as 'decrypted_image.png'.")


if __name__ == "__main__":
    root = tk.Tk()
    app = ModernApp(root)
    root.mainloop()
