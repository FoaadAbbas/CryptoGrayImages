# 🔒 Twofish Hybrid Encryption System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![C](https://img.shields.io/badge/C-C99-00599C) ![License](https://img.shields.io/badge/License-MIT-green) ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

A high-performance **Image & Text Encryption Tool** that combines the ease of use of a **Python GUI** with the raw speed of a **C-based cryptographic engine**. This project implements the **Twofish** block cipher in **OFB (Output Feedback) mode**, integrated with **Schnorr Signatures** and **EC-ElGamal** for secure key exchange.

---

## 🎥 Live Demo

Watch the system in action: **Alice** (Sender) generates keys, loads an image, encrypts it using the C-Engine, and sends it to **Bob** (Receiver) who verifies the signature and decrypts the content.

<p align="center">
  <img src="https://github.com/user-attachments/assets/6bff15f6-d872-47ed-94e5-febc7f2d12e3" alt="Twofish Hybrid Encryption Demo" width="100%">
</p>

---

## 🚀 Features

* **⚡ Hybrid Architecture:** The core encryption logic is written in **C** (compiled to `.dll`/`.so`) and accessed via Python's `ctypes` for maximum performance, handling heavy image processing instantly.
* **🔑 Twofish Algorithm:** Full implementation of the Twofish block cipher (AES finalist) with support for 128/192/256-bit keys.
* **🔄 OFB Mode:** Uses Output Feedback Mode to function as a synchronous stream cipher, allowing encryption of data without padding.
* **✍️ Digital Signatures:** Implements **Schnorr Signatures** to ensure data authenticity and non-repudiation.
* **🛡️ Secure Key Exchange:** Uses **EC-ElGamal** (Elliptic Curve ElGamal) for secure asymmetric key sharing.
* **🎨 Modern GUI:** Built with **CustomTkinter**, offering a dark-mode interface that visualizes the encrypted byte matrix in real-time.

---

## 🛠️ Tech Stack

* **Frontend:** Python (CustomTkinter, Pillow)
* **Backend / Engine:** C (Standard C99)
* **Interoperability:** Python `ctypes` library
* **Cryptography:** Twofish, Schnorr Group, Elliptic Curves

---

## ⚙️ Installation & Setup

### Prerequisites
1.  **Python 3.x** installed.
2.  **GCC Compiler** (MinGW for Windows or standard GCC for Linux).

### 1. Clone the Repository
```bash
git clone [https://github.com/FoaadAbbas/twofish-hybrid-encryption.git](https://github.com/FoaadAbbas/twofish-hybrid-encryption.git)
cd twofish-hybrid-encryption

2. Compile the C Engine

The Python script relies on a shared library. You must compile the C code before running the app.

On Windows (using MinGW):
Bash

gcc -shared -o twofish.dll c_engine/twofish.c -O3

On Linux:
Bash

gcc -shared -o twofish.so -fPIC c_engine/twofish.c -O3

3. Install Python Dependencies
Bash

pip install customtkinter pillow

💻 Usage Guide

    Run the Application:
    Bash

    python main.py

    Generate Keys:

        Click the "Generate Keys" button. This creates Schnorr and ElGamal key pairs for both Alice and Bob in the background.

    Alice's Role (Sender):

        Click "Load Image" and select a file (.jpg, .png).

        The system encrypts the image using the C-DLL (Twofish-OFB).

        The session key is encrypted with Bob's public key.

        The package is signed with Alice's private key.

    Bob's Role (Receiver):

        The encrypted "Chaos" matrix is displayed.

        Click "Decrypt".

        The system verifies Alice's signature, decrypts the session key, and restores the original image.

🧠 Cryptographic Implementation Details
Why Hybrid (C + Python)?

Python is excellent for rapid UI development but can be slow for intensive bitwise operations required in cryptography loops. By offloading the encrypt and decrypt functions to C, we achieve execution speeds comparable to native applications, allowing for real-time encryption of high-resolution images without UI freezing.
Twofish OFB Mode

We use Output Feedback (OFB) mode.

    Stream Cipher Behavior: Converts the block cipher into a stream cipher.

    No Padding: The ciphertext is exactly the same size as the plaintext.

    Error Resilience: Bit errors in transmission do not propagate to affect the rest of the block, making it robust for image data.

📂 Project Structure
Plaintext

twofish-project/
│
├── c_engine/
│   ├── twofish.c       # Core C implementation (The Engine)
│   └── twofish.h       # Header file
│
├── gui/
│   ├── main.py         # Main Entry Point
│   └── ui_utils.py     # UI Helper functions
│
├── crypto/
│   ├── wrapper.py      # CTypes wrapper (Bridge between C and Python)
│   ├── schnorr.py      # Schnorr Signature implementation
│   └── elgamal.py      # EC-ElGamal implementation
│
├── twofish.dll         # Compiled Library (Windows)
├── requirements.txt    # Dependencies
└── README.md           # Documentation

🤝 Contributing

Contributions are welcome! Please fork the repository and create a pull request for any features, bug fixes, or documentation improvements.
📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
📞 Contact

Fuad Abbas

    Email: Foaad.Abbas@e.braude.ac.il

    LinkedIn: linkedin.com/in/fuad-abbas

    GitHub: github.com/FoaadAbbas
