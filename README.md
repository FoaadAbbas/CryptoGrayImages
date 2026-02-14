🔒 Twofish Hybrid Encryption System

A high-performance Image & Text Encryption Tool that combines the ease of use of a Python GUI with the raw speed of a C-based cryptographic engine. This project implements the Twofish block cipher in OFB (Output Feedback) mode, integrated with Schnorr Signatures and EC-ElGamal for secure key exchange.
🚀 Features

    Hybrid Architecture: The core encryption logic is written in C and compiled into a dynamic library (.dll / .so), accessed by Python via ctypes for maximum performance.

    Twofish Algorithm: Full implementation of the Twofish block cipher (AES finalist) with 128/192/256-bit key support.

    OFB Mode: Uses Output Feedback Mode to function as a stream cipher, allowing for encryption of files of any size without padding.

    Digital Signatures: Implements Schnorr Signatures to ensure data authenticity and non-repudiation.

    Secure Key Exchange: Uses EC-ElGamal (Elliptic Curve ElGamal) for secure asymmetric key sharing between users.

    Modern GUI: A user-friendly Python interface to load images, manage keys, and visualize encryption results in real-time.

🛠️ Tech Stack

    Frontend: Python (Tkinter / CustomTkinter)

    Backend / Engine: C (Standard C99)

    Interoperability: Python ctypes library

    Cryptography: Twofish, Schnorr Group, Elliptic Curves

    Image Processing: Pillow (PIL)

📸 Screenshots
Original Image	Encrypted Image (Chaos)	Decrypted Image
		

(Note: Replace these links with actual screenshots from your application)
⚙️ Installation & Setup
Prerequisites

    Python 3.x installed.

    GCC Compiler (MinGW for Windows or standard GCC for Linux).

1. Clone the Repository
Bash

git clone https://github.com/your-username/twofish-hybrid-encryption.git
cd twofish-hybrid-encryption

2. Compile the C Engine

The Python script relies on a shared library. You must compile the C code first.

On Windows (using MinGW):
Bash

gcc -shared -o twofish.dll twofish.c -O3

On Linux:
Bash

gcc -shared -o twofish.so -fPIC twofish.c -O3

3. Install Python Dependencies
Bash

pip install pillow

💻 Usage

    Run the Application:
    Bash

    python main.py

    Generate Keys: Click the "Generate Keys" button to create your Schnorr and ElGamal key pairs.

    Load Image: Select an image (.jpg, .png, .bmp) from your computer.

    Encrypt:

        The system utilizes the C-DLL to process the image bytes via Twofish-OFB.

        The session key is encrypted using EC-ElGamal.

        The image is signed using Schnorr.

    Decrypt: Load an encrypted file and use the private key to restore the original image.

🧠 Cryptographic Implementation Details
Why Hybrid (C + Python)?

Python is excellent for UI development but slow for bitwise operations required in cryptography. By offloading the encrypt and decrypt loops to C, we achieve processing speeds comparable to native applications, allowing for real-time encryption of high-resolution images.
Twofish OFB Mode

We use Output Feedback (OFB) mode. This turns the block cipher into a synchronous stream cipher.

    Advantage: No padding is required. The ciphertext is exactly the same size as the plaintext.

    Advantage: Bit errors in transmission do not propagate to affect the rest of the block.

Authentication (Schnorr)

To prevent tampering, the message is signed using the Schnorr Signature scheme. This proves that the sender possesses the private key and that the message has not been altered.
📂 Project Structure

twofish-project/
│
├── c_engine/
│   ├── twofish.c       # Core C implementation
│   ├── twofish.h       # Header file
│   └── Makefile        # Compilation instructions
│
├── gui/
│   ├── main.py         # Main GUI entry point
│   └── ui_components.py
│
├── crypto/
│   ├── wrapper.py      # CTypes wrapper for the DLL
│   ├── schnorr.py      # Python impl of Schnorr
│   └── elgamal.py      # Python impl of EC-ElGamal
│
├── twofish.dll         # Compiled library (Windows)
├── twofish.so          # Compiled library (Linux)
├── requirements.txt
└── README.md

🤝 Contributing

Contributions are welcome! Please fork the repository and create a pull request for any features or bug fixes.
📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
📞 Contact

Fuad Abbas

    Email: Foaad.Abbas@e.braude.ac.il

    LinkedIn: linkedin.com/in/fuad-abbas

    GitHub: github.com/FoaadAbbas
