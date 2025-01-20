AES Encryption Tool

Overview

AES Encryption Tool is a robust, user-friendly desktop application that provides file encryption and decryption using the Advanced Encryption Standard (AES). This tool is designed to ensure data security with features such as password strength validation, real-time progress tracking, and a sleek graphical user interface (GUI) built with PyQt5. It is suitable for individuals and organizations looking to secure sensitive files effortlessly.

Features

AES-CFB Encryption and Decryption: Secure your files using AES in Cipher Feedback Mode.

Password-Based Key Derivation: Ensures secure cryptographic key generation using PBKDF2.

Progress Bar: Displays real-time progress of the encryption or decryption process.

Cross-Platform: Compatible with Windows, macOS, and Linux.

Password Strength Indicator: Guides users to create strong passwords.

Chunked File Processing: Handles large files efficiently.

Installation

Using PyPI

Ensure Python 3.8 or later is installed.

Install the tool using pip:

pip install aes-encryption-tool

Usage

Run the Application

After installation, launch the tool from your terminal:

aes-tool

Graphical Interface

Input File: Select the file you want to encrypt or decrypt.

Output File: Specify the location and name for the processed file.

Password: Enter a secure password for encryption or decryption. The tool provides feedback on password strength.

Mode Selection: Choose between "encrypt" and "decrypt" modes.

Start Process: Click "Start" to begin. Monitor progress through the progress bar.

Completion: A success or error message will indicate the result.

Commands

Install the Tool:

pip install aes-encryption-tool

Run the Tool:

aes-tool

Uninstall the Tool:

pip uninstall aes-encryption-tool

Learn About the Tool:

pip show aes-encryption-tool

Technical Details

Cryptography

Algorithm: AES (Advanced Encryption Standard) in Cipher Feedback (CFB) mode.

Key Derivation: PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256.

Salt and IV:

A 16-byte salt ensures unique encryption keys per operation.

A 16-byte initialization vector (IV) guarantees ciphertext uniqueness.

Chunk Size: Files are processed in 1 KB chunks to handle large files efficiently.

GUI Implementation

Built using PyQt5 for an intuitive and interactive user experience.

Key components:

File selection dialogs.

Password input with strength validation.

Mode selection dropdown.

Dynamic progress bar.

Multithreading

Utilizes PyQt5's QThread to perform encryption and decryption in a separate thread, keeping the GUI responsive.

Example Workflow

Run the application:

aes-tool

Select the input file using the "Browse" button.

Choose the output file location and name.

Enter a secure password and ensure it is strong.

Select the desired mode ("encrypt" or "decrypt").

Click "Start" and monitor the progress bar.

Upon completion, a message box will indicate success or any encountered errors.

FAQ

1. What encryption standard is used?

The tool uses AES (Advanced Encryption Standard) in Cipher Feedback (CFB) mode.

2. What happens if I lose my password?

The encrypted files cannot be decrypted without the correct password. Always store your password securely.

3. Can I encrypt large files?

Yes, the tool processes files in chunks, allowing it to handle large files without overloading system resources.

4. Is my password stored?

No, the tool does not store or transmit passwords, ensuring your privacy.

Contributing

Contributions are welcome! If you would like to contribute:

Fork the repository: GitHub Repository

Create a feature branch.

Submit a pull request with a detailed description of your changes.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Author

Name: Your Name

Email: syahra2014@gmail.com

GitHub: https://github.com/syahra712/aes-encryption

