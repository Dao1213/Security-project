# Secure File Sharing System 🔒

This project is a **secure file sharing system** developed in **Go**, designed to ensure **confidentiality, integrity, and access control** over an untrusted storage server.

## Features
- 🔑 **End-to-End Encryption**: AES-GCM for file encryption, RSA for key exchange.
- ✅ **Integrity Verification**: Uses HMAC-SHA256 to prevent unauthorized modifications.
- 👥 **Secure User Authentication**: PBKDF2-derived encryption keys.
- 📂 **File Sharing & Revocation**: Controlled access with public-key cryptography.
- 🚀 **Zero-Knowledge Storage**: The server never sees plaintext user data.

## Tech Stack
- **Language**: Go (Golang)
- **Cryptography**: AES-GCM, HMAC-SHA256, RSA, PBKDF2
- **Testing**: Go Test Framework

## How It Works
1. **User Registration & Login**: Secure key derivation from passwords.
2. **File Encryption & Upload**: Symmetric encryption before storage.
3. **File Sharing**: Uses asymmetric encryption for secure key exchange.
4. **Access Control**: Only authorized users can decrypt shared files.
