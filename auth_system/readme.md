# 🔐 Secure Authentication System

This is a standalone secure authentication system built using modern cryptographic techniques. It provides robust user authentication using:

- **JWT (JSON Web Tokens)** for stateless session management.
- **ECC (Elliptic Curve Cryptography)** for key exchange and digital signatures.
- **AES (Advanced Encryption Standard)** for secure data encryption.

---

## 🛡️ Features

- User Registration and Login
- JWT-based Authentication
- ECC Key Generation and Exchange
- AES Encryption of Sensitive Payloads
- Token Expiry and Refresh Handling
- Secure Password Hashing (e.g., Argon2 / bcrypt)
- CSRF and XSS Protection (if web-facing)

---

## 🧱 Tech Stack

- **Backend:** Python (Django / Flask)
- **Crypto:** 
  - ECC (`cryptography` / `ecdsa` / `pyca`)
  - AES-256-CBC/GCM (`cryptography` library)
- **Auth:** JWT (`PyJWT` / `djangorestframework-simplejwt` / `Flask-JWT-Extended`)

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/auth-system.git
cd auth-system