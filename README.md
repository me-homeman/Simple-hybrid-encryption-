# 🔐 Hybrid Encryption Tool (RSA-4096 + AES-256)

This Python tool demonstrates a **256-bit hybrid encryption system** using **RSA-4096** (asymmetric) and **AES-256-CBC** (symmetric) encryption. It provides 
strong cryptographic guarantees, combining the efficiency of AES with the security of RSA and SHA-256 padding.

-------------------------------------------------------------------------------------------------------------------------------------------------------------

## 🚀 Features

- RSA key generation (4096-bit) for secure key exchange
- AES-256 encryption with random IV and PKCS7 padding
- Secure hybrid encryption: AES key encrypted with RSA-OAEP (SHA-256)
- Combined encrypted message format for portability
- Interactive command-line menu for easy use
  
---------------------------------------------------------------------------------------------------------------------------------------------------------------

## 🔧 Requirements

- Python 3.6+
- `cryptography` library

--------------------------------------------------------------------------------------------------------------------------------------------------------------

## How To Install 

- Clone:

```sh
git clone https://github.com/me-homeman/Simple-hybrid-encryption-.git
```
- change  dir:
  
```sh
cd Simple-hybrid-encryption-
```
- Create the virtual environment:

```sh
python -m venv myenv
```
- Activate the virtual environment:

```sh
source myenv/bin/activate  
```

- Install packages:

```sh
 pip install cryptography 
```
       

- start the file:
```sh
 python 'Hybrid Encryption Tool.py' run
```
   
--------------------------------------------------------------------------------------------------------------------------------------------------------------

#🔒 Encrypt a Message

Input your plaintext message.

Outputs a combined encrypted string (in hex), including:

Encrypted AES-256 key

AES IV

AES-encrypted data

--------------------------------------------------------------------------------------------------------------------------------------------------------------

#🔓 Decrypt a Message

Paste the previously generated combined hex string.

Outputs the original plaintext message.

--------------------------------------------------------------------------------------------------------------------------------------------------------------

#📦 Combined Format

The encrypted message is structured as:

pgsql
Copy
Edit
[AES_KEY_LENGTH(2 bytes)][Encrypted AES-256 Key]
[IV_LENGTH(2 bytes)][IV]
[Encrypted Data]
All fields are serialized and represented in a single hexadecimal string for portability.

--------------------------------------------------------------------------------------------------------------------------------------------------------------

#🔐 Cryptographic Details

RSA-4096: Provides ~256-bit security level

AES-256-CBC: Symmetric encryption with a 256-bit key and a 128-bit IV

OAEP Padding with SHA-256: Secures RSA encryption of the AES key

PKCS7 Padding: Ensures data is block-aligned for AES-CBC

--------------------------------------------------------------------------------------------------------------------------------------------------------------

#⚠️ Disclaimer

This tool is for educational and demonstration purposes. For production-grade security, always follow industry best practices and consult with a cryptography expert.











  
