# Cryptographic API

This project provides a RESTful API for cryptographic operations, including key generation, encryption, decryption, hashing, and hash verification.

## Hosting Details
The API is hosted on Vercel and can be accessed at:
```
https://cyber-assi02-git-main-oshan-yalegamas-projects.vercel.app
```

## API  Methods

### Key Generation
**Endpoint:** `POST /generate-key`

**Request Body:**
```json
{
  "key_type": "AES",  // string
  "key_size": 256      // integer (Allowed values: 128, 192, 256)
}
```

**Response:**
```json
{
  "key_id": "12345",
  "key_value": "base64-encoded-key"
}
```

### Encryption
**Endpoint:** `POST /encrypt`

**Request Body:**
```json
{
  "key_id": "12345",   // string
  "plaintext": "message-to-encrypt", // string
  "algorithm": "AES"  // string (AES or RSA)
}
```

**Response:**
```json
{
  "ciphertext": "base64-encoded-ciphertext"
}
```

### Decryption
**Endpoint:** `POST /decrypt`

**Request Body:**
```json
{
  "key_id": "12345",   // string
  "ciphertext": "base64-encoded-ciphertext", // string
  "algorithm": "AES"  // string (AES or RSA)
}
```

**Response:**
```json
{
  "plaintext": "original-message"
}
```

### Hashing
**Endpoint:** `POST /generate-hash`

**Request Body:**
```json
{
  "data": "message-to-hash",  // string
  "algorithm": "SHA-256"  // string (SHA-256, SHA-512)
}
```

**Response:**
```json
{
  "hash_value": "base64-encoded-hash",
  "algorithm": "SHA-256"
}
```

### Hash Verification
**Endpoint:** `POST /verify-hash`

**Request Body:**
```json
{
  "data": "message-to-verify", // string
  "hash_value": "base64-encoded-hash", // string
  "algorithm": "SHA-256"  // string (SHA-256, SHA-512)
}
```

**Response (Valid Case):**
```json
{
  "is_valid": true,
  "message": "Hash matches the data."
}
```

**Response (Invalid Case):**
```json
{
  "is_valid": false,
  "message": "Hash does not match the data."
}
```
