# Criptografia

Criptografia is a simple and efficient cryptography library for JavaScript, providing easy-to-use encryption and decryption functionalities using RSA and AES algorithms. Whether you need to securely transmit messages or store sensitive data, this package ensures strong encryption with minimal setup.

With support for both asymmetric (RSA) and symmetric (AES) encryption, Criptografia is designed for developers who want a reliable security layer in their applications.

## Installation

Using npm:
```sh
npm install criptografia
```
Using yarn:
```sh 
yarn add criptografia
```

## Usage with RSA
```javascript
import { RSA } from "criptografia";

const { publicKey, privateKey } = await RSA.generateKeysAsync();

const message = "Hello, World!";
const encryptedMessage = await RSA.encryptAsync(message, publicKey);
const decryptedMessage = await RSA.decryptAsync(encryptedMessage, privateKey);

console.log("Original message:", message);
console.log("Encrypted message:", encryptedMessage);
console.log("Decrypted message:", decryptedMessage);
```

## Usage with AES
```javascript
import { AES } from "criptografia";

const key = await AES.generateKeyAsync();

const message = 'Hello, world!';
const encryptedMessage = await AES.encryptAsync(message, key);
const decryptedText = await AES.decryptAsync(encryptedMessage, key);

console.log('Generated key:', key);
console.log('Encrypted text:', encryptedMessage);
console.log('Decrypted text:', decryptedText);
```

## License

This package is licensed under the MIT License.

