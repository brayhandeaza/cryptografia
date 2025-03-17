# Cryptografia

Criptografia is a fast and easy-to-use cryptography library for JavaScript and TypeScript, designed to provide secure encryption and decryption functionalities with minimal setup. It supports ECC (Elliptic Curve Cryptography) and AES algorithms for asymmetric and symmetric encryption, as well as various hashing, encoding, and decoding algorithms for securing data.

Whether you're transmitting sensitive messages, storing encrypted data, or handling secure user authentication, Criptografia offers a comprehensive set of tools for developers looking for robust security in their applications.

### With support for:
- ECC (asymmetric encryption) for secure key exchange and message encryption
- AES (symmetric encryption) for fast and efficient data encryption
- Hashing algorithms like SHA-1, SHA-3, SHA-256, SHA-512, and MD5
- Encoding and decoding algorithms including Base64 and Hex
- Asynchronous and synchronous API options for different use cases

## Installation

Using npm:
```sh
npm install criptografia
```
Using yarn:
```sh 
yarn add criptografia
```

## List of Contents: 
<ul>
 <li><a href="#usage-with-ecc">Usage with ECC</a></li> <li><a href="#usage-with-aes">Usage with AES</a></li> <li><a href="#usage-with-asynchronous-hashing-algorithms">Usage with Hash</a></li> <li><a href="#usage-with-asynchronous-encoding-and-decoding-algorithms">Usage with Encoding and Decoding</a></li>
</ul>

## Usage with ECC
```javascript
import { ECC } from "criptografia";

const { publicKey, privateKey } = await ECC.generateKeyPairs();

const message = "Hello, World!";
const encryptedMessage = await ECC.encrypt(message, publicKey);
const decryptedMessage = await ECC.decrypt(encryptedMessage, privateKey);

console.log("Original message:", message);
console.log("Encrypted message:", encryptedMessage);
console.log("Decrypted message:", decryptedMessage);
```

## Usage with AES
```javascript
import { AES } from "criptografia";

const key = await AES.generateKey();

const message = 'Hello, world!';
const encryptedMessage = await AES.encrypt(message, key);
const decryptedText = await AES.decrypt(encryptedMessage, key);
        
console.log('Generated key:', key);
console.log('Encrypted text:', encryptedMessage);
console.log('Decrypted text:', decryptedText);
```


## Usage with Asynchronous Hashing Algorithms
```javascript
import { HASH } from "criptografia";

const message = "Hello, World!";

const sha1 = await HASH.sha1Async(message);
const sha3 = await HASH.sha3Async(message);
const sha224 = await HASH.sha224Async(message);
const sha256 = await HASH.sha256Async(message);
const sha384 = await HASH.sha384Async(message);
const sha512 = await HASH.sha512Async(message);
const md5 = await HASH.md5Async(message);

console.log("SHA-1:", sha1);
console.log("SHA-3:", sha3);
console.log("SHA-224:", sha224);
console.log("SHA-256:", sha256);
console.log("SHA-384:", sha384);
console.log("SHA-512:", sha512);
console.log("MD5:", md5);
```
## Usage with Synchronous Hashing Algorithms
```javascript
import { HASH } from "criptografia";

const message = "Hello, World!";

const sha1 = await HASH.sha1(message);
const sha3 = await HASH.sha3(message);
const sha224 = await HASH.sha224(message);
const sha256 = await HASH.sha256(message);
const sha384 = await HASH.sha384(message);
const sha512 = await HASH.sha512(message);
const md5 = await HASH.md5(message);

console.log("SHA-1:", sha1);
console.log("SHA-3:", sha3);
console.log("SHA-224:", sha224);
console.log("SHA-256:", sha256);
console.log("SHA-384:", sha384);
console.log("SHA-512:", sha512);
console.log("MD5:", md5);
```

## Usage with Synchronous Encoding and Decoding Algorithms
```javascript
import { HASH } from "criptografia";

const message = "Hello, World!";

const base64ToString = await HASH.base64ToString(message);
const stringToBase64 = await HASH.stringToBase64(message);
const base64ToHex = await HASH.base64ToHex(message);
const hexToBase64 = await HASH.hexToBase64(message);
const stringToHex = await HASH.stringToHex(message);
const hexToString = await HASH.hexToString(message);

console.log("Base64 to String:", base64ToString);
console.log("String to Base64:", stringToBase64);
console.log("Base64 to Hex:", base64ToHex);
console.log("Hex to Base64:", hexToBase64);
console.log("String to Hex:", stringToHex);
console.log("Hex to String:", hexToString);
```

## Usage with Asynchronous Encoding and Decoding Algorithms
```javascript
import { HASH } from "criptografia";

const message = "Hello, World!";

const base64ToString = await HASH.base64ToStringAsync(message);
const stringToBase64 = await HASH.stringToBase64Async(message);
const base64ToHex = await HASH.base64ToHexAsync(message);
const hexToBase64 = await HASH.hexToBase64Async(message);
const stringToHex = await HASH.stringToHexAsync(message);
const hexToString = await HASH.hexToStringAsync(message);

console.log("Base64 to String:", base64ToString);
console.log("String to Base64:", stringToBase64);
console.log("Base64 to Hex:", base64ToHex);
console.log("Hex to Base64:", hexToBase64);
console.log("String to Hex:", stringToHex);
console.log("Hex to String:", hexToString);
```
