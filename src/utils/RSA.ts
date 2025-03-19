import { BigInteger } from "jsbn";
import { Buffer } from "buffer";
import { HASH } from "./HASH";


export class RSA {
    // ===============================================================================================================
    // Generate RSA keys asynchronously
    // ===============================================================================================================
    static generateKeysAsync = async (bitLength: number = 2048): Promise<{ publicKey: string; privateKey: string }> => {
        try {
            const e = new BigInteger("65537"); // Public exponent
            let p, q, n, phi, d;

            do {
                p = RSA.generatePrime(bitLength / 2);
                q = RSA.generatePrime(bitLength / 2);
                n = p.multiply(q);
                phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            } while (!RSA.gcd(e, phi).equals(BigInteger.ONE));

            d = e.modInverse(phi);

            return {
                publicKey: `${RSA.bigIntToHex(e)}.${RSA.bigIntToHex(n)}`,
                privateKey: `${RSA.bigIntToHex(d)}.${RSA.bigIntToHex(n)}`
            };

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // ===============================================================================================================
    // Generate RSA keys
    // ===============================================================================================================
    static generateKeys(bitLength: number = 512) {
        const e = new BigInteger("65537"); // Public exponent
        let p, q, n, phi, d;

        do {
            p = RSA.generatePrime(bitLength / 2);
            q = RSA.generatePrime(bitLength / 2);
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        } while (!RSA.gcd(e, phi).equals(BigInteger.ONE));

        d = e.modInverse(phi);

        return {
            publicKey: `${RSA.bigIntToHex(e)}.${RSA.bigIntToHex(n)}`,
            privateKey: `${RSA.bigIntToHex(d)}.${RSA.bigIntToHex(n)}`
        };
    }

    // ===============================================================================================================
    // Encrypt message asynchronously
    // ===============================================================================================================
    static encryptAsync = async (message: string, publicKey: string): Promise<string> => {
        try {
            const [eHex, nHex] = publicKey.split(".");
            const e = RSA.hexToBigInt(eHex);
            const n = RSA.hexToBigInt(nHex);
            const m = RSA.textToBigInt(message);
            if (m.compareTo(n) >= 0) throw new Error("Message too large for RSA key size");
            return RSA.bigIntToHex(m.modPow(e, n));

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // ===============================================================================================================
    // Encrypt message
    // ===============================================================================================================
    static encrypt(message: string, publicKey: string) {
        const [eHex, nHex] = publicKey.split(".");
        const e = RSA.hexToBigInt(eHex);
        const n = RSA.hexToBigInt(nHex);
        const m = RSA.textToBigInt(message);
        if (m.compareTo(n) >= 0) throw new Error("Message too large for RSA key size");
        return RSA.bigIntToHex(m.modPow(e, n));
    }

    // ===============================================================================================================
    // Decrypt message asynchronously
    // ===============================================================================================================
    static decryptAsync = (cipherText: string, privateKey: string): Promise<string> => {
        try {
            const [dHex, nHex] = privateKey.split(".");
            const d = RSA.hexToBigInt(dHex);
            const n = RSA.hexToBigInt(nHex);
            const c = RSA.hexToBigInt(cipherText);
            return Promise.resolve(RSA.bigIntToText(c.modPow(d, n)));
        } catch (error) {
            return Promise.reject(error)
        }
    }

    // ===============================================================================================================
    // Decrypt message
    // ===============================================================================================================
    static decrypt(cipherText: string, privateKey: string) {
        const [dHex, nHex] = privateKey.split(".");
        const d = RSA.hexToBigInt(dHex);
        const n = RSA.hexToBigInt(nHex);
        const c = RSA.hexToBigInt(cipherText);
        return RSA.bigIntToText(c.modPow(d, n));
    }

    // ===============================================================================================================
    // Sign message asynchronously
    // ===============================================================================================================
    static sign(message: string, privateKey: string): Promise<string> {
        try {
            const [dHex, nHex] = privateKey.split(".");
            const d = RSA.hexToBigInt(dHex);
            const n = RSA.hexToBigInt(nHex);

            const hashedMessage = HASH.sha256(message);
            const hash = RSA.textToBigInt(hashedMessage);

            return Promise.resolve(RSA.bigIntToHex(hash.modPow(d, n)));

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // ===============================================================================================================
    // Verify signature asynchronously
    // ===============================================================================================================
    static verify(message: string, signature: string, publicKey: string): Promise<boolean> {
        try {
            const [eHex, nHex] = publicKey.split(".");
            const e = RSA.hexToBigInt(eHex);
            const n = RSA.hexToBigInt(nHex);

            const hashedMessage = HASH.sha256(message);
            const hash = RSA.textToBigInt(hashedMessage);

            const decryptedHash = RSA.hexToBigInt(signature).modPow(e, n);
            return Promise.resolve(hash.equals(decryptedHash));

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // ===============================================================================================================
    // Converters bigInt > text
    // ===============================================================================================================
    private static bigIntToText(big: BigInteger): string {
        let hex = big.toString(16);
        if (hex.length % 2 !== 0) hex = "0" + hex;
        return Buffer.from(hex, "hex").toString("utf8");
    }

    // ===============================================================================================================
    // Converters text > bigInt
    // ===============================================================================================================
    private static textToBigInt(text: string): BigInteger {
        return new BigInteger(Buffer.from(text, "utf8").toString("hex"), 16);
    }

    // ===============================================================================================================
    // Converters bigInt > hex
    // ===============================================================================================================
    private static bigIntToHex(big: BigInteger): string {
        return big.toString(16);
    }

    // ===============================================================================================================
    // Converters hex > bigInt
    // ===============================================================================================================
    private static hexToBigInt(hex: string): BigInteger {
        return new BigInteger(hex, 16);
    }

    // ===============================================================================================================
    // Greatest common divisor
    // ===============================================================================================================
    private static gcd(a: BigInteger, b: BigInteger): BigInteger {
        return b.equals(BigInteger.ZERO) ? a : RSA.gcd(b, a.mod(b));
    }

    // ===============================================================================================================
    // Generate prime number
    // ===============================================================================================================
    private static generatePrime(bits: number): BigInteger {
        let prime;
        do {
            prime = new BigInteger(bits, 1, RSA.getRandom());
        } while (!prime.isProbablePrime(10));
        return prime;
    }

    // ===============================================================================================================
    // Random number generator
    // ===============================================================================================================
    private static getRandom(): any {
        return {
            nextBytes: (bytes: number[]) => {
                for (let i = 0; i < bytes.length; i++) {
                    bytes[i] = Math.floor(Math.random() * 256);
                }
            }
        };
    }
}
