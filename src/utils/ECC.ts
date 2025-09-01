import CryptoJS from "crypto-js";
import elliptic from "elliptic"
import { KeyPair } from "../types";
import { AES } from "./AES";


const EC = elliptic.ec;
const ec = new EC("secp256k1");


export class ECC {
    // private static ec = new elliptic.ec("secp256k1");

    // Generate EC key pair
    static generateKeyPairs(): KeyPair {
        try {
            const keyPair = ec.genKeyPair();
            return {
                publicKey: keyPair.getPublic("hex"),
                privateKey: keyPair.getPrivate("hex"),
            }

        } catch (error) {
            throw error
        }
    }
    static async generateKeysAsync(): Promise<KeyPair> {
        try {
            const keyPair = ec.genKeyPair();
            return Promise.resolve({
                publicKey: keyPair.getPublic("hex"),
                privateKey: keyPair.getPrivate("hex"),
            })

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // Encrypt using ECIES
    static encrypt(message: string, publicKeyHex: string): string {
        try {
            const key = ec.keyFromPublic(publicKeyHex, "hex");
            const ephemeralKeyPair = ec.genKeyPair();
            const sharedSecret = ephemeralKeyPair.derive(key.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            const encryptedMessage = AES.encrypt(message, aesKey);

            return `${ephemeralKeyPair.getPublic("hex")}.${encryptedMessage}`
        } catch (error) {
            throw error
        }
    }
    static async encryptAsync(message: string, publicKeyHex: string): Promise<string> {
        try {
            const key = ec.keyFromPublic(publicKeyHex, "hex");
            const ephemeralKeyPair = ec.genKeyPair();
            const sharedSecret = ephemeralKeyPair.derive(key.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            const encryptedMessage = await AES.encryptAsync(message, aesKey);

            return Promise.resolve(`${ephemeralKeyPair.getPublic("hex")}.${encryptedMessage}`);
        } catch (error) {
            return Promise.reject(error);
        }
    }

    // Decrypt using ECIES
    static decrypt(cipherText: string, privateKeyHex: string): string {
        try {
            const [ephemeralPublicKeyHex, encryptedMessage] = cipherText.split(".");
            if (!ephemeralPublicKeyHex || !encryptedMessage) throw new Error("Invalid encrypted format");

            const privateKey = ec.keyFromPrivate(privateKeyHex, "hex");
            const ephemeralPublicKey = ec.keyFromPublic(ephemeralPublicKeyHex, "hex");
            const sharedSecret = privateKey.derive(ephemeralPublicKey.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            return AES.decrypt(encryptedMessage, aesKey);

        } catch (error) {
            throw error
        }
    }
    static async decryptAsync(cipherText: string, privateKeyHex: string): Promise<string> {
        try {
            const [ephemeralPublicKeyHex, encryptedMessage] = cipherText.split(".");
            if (!ephemeralPublicKeyHex || !encryptedMessage) throw new Error("Invalid encrypted format");

            const privateKey = ec.keyFromPrivate(privateKeyHex, "hex");
            const ephemeralPublicKey = ec.keyFromPublic(ephemeralPublicKeyHex, "hex");
            const sharedSecret = privateKey.derive(ephemeralPublicKey.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            return Promise.resolve(AES.decrypt(encryptedMessage, aesKey));

        } catch (error) {
            return Promise.reject(error);
        }
    }

    static sign = (data: string, privateKey: string): string => {
        try {
            const key = ec.keyFromPrivate(privateKey, 'hex');
            const signature = key.sign(data, { canonical: true });

            return signature.toDER('hex');
        } catch (error) {
            throw error
        }
    };
    static signAsync = async (data: string, privateKey: string): Promise<string> => {
        try {
            const key = ec.keyFromPrivate(privateKey, 'hex');
            const signature = key.sign(data, { canonical: true });

            return Promise.resolve(signature.toDER('hex'));
        } catch (error) {
            return Promise.reject(error);
        }
    };

    static verify = (data: string, signature: string, publicKey: string): boolean => {
        try {
            const key = ec.keyFromPublic(publicKey, 'hex');
            const verified = key.verify(data, signature);

            return verified;
        } catch (error) {
            throw error
        }
    };
    static verifyAsync = async (data: string, signature: string, publicKey: string): Promise<boolean> => {
        try {
            const key = ec.keyFromPublic(publicKey, 'hex');
            const verified = key.verify(data, signature);

            return Promise.resolve(verified);
        } catch (error) {
            return Promise.reject(error);
        }
    };

}

