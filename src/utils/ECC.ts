import CryptoJS from "crypto-js";
import elliptic from "elliptic"


export class ECC {
    private static ec = new elliptic.ec("secp256k1");

    // Generate EC key pair
    static async generateKeyPairs(): Promise<{ publicKey: string; privateKey: string }> {
        try {
            const keyPair = ECC.ec.genKeyPair();
            return Promise.resolve({
                publicKey: keyPair.getPublic("hex"),
                privateKey: keyPair.getPrivate("hex"),
            })

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // Encrypt using ECIES
    static encrypt(message: string, publicKeyHex: string): Promise<string> {
        try {
            const key = ECC.ec.keyFromPublic(publicKeyHex, "hex");
            const ephemeralKeyPair = ECC.ec.genKeyPair();
            const sharedSecret = ephemeralKeyPair.derive(key.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            const encryptedMessage = ECC.AESEncrypt(message, aesKey);

            return Promise.resolve(`${ephemeralKeyPair.getPublic("hex")}.${encryptedMessage}`);
        } catch (error) {
            return Promise.reject(error);
        }
    }

    // Decrypt using ECIES
    static decrypt(cipherText: string, privateKeyHex: string): Promise<string> {
        try {
            const [ephemeralPublicKeyHex, encryptedMessage] = cipherText.split(".");
            if (!ephemeralPublicKeyHex || !encryptedMessage) throw new Error("Invalid encrypted format");

            const privateKey = ECC.ec.keyFromPrivate(privateKeyHex, "hex");
            const ephemeralPublicKey = ECC.ec.keyFromPublic(ephemeralPublicKeyHex, "hex");
            const sharedSecret = privateKey.derive(ephemeralPublicKey.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            return Promise.resolve(ECC.AESDecrypt(encryptedMessage, aesKey));
            
        } catch (error) {
            return Promise.reject(error);
        }
    }

    // AES Encryption
    private static AESEncrypt(plainText: string, aesKey: string): string {
        const keyWordArray = CryptoJS.enc.Hex.parse(aesKey);
        const encrypted = CryptoJS.AES.encrypt(plainText, keyWordArray, {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: keyWordArray,
        });
        return encrypted.toString();
    }

    // AES Decryption
    private static AESDecrypt(cipherText: string, aesKey: string): string {
        const keyWordArray = CryptoJS.enc.Hex.parse(aesKey);
        const decrypted = CryptoJS.AES.decrypt(cipherText, keyWordArray, {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: keyWordArray,
        });
        return decrypted.toString(CryptoJS.enc.Utf8);
    }
}

