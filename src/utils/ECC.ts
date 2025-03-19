import CryptoJS from "crypto-js";
import elliptic from "elliptic"


const EC = elliptic.ec;
const ec = new EC("secp256k1");


export class ECC {
    // private static ec = new elliptic.ec("secp256k1");

    // Generate EC key pair
    static async generateKeyPairs(): Promise<{ publicKey: string; privateKey: string }> {
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
    static encrypt(message: string, publicKeyHex: string): Promise<string> {
        try {
            const key = ec.keyFromPublic(publicKeyHex, "hex");
            const ephemeralKeyPair = ec.genKeyPair();
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

            const privateKey = ec.keyFromPrivate(privateKeyHex, "hex");
            const ephemeralPublicKey = ec.keyFromPublic(ephemeralPublicKeyHex, "hex");
            const sharedSecret = privateKey.derive(ephemeralPublicKey.getPublic());

            const aesKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString(CryptoJS.enc.Hex).substring(0, 32);
            return Promise.resolve(ECC.AESDecrypt(encryptedMessage, aesKey));

        } catch (error) {
            return Promise.reject(error);
        }
    }

    static sign = async (data: string, privateKey: string): Promise<string> => {
        try {
            const key = ec.keyFromPrivate(privateKey, 'hex');
            const signature = key.sign(data, { canonical: true });

            return Promise.resolve(signature.toDER('hex'));
        } catch (error) {
            return Promise.reject(error);
        }
    };

    static verify = async (data: string, signature: string, publicKey: string): Promise<boolean> => {
        try {
            const key = ec.keyFromPublic(publicKey, 'hex');
            const verified = key.verify(data, signature);

            return Promise.resolve(verified);
        } catch (error) {
            return Promise.reject(error);
        }
    };

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

