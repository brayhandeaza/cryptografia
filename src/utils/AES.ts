import CryptoJS from "crypto-js";

export class AES {
    static generateKey = (): string => {
        try {
            const left = CryptoJS.SHA256(Date.now().toString()).toString()
            const right = CryptoJS.SHA1(Date.now().toString()).toString()

            return `${left}${right}`

        } catch (error) {
            throw error
        }
    }
    static generateKeyAsync = async (): Promise<string> => {
        try {
            const left = CryptoJS.SHA256(Date.now().toString()).toString()
            const right = CryptoJS.SHA1(Date.now().toString()).toString()

            return Promise.resolve(`${left}${right}`)

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // Encrypt 
    static encrypt = (message: string, key: string): string => {
        try {
            const keyWordArray = CryptoJS.enc.Utf8.parse(key);
            const encrypted = CryptoJS.AES.encrypt(message, keyWordArray, {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: keyWordArray
            });

            return encrypted.toString();

        } catch (error) {
            throw error
        }
    }
    static encryptAsync = async (message: string, key: string): Promise<string> => {
        try {
            const keyWordArray = CryptoJS.enc.Utf8.parse(key);
            const encrypted = CryptoJS.AES.encrypt(message, keyWordArray, {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: keyWordArray
            });

            return Promise.resolve(encrypted.toString());

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // Decrypt
    static decrypt = (message: string, key: string): string => {
        try {
            const keyWordArray = CryptoJS.enc.Utf8.parse(key);
            const decrypted = CryptoJS.AES.decrypt(message, keyWordArray, {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: keyWordArray
            });
            return decrypted.toString(CryptoJS.enc.Utf8);

        } catch (error) {
            throw error
        }
    }
    static decryptAsync = async (message: string, key: string): Promise<string> => {
        try {
            const keyWordArray = CryptoJS.enc.Utf8.parse(key);
            const decrypted = CryptoJS.AES.decrypt(message, keyWordArray, {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: keyWordArray
            });
            return Promise.resolve(decrypted.toString(CryptoJS.enc.Utf8));

        } catch (error) {
            return Promise.reject(error)
        }
    }
}