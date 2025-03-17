import CryptoJS from "crypto-js";

export const AES = {
    encrypt: (message: string, key: string) => CryptoJS.AES.encrypt(message, key),
    decrypt: (message: string, key: string) => CryptoJS.AES.decrypt(message, key),

    encryptAsync: async (message: string, key: string) => {
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
    },
    decryptAsync: async (message: string, key: string) => {
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