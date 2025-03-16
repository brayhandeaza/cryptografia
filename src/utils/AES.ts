import CryptoJS from "crypto-js";

export class AES {
    // ===============================================================================================================
    // Generate a random AES key of 'length' bytes
    // ===============================================================================================================
    static generateKey(length: number = 64): string {
        const key = this.randomBytes(length); // Generate a random key of 'length' bytes
        return key.map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // ===============================================================================================================
    // Generate a random AES key of 'length' bytes asynchronously
    // ===============================================================================================================
    static generateKeyAsync(length: number = 64): Promise<string> {
        return new Promise((resolve, reject) => {
            try {
                const key = this.randomBytes(length); // Generate a random key of 'length' bytes
                resolve(key.map(byte => byte.toString(16).padStart(2, '0')).join(''));
            } catch (error) {
                reject(error);
            }
        });
    }

    // ===============================================================================================================
    // Encrypt a text using AES with the given key asynchronously
    // ===============================================================================================================  
    static encryptAsync(text: string, key: string): Promise<string> {
        try {
            const keyWordArray = CryptoJS.enc.Utf8.parse(key);
            const encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: keyWordArray
            });

            return Promise.resolve(encrypted.toString());
        } catch (error) {
            return Promise.reject(error);
        }
    }

    // ===============================================================================================================
    // Decrypt a text using AES with the given key
    // ===============================================================================================================
    static encrypt(text: string, key: string): string {
        const keyWordArray = CryptoJS.enc.Utf8.parse(key);
        const encrypted = CryptoJS.AES.encrypt(text, keyWordArray, {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: keyWordArray
        });

        return encrypted.toString();
    }

    // ===============================================================================================================
    // Decrypt a text using AES with the given key
    // ===============================================================================================================
    static decryptAsync(text: string, key: string): Promise<string> {
        try {
            const keyWordArray = CryptoJS.enc.Utf8.parse(key);
            const decrypted = CryptoJS.AES.decrypt(text, keyWordArray, {
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                iv: keyWordArray
            });

            return Promise.resolve(decrypted.toString(CryptoJS.enc.Utf8));

        } catch (error) {
            return Promise.reject(error)
        }
    }

    // ===============================================================================================================
    // Decrypt a text using AES with the given key
    // ===============================================================================================================
    static decrypt(text: string, key: string): string {
        const keyWordArray = CryptoJS.enc.Utf8.parse(key);
        const decrypted = CryptoJS.AES.decrypt(text, keyWordArray, {
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
            iv: keyWordArray
        });

        return decrypted.toString(CryptoJS.enc.Utf8);
    }

    // ===============================================================================================================
    // Generate an array of 'length' random bytes
    // ===============================================================================================================
    private static randomBytes(length: number): number[] {
        return Array.from({ length }, () => Math.floor(Math.random() * 256));
    }
}
