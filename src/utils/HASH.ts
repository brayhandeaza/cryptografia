import CryptoJS from 'crypto-js';

export const HASH = {
    // Hash functions
    sha1: (message: string) => CryptoJS.SHA1(message).toString(),
    sha3: (message: string, length: number = 256) => CryptoJS.SHA3(message, { outputLength: length }).toString(),
    sha224: (message: string) => CryptoJS.SHA224(message).toString(),
    sha256: (message: string) => CryptoJS.SHA256(message).toString(),
    sha384: (message: string) => CryptoJS.SHA384(message).toString(),
    sha512: (message: string) => CryptoJS.SHA512(message).toString(),
    md5: (message: string) => CryptoJS.MD5(message).toString(),

    // Hash asyncronouslly functions
    sha1Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.SHA1(message).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },
    sha3Async: async (message: string, length: number = 256): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.SHA3(message, { outputLength: length }).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },
    sha224Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.SHA224(message).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },
    sha256Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.SHA256(message).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },
    sha384Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.SHA384(message).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },
    sha512Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.SHA512(message).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },
    md5Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.MD5(message).toString())
        } catch (error) {
            return Promise.reject(error)
        }
    },

    // encoder functions
    base64ToString: (base64: string) => CryptoJS.enc.Base64.parse(base64).toString(CryptoJS.enc.Utf8),
    stringToBase64: (message: string) => CryptoJS.enc.Utf8.parse(message).toString(CryptoJS.enc.Base64),
    base64ToHex: (base64: string) => CryptoJS.enc.Base64.parse(base64).toString(CryptoJS.enc.Hex),
    hexToBase64: (hex: string) => CryptoJS.enc.Hex.parse(hex).toString(CryptoJS.enc.Base64),
    stringToHex: (message: string) => CryptoJS.enc.Utf8.parse(message).toString(CryptoJS.enc.Hex),
    hexToString: (hex: string) => CryptoJS.enc.Hex.parse(hex).toString(CryptoJS.enc.Utf8),

    // encoder asyncronouslly functions
    base64ToStringAsync: async (base64: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.enc.Base64.parse(base64).toString(CryptoJS.enc.Utf8))
        } catch (error) {
            return Promise.reject(error)
        }
    },
    stringToBase64Async: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.enc.Utf8.parse(message).toString(CryptoJS.enc.Base64))
        } catch (error) {
            return Promise.reject(error)
        }
    },
    base64ToHexAsync: async (base64: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.enc.Base64.parse(base64).toString(CryptoJS.enc.Hex))
        } catch (error) {
            return Promise.reject(error)
        }
    },
    hexToBase64Async: async (hex: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.enc.Hex.parse(hex).toString(CryptoJS.enc.Base64))
        } catch (error) {
            return Promise.reject(error)
        }
    },
    stringToHexAsync: async (message: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.enc.Utf8.parse(message).toString(CryptoJS.enc.Hex))
        } catch (error) {
            return Promise.reject(error)
        }
    },
    hexToStringAsync: async (hex: string): Promise<string> => {
        try {
            return Promise.resolve(CryptoJS.enc.Hex.parse(hex).toString(CryptoJS.enc.Utf8))
        } catch (error) {
            return Promise.reject(error)
        }
    }
}


// sha1,
// sha3,
// sha224,
// sha256,
// sha384,
// sha512,
// md5,

// sha1Async,
// sha3Async,
// sha224Async,
// sha256Async,
// sha384Async,
// sha512Async,
// md5Async,

// base64ToString,
// stringToBase64,
// base64ToHex,
// hexToBase64,
// stringToHex,
// hexToString,

// base64ToStringAsync,
// stringToBase64Async,
// base64ToHexAsync,
// hexToBase64Async,
// stringToHexAsync,
// hexToStringAsync,
