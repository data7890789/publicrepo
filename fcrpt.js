/**
 * @returns {Object} .
 */
const xabe0 = () => {
    // Helper functions
    // created https://www.html-code-generator.com/javascript/data-encryption-decryption-with-password
    /**
     * Converts an ArrayBuffer to a hexadecimal string.
     * @param {ArrayBuffer} buffer - The buffer to convert.
     * @returns {string} The hexadecimal representation of the buffer.
     */
    const arrayBufferToHex = (buffer) =>
        Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

    /**
     * Converts a hexadecimal string to a Uint8Array.
     * @param {string} hexString - The hexadecimal string to convert.
     * @returns {Uint8Array} The resulting Uint8Array.
     */
    const hexToUint8Array = (hexString) =>
        new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    /**
     * Derives a cryptographic key from a password using PBKDF2.
     * @param {string} password - The password to derive the key from.
     * @param {Uint8Array} salt - The salt for key derivation.
     * @param {string[]} keyUsage - The intended usage of the key (e.g., ["encrypt"] or ["decrypt"]).
     * @returns {Promise<CryptoKey>} A promise that resolves to the derived key.
     */
    const deriveKey = async (password, salt, keyUsage) => {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password), {
                name: "PBKDF2"
            },
            false,
            ["deriveBits", "deriveKey"]
        );
        return window.crypto.subtle.deriveKey({
                name: "PBKDF2",
                salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial, {
                name: "AES-GCM",
                length: 256
            },
            false,
            keyUsage
        );
    };


    /**
     * Decrypts the given encrypted data using AES-GCM decryption.
     * @param {string} encryptedText - The encrypted data as a hexadecimal string.
     * @param {string|number} password - The password to use for decryption.
     * @returns {Promise<any>} A promise that resolves to the decrypted data. If the original data was JSON, it will be parsed.
     * @throws {Error} If the encrypted text or password is invalid.
     */
    const d8e2b1 = async (encryptedText, password) => {
        if (typeof encryptedText !== "string") {
            throw new Error("encryptedText must be a string");
        }
   
        const data = hexToUint8Array(encryptedText);
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const encryptedContent = data.slice(28);
        const key = await deriveKey(password.toString(), salt, ["decrypt"]);
        const decryptedData = await window.crypto.subtle.decrypt({
                name: "AES-GCM",
                iv
            },
            key,
            encryptedContent
        );
        const dec = new TextDecoder();
        const decryptedString = dec.decode(decryptedData);
       
        // console.log(atob(decryptedString));
            document.write(atob(decryptedString));
       
    
    };
    return {
     
        d8e2b1: d8e2b1    //dec
    };
};
