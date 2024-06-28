function encrypt() {
    const plaintext = document.getElementById('plaintext').value;
    const key = document.getElementById('encryptionKey').value;
    const ciphertext = CryptoJS.AES.encrypt(plaintext, key).toString();
    document.getElementById('ciphertext').value = ciphertext;
}

function decrypt() {
    const ciphertext = document.getElementById('ciphertextToDecrypt').value;
    const key = document.getElementById('decryptionKey').value;
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
    document.getElementById('decryptedText').value = decryptedText;
}
