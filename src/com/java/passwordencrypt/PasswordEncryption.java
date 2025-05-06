package com.java.passwordencrypt;

/*
 java.security.Key: This is the interface for keys used in cryptography. We use it to define the key for encryption and decryption.

java.util.Base64: This class is used to encode/decode data in Base64 format. It's commonly used for encoding binary data as a string.

javax.crypto.Cipher: This class is used to perform cryptographic operations such as encryption and decryption.

javax.crypto.spec.SecretKeySpec: This class represents a secret key for symmetric encryption (like AES). It allows you to create a key using byte arrays.

*/

import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PasswordEncryption {

	// ALGO: This is the encryption algorithm. AES (Advanced Encryption Standard) is
	// a symmetric key encryption algorithm used here.
	private static final String ALGO = "AES"; // AES encryption

	// Make sure the key is exactly 16 bytes (128 bits)
	// KEY_STRING: A 16-character string (equal to 16 bytes) that will be used as
	// the encryption key. We use this string as a base to generate the keyValues.
	private static final String KEY_STRING = "MyAESSecret12345"; // 16 characters

	// keyValues: A byte[] (byte array) that will store the key after converting
	// KEY_STRING to bytes.
	private static final byte[] keyValues;

	// Static Initialization Block for Key Setup
	static {
		try {
			keyValues = KEY_STRING.getBytes("UTF-8"); // Ensure consistent byte encoding
			System.out.println("Key length in bytes: " + keyValues.length); // Debug output
		} catch (Exception e) {
			throw new RuntimeException("Failed to initialize key bytes", e);
		}
	}

	// Encrypt M ethod
	public static String encrypt(String data) throws Exception {
		Key key = generateKey(); // henerateKey() - Calls a method to generate the secret key from the keyValues
									// byte array. This key is used in the encryption and decryption processes.
		Cipher c = Cipher.getInstance(ALGO); // Cipher.getInstance(ALGO): Creates a Cipher object that will use the AES
												// algorithm.
		c.init(Cipher.ENCRYPT_MODE, key); // c.init(Cipher.ENCRYPT_MODE, key): Initializes the cipher to perform
											// encryption using the generated key.
		byte[] encVal = c.doFinal(data.getBytes("UTF-8")); // data.getBytes("UTF-8"): Converts the plaintext string
															// (data) into bytes using UTF-8 encoding.
		// c.doFinal(...): This method performs the encryption. It takes the byte array
		// and encrypts it, returning the encrypted byte array.
		return Base64.getEncoder().encodeToString(encVal); // Base64.getEncoder().encodeToString(encVal): This converts
															// the encrypted byte array (encVal) into a
	}

	// Decrypt Method
	public static String decrypt(String encryptedData) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decodedValue = Base64.getDecoder().decode(encryptedData);
		byte[] decValue = c.doFinal(decodedValue);
		return new String(decValue, "UTF-8");
	}

	//Key Generation
	private static Key generateKey() {
		return new SecretKeySpec(keyValues, ALGO);
	}

	//main Method
	public static void main(String[] args) throws Exception {
		String password = "Aishu";
		String passwordEnc = PasswordEncryption.encrypt(password);
		System.out.println("Plain text: " + password + " | Encrypted: " + passwordEnc);

		String passwordDec = PasswordEncryption.decrypt(passwordEnc);
		System.out.println("Decrypted: " + passwordDec);
	}
}
