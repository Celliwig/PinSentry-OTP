/*
 * Class for key store & encryption.
 */

package pstotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class KeyStore {
	//public static final short NUM_KEY_SLOTS = (short) 512;					// Number of key slots to create
	public static final short NUM_KEY_SLOTS = (short) 16;
	public static final short HMAC_BUFFER_SIZE_BYTES = (short) 128;					// Size of buffer used to generate HMAC digest

	private KeySlot[] keys;										// OTP key store
	private byte[] ipad = null;									// HMAC inner padding
	private byte[] opad = null;									// HMAC outer padding
	private byte[] hmacBuf = null;
	private RandomData rng_alg = null;								// Random Number Generator
	private MessageDigest sha1 = null;								// SHA1 methods

	public KeyStore() {
		ipad = JCSystem.makeTransientByteArray(KeySlot.MAX_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_RESET);
		opad = JCSystem.makeTransientByteArray(KeySlot.MAX_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_RESET);
		hmacBuf = JCSystem.makeTransientByteArray(HMAC_BUFFER_SIZE_BYTES, JCSystem.CLEAR_ON_RESET);

		rng_alg = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

		keys = new KeySlot[NUM_KEY_SLOTS];
		for (short i = 0; i < KeyStore.NUM_KEY_SLOTS; i++) {
			keys[i] = new KeySlot();
			// Initialise key slot with random data
			//rng_alg.generateData(keys[i].key,(short) 0, KeySlot.MAX_KEY_SIZE_BYTES);
		}

		sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
	}


//////////////////////////////////////////////////////////////////////////////////////////
//					SHA1 Methods					//
//////////////////////////////////////////////////////////////////////////////////////////
// Use the SHA1 algo to hash input data
	public short sha1Hash(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
		sha1.reset();
		return sha1.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
	}

// Use the SHA1 algo to create an HMAC for the supplied key/data pair
	public short sha1HMAC(byte[] key, short keyOffset, short keyLength, byte[] data, short dataOffset, short dataLength, byte[] outBuffer, short outOffset) {
		short hash_len;

		// If keyLength is greater than maximum KeySlot.MAX_KEY_SIZE_BYTES, SHA1 the key
		if (keyLength > KeySlot.MAX_KEY_SIZE_BYTES) {
			keyLength = sha1Hash(key, keyOffset, keyLength, key, keyOffset);
		}

		// Check if dataLength will overflow HMAC buffer
		if (dataLength > (HMAC_BUFFER_SIZE_BYTES - KeySlot.MAX_KEY_SIZE_BYTES)) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return 0;
		}

		// Initialise ipad/opad
		for (short i = 0; i < KeySlot.MAX_KEY_SIZE_BYTES; i++) {
			// Copy in key data
			if (i < keyLength) {
				ipad[i] = key[(short) (i + keyOffset)];
				opad[i] = key[(short) (i + keyOffset)];
			} else {
				// Zero if key is shorter than max key size
				ipad[i] = 0;
				opad[i] = 0;
			}

			// XOR key data
			ipad[i] ^= 0x36;
			opad[i] ^= 0x5c;
		}

		// Inner
		Util.arrayCopyNonAtomic(ipad, (short) 0, hmacBuf, (short) 0, KeySlot.MAX_KEY_SIZE_BYTES);
		Util.arrayCopyNonAtomic(data, dataOffset, hmacBuf, KeySlot.MAX_KEY_SIZE_BYTES, dataLength);

		sha1.reset();
		hash_len = sha1.doFinal(hmacBuf, (short) 0, (short) (KeySlot.MAX_KEY_SIZE_BYTES + dataLength), hmacBuf, KeySlot.MAX_KEY_SIZE_BYTES);

		// Outer
		Util.arrayCopyNonAtomic(opad, (short) 0, hmacBuf, (short) 0, KeySlot.MAX_KEY_SIZE_BYTES);

		sha1.reset();
		hash_len = sha1.doFinal(hmacBuf, (short) 0, (short) (64 + hash_len), outBuffer, outOffset);

		return hash_len;
	}
}
