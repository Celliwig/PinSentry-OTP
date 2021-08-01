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
		ipad = JCSystem.makeTransientByteArray(KeySlot.MAX_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);
		opad = JCSystem.makeTransientByteArray(KeySlot.MAX_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);
		hmacBuf = JCSystem.makeTransientByteArray(HMAC_BUFFER_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);

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

// Use the SHA1 algo to create an HMAC based TOTP value for the supplied key/data pair
	public short sha1HMACTOTP(byte[] key, short keyOffset, short keyLength, byte[] data, short dataOffset, short dataLength, byte[] outBuffer, short outOffset) {
		byte offset, compVal;
		short hash_len;
		short totpResponse[] = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);	// Use shorts to hold byte values (allows for <0)
		short totpDivisor[] = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);	// This is because no integer type available

		// Generate SHA1 HMAC
		hash_len = sha1HMAC(key, keyOffset, keyLength, data, dataOffset, dataLength, hmacBuf, (short) 0);

		// Get offset
		offset = (byte) (hmacBuf[(short) (hash_len - 1)] & 0x0f);
		// Drop most significant bit
		hmacBuf[offset] = (byte) (hmacBuf[offset] & 0x7f);

		// Copy 4 required bytes from HMAC
		totpResponse[0] = (short) (hmacBuf[offset] & 0xff);					// MSB
		totpResponse[1] = (short) (hmacBuf[(short) (offset + 1)] & 0xff);
		totpResponse[2] = (short) (hmacBuf[(short) (offset + 2)] & 0xff);
		totpResponse[3] = (short) (hmacBuf[(short) (offset + 3)] & 0xff);			// LSB

		// Create divisor for 6 digit TOTPs
		totpDivisor[0] = 0x0000;								// MSB
		totpDivisor[1] = 0x000f;
		totpDivisor[2] = 0x0042;
		totpDivisor[3] = 0x0040;								// LSB

		// Need to perform totpResponse modulo totpDivisor
		while (true) {
			// Compare totpResponse and totpDivisor, specifically checking for totpResponse < totpDivisor
			compVal = 0;
			if (totpResponse[0] > totpDivisor[0]) compVal += 8;
			if (totpResponse[0] < totpDivisor[0]) compVal -= 8;
			if (totpResponse[1] > totpDivisor[1]) compVal += 4;
			if (totpResponse[1] < totpDivisor[1]) compVal -= 4;
			if (totpResponse[2] > totpDivisor[2]) compVal += 2;
			if (totpResponse[2] < totpDivisor[2]) compVal -= 2;
			if (totpResponse[3] > totpDivisor[3]) compVal += 1;
			if (totpResponse[3] < totpDivisor[3]) compVal -= 1;
			if (compVal < 0) break;

			// Subtract totpDivisor from totpResponse
			totpResponse[3] = (short)  (totpResponse[3] - totpDivisor[3]);
			// Check for 'rollunder'
			if (totpResponse[3] < 0) {
				totpResponse[3] = (short) (totpResponse[3] + 0x100);
				totpResponse[2]--;
			}
			totpResponse[2] = (short) (totpResponse[2] - totpDivisor[2]);
			// Check for 'rollunder'
			if (totpResponse[2] < 0) {
				totpResponse[2] = (short) (totpResponse[2] + 0x100);
				totpResponse[1]--;
			}
			totpResponse[1] = (short) (totpResponse[1] - totpDivisor[1]);
			// Check for 'rollunder'
			if (totpResponse[1] < 0) {
				totpResponse[1] = (short) (totpResponse[1] + 0x100);
				totpResponse[0]--;
			}
			totpResponse[0] = (short) (totpResponse[0] - totpDivisor[0]);
			// Check for 'rollunder' (this shouldn't happen)
			if (totpResponse[0] < 0) break;
		}

		// Copy result to output buffer
		outBuffer[outOffset] = (byte) (totpResponse[0] & 0xff);
		outBuffer[(short) (outOffset + 1)] = (byte) (totpResponse[1] & 0xff);
		outBuffer[(short) (outOffset + 2)] = (byte) (totpResponse[2] & 0xff);
		outBuffer[(short) (outOffset + 3)] = (byte) (totpResponse[3] & 0xff);

		return (short) 4;
	}
}
