/*
 * Class for key store & encryption.
 */

package psotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class KeyStore {
	public static final short NUM_KEY_SLOTS = (short) 512;						// Number of key slots to create
	public static final short HMAC_BUFFER_SIZE_BYTES = (short) 128;					// Size of buffer used to generate HMAC digest
	public static final short CARDID_SIZE_BYTES = 16;						// CardID size in bytes

	public static final byte ACCESS_PIN_LEN = 4;
	public static final byte ACCESS_PIN_LEN_BYTES = ACCESS_PIN_LEN/2;

	private static KeySlot[] keys;									// OTP key store
	private static byte[] ipad = null;								// HMAC inner padding
	private static byte[] opad = null;								// HMAC outer padding
	private static byte[] hmacBuf = null;
	private static RandomData rng_alg = null;							// Random Number Generator
	private static MessageDigest sha1 = null;							// SHA1 methods
	protected static OwnerPIN AccessPIN;
	private static byte[] cardID = null;								// Unique ID used to 'auth' transactions
	private static short selectedSlot = 0;

	public KeyStore() {
		if (cardID == null) {
			ipad = JCSystem.makeTransientByteArray(KeySlot.MAX_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);
			opad = JCSystem.makeTransientByteArray(KeySlot.MAX_KEY_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);
			hmacBuf = JCSystem.makeTransientByteArray(HMAC_BUFFER_SIZE_BYTES, JCSystem.CLEAR_ON_DESELECT);

			rng_alg = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

			keys = new KeySlot[KeyStore.NUM_KEY_SLOTS];
			for (short i = 0; i < KeyStore.NUM_KEY_SLOTS; i++) {
				keys[i] = new KeySlot();
				// Initialise key slot with random data
				//rng_alg.generateData(keys[i].key, (short) 0, KeySlot.MAX_KEY_SIZE_BYTES);
			}

			sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

			AccessPIN = new OwnerPIN((byte) 3, ACCESS_PIN_LEN_BYTES);
			AccessPIN.update(new byte[] { 0x12, 0x34 }, (short) 0, ACCESS_PIN_LEN_BYTES);

			// Create a unique ID for the card
			cardID = new byte[KeyStore.CARDID_SIZE_BYTES];
			rng_alg.generateData(cardID, (short) 0, KeyStore.CARDID_SIZE_BYTES);
		}
	}

//////////////////////////////////////////////////////////////////////////////////////////
//					Card Methods					//
//////////////////////////////////////////////////////////////////////////////////////////
// Display card info
	public short getCardInfo(byte[] outBuffer, short outOffset) {
		short retVal = 0;

		// Copy card ID to output
		outBuffer[(short) (outOffset+retVal)] = (byte) KeyStore.CARDID_SIZE_BYTES;
		retVal += 1;
		Util.arrayCopyNonAtomic(cardID, (short) 0, outBuffer, (short) (outOffset+retVal), KeyStore.CARDID_SIZE_BYTES);
		retVal += KeyStore.CARDID_SIZE_BYTES;

		// Copy number of key slots to output
		Util.setShort(outBuffer, (short) (outOffset+retVal), KeyStore.NUM_KEY_SLOTS);
		retVal += 2;

		return retVal;
	}

// Check action has valid hash
	public boolean checkHash(byte[] data, short dataOffset, short dataLength, byte[] hash, short hashOffset, short hashLength) {
		short newHashLen;

		// Check if this will overrun buffer
		if (((short) (dataLength + KeyStore.CARDID_SIZE_BYTES)) >= KeyStore.HMAC_BUFFER_SIZE_BYTES) return false;

		// Concat data
		Util.arrayCopyNonAtomic(data, dataOffset, hmacBuf, (short) 0, dataLength);
		Util.arrayCopyNonAtomic(cardID, (short) 0, hmacBuf, dataLength, KeyStore.CARDID_SIZE_BYTES);

		// Generate hash
		newHashLen = sha1Hash(hmacBuf, (short) 0, (short) (dataLength + KeyStore.CARDID_SIZE_BYTES), hmacBuf, (short) 0);

		// Compare hash values
		if (newHashLen != hashLength) return false;
		if (Util.arrayCompare(hmacBuf, (short) 0, hash, hashOffset, newHashLen) == 0) return true;
		return false;
	}

// Update a particular key slot with new key data after checking the SHA1 hash of the key
	public boolean updateSlot(short slotNum, byte[] keyData, short keyOffset, short keyLength, byte[] counterData, short counterOffset, short counterLength) {
		boolean rtn;

		// Check key data size
		if ((keyLength < 1) || (keyLength > KeySlot.MAX_KEY_SIZE_BYTES)) return false;

		// Check slot number valid
		if ((slotNum < 0) || (slotNum >= KeyStore.NUM_KEY_SLOTS)) return false;

		rtn = keys[slotNum].update(keyData, keyOffset, keyLength);
		if (counterLength > 0) {
			keys[slotNum].setCounter(counterData, counterOffset, counterLength);
		} else {
			keys[slotNum].resetCounter();
		}
		return rtn;
	}

// Set the slot to use for OTP operations
	public boolean setSlot(short slotNum) {
		if (slotNum >= KeyStore.NUM_KEY_SLOTS) return false;
		selectedSlot = slotNum;
		return true;
	}

// Generate OTP response for the supplied data
	public void getOTPResponse(byte[] data, short dataOffset, short dataLength, byte[] outBuffer, short outOffset) {
		byte dataCheck = 0;

		// Get key slot
		KeySlot optKey = keys[selectedSlot];

		// Check if any data passed through
		for (byte i = 0; i < dataLength; i++) {
			dataCheck |= data[i];
		}
		// If no data passed through, and data buffer larger enough for counter
		if ((dataCheck == 0) && (dataLength >= KeySlot.COUNTER_SIZE_BYTES)) {
			// Use counter instead
			dataLength = optKey.getCounter(data, dataOffset, KeySlot.COUNTER_SIZE_BYTES);
		}

		sha1HMACOTP(optKey.getKey(), (short) 0, optKey.getKeySize(), data, dataOffset, dataLength, outBuffer, outOffset);
	}

// Return the current counter value for given slot
	public short getCounterValue(short slotNum, byte[] outBuffer, short outOffset, short outLength) {
		return keys[slotNum].getCounter(outBuffer, outOffset, outLength);
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
		short hashLen;

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
		hashLen = sha1.doFinal(hmacBuf, (short) 0, (short) (KeySlot.MAX_KEY_SIZE_BYTES + dataLength), hmacBuf, KeySlot.MAX_KEY_SIZE_BYTES);

		// Outer
		Util.arrayCopyNonAtomic(opad, (short) 0, hmacBuf, (short) 0, KeySlot.MAX_KEY_SIZE_BYTES);

		sha1.reset();
		hashLen = sha1.doFinal(hmacBuf, (short) 0, (short) (64 + hashLen), outBuffer, outOffset);

		return hashLen;
	}

// Use the SHA1 algo to create an HMAC based OTP value for the supplied key/data pair
	public short sha1HMACOTP(byte[] key, short keyOffset, short keyLength, byte[] data, short dataOffset, short dataLength, byte[] outBuffer, short outOffset) {
		byte offset, compVal;
		short hashLen;
		short otpResponse0, otpResponse1, otpResponse2, otpResponse3;
		short otpDivisor0, otpDivisor1, otpDivisor2, otpDivisor3;

		// Generate SHA1 HMAC
		hashLen = sha1HMAC(key, keyOffset, keyLength, data, dataOffset, dataLength, hmacBuf, (short) 0);

		// Get offset
		offset = (byte) (hmacBuf[(short) (hashLen - 1)] & 0x0f);
		// Drop most significant bit
		hmacBuf[offset] = (byte) (hmacBuf[offset] & 0x7f);

		// Copy 4 required bytes from HMAC
		otpResponse0 = (short) (hmacBuf[offset] & 0xff);					// MSB
		otpResponse1 = (short) (hmacBuf[(short) (offset + 1)] & 0xff);
		otpResponse2 = (short) (hmacBuf[(short) (offset + 2)] & 0xff);
		otpResponse3 = (short) (hmacBuf[(short) (offset + 3)] & 0xff);				// LSB

		// Create divisor for 6 digit OTPs
		otpDivisor0 = 0x0000;									// MSB
		otpDivisor1 = 0x000f;
		otpDivisor2 = 0x0042;
		otpDivisor3 = 0x0040;									// LSB

		// Need to perform otpResponse modulo otpDivisor
		while (true) {
			// Compare otpResponse and otpDivisor, specifically checking for otpResponse < otpDivisor
			compVal = 0;
			if (otpResponse0 > otpDivisor0) compVal += 8;
			if (otpResponse0 < otpDivisor0) compVal -= 8;
			if (otpResponse1 > otpDivisor1) compVal += 4;
			if (otpResponse1 < otpDivisor1) compVal -= 4;
			if (otpResponse2 > otpDivisor2) compVal += 2;
			if (otpResponse2 < otpDivisor2) compVal -= 2;
			if (otpResponse3 > otpDivisor3) compVal += 1;
			if (otpResponse3 < otpDivisor3) compVal -= 1;
			if (compVal < 0) break;

			// Subtract otpDivisor from otpResponse
			otpResponse3 = (short)  (otpResponse3 - otpDivisor3);
			// Check for 'rollunder'
			if (otpResponse3 < 0) {
				otpResponse3 = (short) (otpResponse3 + 0x100);
				otpResponse2--;
			}
			otpResponse2 = (short) (otpResponse2 - otpDivisor2);
			// Check for 'rollunder'
			if (otpResponse2 < 0) {
				otpResponse2 = (short) (otpResponse2 + 0x100);
				otpResponse1--;
			}
			otpResponse1 = (short) (otpResponse1 - otpDivisor1);
			// Check for 'rollunder'
			if (otpResponse1 < 0) {
				otpResponse1 = (short) (otpResponse1 + 0x100);
				otpResponse0--;
			}
			otpResponse0 = (short) (otpResponse0 - otpDivisor0);
			// Check for 'rollunder' (this shouldn't happen)
			if (otpResponse0 < 0) break;
		}

		// Copy result to output buffer
		outBuffer[outOffset] = (byte) (otpResponse0 & 0xff);
		outBuffer[(short) (outOffset + 1)] = (byte) (otpResponse1 & 0xff);
		outBuffer[(short) (outOffset + 2)] = (byte) (otpResponse2 & 0xff);
		outBuffer[(short) (outOffset + 3)] = (byte) (otpResponse3 & 0xff);

		return (short) 4;
	}
}
