/*
 * Basic class to encompasses a single OTP key
 */

package psotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KeySlot {
	public static final short MAX_KEY_SIZE_BYTES = (short) 64;
	public static final short COUNTER_SIZE_BYTES = (short) 8;

	private byte[] slotKey = null;
	private short slotKeySize;
	private short[] slotCounter = null;

	public KeySlot() {
		slotKey = new byte[MAX_KEY_SIZE_BYTES];
		slotKeySize = (short) 0;
		slotCounter = new short[COUNTER_SIZE_BYTES];
	}

	// Byte array containg the key
	// (Array can be larger than the key)
	public byte[] getKey() {
		return slotKey;
	}

	// Returns the size (in bytes) of the key
	public short getKeySize() {
		return slotKeySize;
	}

	// Write the contents of the slot counter into byte buffer
	// (which must be at a minimum COUNTER_SIZE_BYTES wide)
	// And increment counter
	public short getCounter(byte[] out, short outOffset, short outLength) {
		byte i;

		// Check size of output buffer
		if (outLength <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (outLength > COUNTER_SIZE_BYTES) outLength = COUNTER_SIZE_BYTES;

		// Copy counter to buffer
		for (i = 0; i < outLength; i++) {
			out[(short) (outOffset + i)] = (byte) (slotCounter[i] & 0x00ff);
		}

		// Increment counter
		slotCounter[7]++;
		if (slotCounter[7] > 0x00ff) {
			slotCounter[7] = 0x0000;
			slotCounter[6]++;
		}
		if (slotCounter[6] > 0x00ff) {
			slotCounter[6] = 0x0000;
			slotCounter[5]++;
		}
		if (slotCounter[5] > 0x00ff) {
			slotCounter[5] = 0x0000;
			slotCounter[4]++;
		}
		if (slotCounter[4] > 0x00ff) {
			slotCounter[4] = 0x0000;
			slotCounter[3]++;
		}
		if (slotCounter[3] > 0x00ff) {
			slotCounter[3] = 0x0000;
			slotCounter[2]++;
		}
		if (slotCounter[2] > 0x00ff) {
			slotCounter[2] = 0x0000;
			slotCounter[1]++;
		}
		if (slotCounter[1] > 0x00ff) {
			slotCounter[1] = 0x0000;
			slotCounter[0]++;
		}
		if (slotCounter[0] > 0x00ff) {
			slotCounter[0] = 0x0000;
		}

		return COUNTER_SIZE_BYTES;
	}

	// Updates the slot with a new key
	// Resets the slot counter
	public boolean update(byte[] keyData, short keyOffset, short keySize) {
		// Check if key data is larger than slot size
		if (keySize >= KeySlot.MAX_KEY_SIZE_BYTES) return false;

		// Copy key data to slot
		for (short i = 0; i < keySize; i++) {
			slotKey[i] = keyData[(short) (i + keyOffset)];
		}
		slotKeySize = keySize;

		// Reset slot counter
		slotCounter[0] = 0x0000;
		slotCounter[1] = 0x0000;
		slotCounter[2] = 0x0000;
		slotCounter[3] = 0x0000;
		slotCounter[4] = 0x0000;
		slotCounter[5] = 0x0000;
		slotCounter[6] = 0x0000;
		slotCounter[7] = 0x0000;

		return true;
	}
}
