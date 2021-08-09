/*
 * Basic class to encompasses a single OTP key
 */

package psotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class KeySlot {
	public static final short MAX_KEY_SIZE_BYTES = (short) 64;
	public static final short COUNTER_SIZE_BYTES = (short) 8;

	private byte[] slotKey = null;
	private short slotKeySize;
	private byte[] slotCounter = null;

	public KeySlot() {
		slotKey = new byte[MAX_KEY_SIZE_BYTES];
		slotKeySize = (short) 0;
		slotCounter = new byte[COUNTER_SIZE_BYTES];
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
		boolean counterCarry;
		short counterDigit;

		// Check size of output buffer
		if (outLength <= 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (outLength > COUNTER_SIZE_BYTES) outLength = COUNTER_SIZE_BYTES;

		// Copy counter to buffer
		Util.arrayCopyNonAtomic(slotCounter, (short) 0, out, outOffset, outLength);

		// Clear carry
		counterCarry = false;
		// Increment LSB
		counterDigit = (short) (slotCounter[7] & 0x00ff);
		counterDigit++;
		// Handle byte rollover
		if (counterDigit > 0x00ff) {
			counterDigit = 0x0000;
			counterCarry = true;
		}
		// Write byte back
		slotCounter[7] = (byte) (counterDigit & 0x00ff);
		// Handle carry
		if (counterCarry) {
			// Clear carry
			counterCarry = false;
			// Increment LSB + 1
			counterDigit = (short) (slotCounter[6] & 0x00ff);
			counterDigit++;
			// Handle byte rollover
			if (counterDigit > 0x00ff) {
				counterDigit = 0x0000;
				counterCarry = true;
			}
			// Write byte back
			slotCounter[6] = (byte) (counterDigit & 0x00ff);
			// Handle carry
			if (counterCarry) {
				// Clear carry
				counterCarry = false;
				// Increment LSB + 2
				counterDigit = (short) (slotCounter[5] & 0x00ff);
				counterDigit++;
				// Handle byte rollover
				if (counterDigit > 0x00ff) {
					counterDigit = 0x0000;
					counterCarry = true;
				}
				// Write byte back
				slotCounter[5] = (byte) (counterDigit & 0x00ff);
				// Handle carry
				if (counterCarry) {
					// Clear carry
					counterCarry = false;
					// Increment LSB + 3
					counterDigit = (short) (slotCounter[4] & 0x00ff);
					counterDigit++;
					// Handle byte rollover
					if (counterDigit > 0x00ff) {
						counterDigit = 0x0000;
						counterCarry = true;
					}
					// Write byte back
					slotCounter[4] = (byte) (counterDigit & 0x00ff);
					// Handle carry
					if (counterCarry) {
						// Clear carry
						counterCarry = false;
						// Increment LSB + 4
						counterDigit = (short) (slotCounter[3] & 0x00ff);
						counterDigit++;
						// Handle byte rollover
						if (counterDigit > 0x00ff) {
							counterDigit = 0x0000;
							counterCarry = true;
						}
						// Write byte back
						slotCounter[3] = (byte) (counterDigit & 0x00ff);
						// Handle carry
						if (counterCarry) {
							// Clear carry
							counterCarry = false;
							// Increment LSB + 5
							counterDigit = (short) (slotCounter[2] & 0x00ff);
							counterDigit++;
							// Handle byte rollover
							if (counterDigit > 0x00ff) {
								counterDigit = 0x0000;
								counterCarry = true;
							}
							// Write byte back
							slotCounter[2] = (byte) (counterDigit & 0x00ff);
							// Handle carry
							if (counterCarry) {
								// Clear carry
								counterCarry = false;
								// Increment LSB + 6
								counterDigit = (short) (slotCounter[1] & 0x00ff);
								counterDigit++;
								// Handle byte rollover
								if (counterDigit > 0x00ff) {
									counterDigit = 0x0000;
									counterCarry = true;
								}
								// Write byte back
								slotCounter[1] = (byte) (counterDigit & 0x00ff);
								// Handle carry
								if (counterCarry) {
									// Clear carry
									counterCarry = false;
									// Increment LSB + 7
									counterDigit = (short) (slotCounter[0] & 0x00ff);
									counterDigit++;
									// Handle byte rollover
									if (counterDigit > 0x00ff) {
										counterDigit = 0x0000;
										counterCarry = true;
									}
									// Write byte back
									slotCounter[0] = (byte) (counterDigit & 0x00ff);
									// Ignore carry
								}
							}
						}
					}
				}
			}
		}

		return COUNTER_SIZE_BYTES;
	}

	// Updates the slot with a new key
	// Resets the slot counter
	public boolean update(byte[] keyData, short keyOffset, short keySize) {
		// Check if key data is larger than slot size
		if (keySize > KeySlot.MAX_KEY_SIZE_BYTES) return false;

		// Copy key data to slot
		Util.arrayCopyNonAtomic(keyData, keyOffset, slotKey, (short) 0, keySize);
		slotKeySize = keySize;

		// Reset slot counter
		slotCounter[0] = 0x00;
		slotCounter[1] = 0x00;
		slotCounter[2] = 0x00;
		slotCounter[3] = 0x00;
		slotCounter[4] = 0x00;
		slotCounter[5] = 0x00;
		slotCounter[6] = 0x00;
		slotCounter[7] = 0x00;

		return true;
	}
}
