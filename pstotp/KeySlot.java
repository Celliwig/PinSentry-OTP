/*
 * Basic class to encompasses a single OTP key
 */

package pstotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KeySlot {
	public static final short MAX_KEY_SIZE_BYTES = (short) 64;

	private byte[] key = null;
	private short keysize;

	public KeySlot() {
		key = new byte[MAX_KEY_SIZE_BYTES];
		keysize = (short) 0;
	}

	public byte[] getKey() {
		return key;
	}

	public short getKeySize() {
		return keysize;
	}

	public boolean update(byte[] keyData, short keyOffset, short keySize) {
		// Check if key data is larger than slot size
		if (keySize >= KeySlot.MAX_KEY_SIZE_BYTES) return false;

		// Copy key data to slot
		for (short i = 0; i < KeySlot.MAX_KEY_SIZE_BYTES; i++) {
			key[i] = keyData[(short) (i + keyOffset)];
		}

		return true;
	}
}
