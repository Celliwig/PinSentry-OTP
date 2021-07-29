/*
 * Basic class to encompasses a single OTP key
 */

package pstotp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class KeySlot {
	public static final short MAX_KEY_SIZE_BYTES = (short) 64;

	public byte[] key = null;

	public KeySlot() {
		key = new byte[MAX_KEY_SIZE_BYTES];
	}
}
