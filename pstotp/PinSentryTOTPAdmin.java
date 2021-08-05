/*
 * This applet is responsible for key store management.
 *
 *	CLA	INS	P1
 * ---------------------------------------------------------------------
 *	00
 *		01		PIN Funcions
 *			01	Verify Admin PIN
 *			02	Update Admin PIN
 *			03	Update EMV PIN (and reset PIN retry counter)
 *
 *		02		Keystore
 *			01	Get card data
 *			02	Update key store
 *
 *		FF		Test Functions
 *			01	Test SHA1 function
 *			02	Test HMAC-SHA1 function
 *			03	Test HMAC-SHA1 TOTP function
 *			FF	Get counter value of the last slot
 */

package pstotp;

import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class PinSentryTOTPAdmin extends Applet {
	public static final byte INS_PIN = (byte) 0x01;
	public static final byte INS_KEYSTORE = (byte) 0x02;
	public static final byte INS_TEST = (byte) 0xff;

	public static final byte P1_PIN_VERIFY = (byte) 0x01;
	public static final byte P1_PIN_UPDATE = (byte) 0x02;
	public static final byte P1_PIN_UPDATE_EMV = (byte) 0x03;

	public static final byte P1_KEYSTORE_CARDDATA = (byte) 0x01;
	public static final byte P1_KEYSTORE_UPDATE = (byte) 0x02;

	public static final byte P1_TEST_SHA1 = (byte) 0x01;
	public static final byte P1_TEST_HMAC_SHA1 = (byte) 0x02;
	public static final byte P1_TEST_HMAC_SHA1_TOTP = (byte) 0x03;
	public static final byte P1_TEST_SLOT_COUNTER = (byte) 0xFF;

	public static final byte ADMIN_PIN_LEN = 8;
	public static final byte ADMIN_PIN_LEN_BYTES = ADMIN_PIN_LEN/2;

	private final OwnerPIN AdminPIN;                                                                // Applet's PIN
	private final KeyStore TOTPKeys;								// Keystore
	private final byte[] Response;

	private PinSentryTOTPAdmin() {
		Response = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

		AdminPIN = new OwnerPIN((byte) 3, ADMIN_PIN_LEN_BYTES);
		AdminPIN.update(new byte[] { 0x12, 0x34, 0x56, 0x78 }, (short) 0, ADMIN_PIN_LEN_BYTES);

		TOTPKeys = new KeyStore();
	}

	/*
	 * Installs an instance of the applet.
	 *
	 * @see javacard.framework.Applet#install(byte[], byte, byte)
	 */
	public static void install(byte[] buffer, short offset, byte length) {
		(new PinSentryTOTPAdmin()).register();
	}

	/*
	 * Processes incoming APDUs.
	 *
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();
		byte cla = apduBuffer[ISO7816.OFFSET_CLA];
		byte ins = apduBuffer[ISO7816.OFFSET_INS];
		byte p1 = apduBuffer[ISO7816.OFFSET_P1];

		if (selectingApplet()) {
			AdminPIN.reset();								// Reset PIN validated state
			apdu.setOutgoingAndSend((short) 0, (short) 0);					// Return 9000
			return;
		}

		switch (ins) {
		case INS_PIN:
			switch (p1) {
			case P1_PIN_VERIFY:
				verifyAdminPIN(apdu, apduBuffer);
				return;									// Don't invalidate the PIN again
			case P1_PIN_UPDATE:
				if (AdminPIN.isValidated()) {
					updateAdminPIN(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			case P1_PIN_UPDATE_EMV:
				if (AdminPIN.isValidated()) {
					updateEMVPIN(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case INS_TEST:
			switch (p1) {
			case P1_TEST_SHA1:
				if (AdminPIN.isValidated()) {
					testSHA1(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			case P1_TEST_HMAC_SHA1:
				if (AdminPIN.isValidated()) {
					testSHA1HMAC(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			case P1_TEST_HMAC_SHA1_TOTP:
				if (AdminPIN.isValidated()) {
					testSHA1TOTP(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			case P1_TEST_SLOT_COUNTER:
				if (AdminPIN.isValidated()) {
					testCounterUpdate(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		case INS_KEYSTORE:
			switch (p1) {
			case P1_KEYSTORE_CARDDATA:
				if (AdminPIN.isValidated()) {
					printCardData(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			case P1_KEYSTORE_UPDATE:
				if (AdminPIN.isValidated()) {
					updateKeySlot(apdu, apduBuffer);
				} else {
					ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				}
				break;
			default:
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
				break;
			}
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			break;
		}

		// Invalidate PIN after action
		AdminPIN.reset();
	}

//////////////////////////////////////////////////////////////////////////////////////////
//					PIN Methods					//
//////////////////////////////////////////////////////////////////////////////////////////
// Verify management PIN
	private void verifyAdminPIN(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		if (AdminPIN.getTriesRemaining() == 0) {
			ISOException.throwIt(ISO7816.SW_FILE_INVALID);					// PIN blocked
			return;
		}

		// Check PIN length, 8 digits = 4 bytes
		if ((lc_actual == (short) tmpLength) && ((short) tmpLength == PinSentryTOTPAdmin.ADMIN_PIN_LEN_BYTES)) {
			// PIN object must be coded with 4 bit words
			if (AdminPIN.check(apduBuffer, (short) ISO7816.OFFSET_CDATA, (byte) PinSentryTOTPAdmin.ADMIN_PIN_LEN_BYTES)) {
				apdu.setOutgoingAndSend((short) 0, (short) 0);				// Return 9000
			} else {
				ISOException.throwIt((short) (0x63C0 + AdminPIN.getTriesRemaining()));
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

// Update management PIN
	private void updateAdminPIN(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		// Check length
		if ((lc_actual == (short) tmpLength) && (tmpLength > 0)) {
			short pinLen = apduBuffer[ISO7816.OFFSET_CDATA];
			// Check PIN length, 8 digits = 4 bytes
			if (((short) (pinLen + 1) < tmpLength) && (pinLen == PinSentryTOTPAdmin.ADMIN_PIN_LEN_BYTES)) {
				short hashLen = apduBuffer[(short) (ISO7816.OFFSET_CDATA + pinLen + 1)];
				if ((short) (pinLen + hashLen + 2) <= tmpLength) {
					// Check hashes match
					if (TOTPKeys.checkHash(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), pinLen,
								apduBuffer, (short) (ISO7816.OFFSET_CDATA + pinLen + 2), hashLen)) {
						AdminPIN.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), (byte) pinLen);
						apdu.setOutgoingAndSend((short) 0, (short) 0);			// Return 9000
					} else {
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

// Update EMV PIN
	private void updateEMVPIN(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		// Check length
		if ((lc_actual == (short) tmpLength) && (tmpLength > 0)) {
			short pinLen = apduBuffer[ISO7816.OFFSET_CDATA];
			// Check PIN length, 8 digits = 4 bytes
			if (((short) (pinLen + 1) < tmpLength) && (pinLen == KeyStore.ACCESS_PIN_LEN_BYTES)) {
				short hashLen = apduBuffer[(short) (ISO7816.OFFSET_CDATA + pinLen + 1)];
				if ((short) (pinLen + hashLen + 2) <= tmpLength) {
					// Check hashes match
					if (TOTPKeys.checkHash(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), pinLen,
								apduBuffer, (short) (ISO7816.OFFSET_CDATA + pinLen + 2), hashLen)) {
						TOTPKeys.AccessPIN.update(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), (byte) pinLen);
						apdu.setOutgoingAndSend((short) 0, (short) 0);			// Return 9000
					} else {
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

//////////////////////////////////////////////////////////////////////////////////////////
//					KeyStore Methods				//
//////////////////////////////////////////////////////////////////////////////////////////
// Print card data
	private void printCardData(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		if (lc_actual != 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		Response[0] = (byte) TOTPKeys.getCardInfo(Response, (short) 1);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) (Response[0] + 1));
		apdu.sendBytesLong(Response, (short) 0, (short) (Response[0] + 1));
	}

// Add a update slot in keystore
	private void updateKeySlot(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		if ((lc_actual == (short) tmpLength) && (tmpLength > 0)) {
			short slotKeyLen = apduBuffer[(short) (ISO7816.OFFSET_CDATA)];
			if ((short) (slotKeyLen + 1) < tmpLength) {
				short hashLen = apduBuffer[(short) (ISO7816.OFFSET_CDATA + slotKeyLen + 1)];
				if ((short) (slotKeyLen + hashLen + 2) <= tmpLength) {
					if (TOTPKeys.updateSlot(apduBuffer, (short) (ISO7816.OFFSET_CDATA+1), slotKeyLen,
							apduBuffer, (short) (ISO7816.OFFSET_CDATA+slotKeyLen+2), hashLen)) {
						apdu.setOutgoingAndSend((short) 0, (short) 0);			// Return 9000
					} else {
						ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					}
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

//////////////////////////////////////////////////////////////////////////////////////////
//					Test Methods					//
//////////////////////////////////////////////////////////////////////////////////////////
// Test SHA1 method
	private void testSHA1(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		if ((lc_actual == (short) tmpLength) && (tmpLength > 0)) {
			Response[0] = (byte) TOTPKeys.sha1Hash(apduBuffer, ISO7816.OFFSET_CDATA, (short) tmpLength, Response, (short) 1);

			apdu.setOutgoing();
			apdu.setOutgoingLength((short) (Response[0] + 1));
			apdu.sendBytesLong(Response, (short) 0, (short) (Response[0] + 1));
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

// Test HMAC-SHA1 method
	private void testSHA1HMAC(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		if ((lc_actual == (short) tmpLength) && (tmpLength > 0)) {
			short keyLength = apduBuffer[ISO7816.OFFSET_CDATA];
			if ((short) (keyLength + 1) < tmpLength) {
				short dataLength = apduBuffer[(short) (ISO7816.OFFSET_CDATA + keyLength + 1)];
				if ((short) (keyLength + dataLength + 2) <= tmpLength) {
					Response[0] = (byte) TOTPKeys.sha1HMAC(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), keyLength,
											apduBuffer, (short) (ISO7816.OFFSET_CDATA + keyLength + 2), dataLength,
											Response, (short) 1);

					apdu.setOutgoing();
					apdu.setOutgoingLength((short) (Response[0] + 1));
					apdu.sendBytesLong(Response, (short) 0, (short) (Response[0] + 1));
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

// Test HMAC-SHA1 TOTP method
	private void testSHA1TOTP(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		if ((lc_actual == (short) tmpLength) && (tmpLength > 0)) {
			short keyLength = apduBuffer[ISO7816.OFFSET_CDATA];
			if ((short) (keyLength + 1) < tmpLength) {
				short dataLength = apduBuffer[(short) (ISO7816.OFFSET_CDATA + keyLength + 1)];
				if ((short) (keyLength + dataLength + 2) <= tmpLength) {
					Response[0] = (byte) TOTPKeys.sha1HMACTOTP(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), keyLength,
											apduBuffer, (short) (ISO7816.OFFSET_CDATA + keyLength + 2), dataLength,
											Response, (short) 1);

					apdu.setOutgoing();
					apdu.setOutgoingLength((short) (Response[0] + 1));
					apdu.sendBytesLong(Response, (short) 0, (short) (Response[0] + 1));
				} else {
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}

// Test slot counter
	private void testCounterUpdate(APDU apdu, byte[] apduBuffer) {
		short lc_actual = apdu.setIncomingAndReceive();
		byte tmpLength = apduBuffer[ISO7816.OFFSET_LC];

		if ((lc_actual == (short) tmpLength) && (tmpLength == 0)) {
			Response[0] = (byte) TOTPKeys.getCounterValue((short) (KeyStore.NUM_KEY_SLOTS - 1), Response, (short) 1, KeySlot.COUNTER_SIZE_BYTES);

			apdu.setOutgoing();
			apdu.setOutgoingLength((short) (Response[0] + 1));
			apdu.sendBytesLong(Response, (short) 0, (short) (Response[0] + 1));
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
	}
}
