/*
 * Class to record all the static data of an EMV applet, ie. the card details that
 * do not change over time (such as PAN, expiry date, etc.), with the exception
 * of the cryptographic keys.
 *
 * This static data is organised in the simplest possible way, using some public byte
 * arrays to record exact APDUs that the card has to produce.
 *
 * This class does not offer personalisation support - everything is hard-coded.
 *
 * Celliwig (07/2021): Data updated to emulate Barclays (UK) debit card
 *
 */

package openemv;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class EMVStaticData implements EMVConstants {
	private final byte[] AFL = new byte[] { 0x08, 0x01, 0x02, 0x00 };

	/* Returns the 4 byte AFL (Application File Locator) */
	public byte[] getAFL() {
	    return AFL;
	}

	/*
	 * Returns the 2 byte AIP (Application Interchange Profile)
	 *  See Book 3, Annex C1 for details
	 */
	public short getAIP() {
		return 0x1000;									// Cardholder verification supported
	}

	private final byte[] fci = new byte[] {
					0x6F, 0x1D,						// File Control Information (FCI) [Size: 29]
					(byte) 0x84, 0x07,					// Dedicated File (DF) Name [Size: 7]
					(byte) 0xA0, 0x00, 0x00, 0x00, 0x03,(byte) 0x80, 0x02,	// AID
					(byte) 0xA5, 0x12,					// File Control Information (FCI) [Size: 18]
					0x50, 0x08,						// Application Label [Size: 8]
					0x42, 0x41, 0x52, 0x43, 0x4C, 0x41, 0x59, 0x53,		// ASCII: BARCLAYS
					(byte) 0x87, 0x01,					// Application Priority Indicator [Size: 1]
					0x00,							// Priority: 0
					0x5F, 0x2D, 0x02,					// Language Preference [Size: 2]
					0x65, 0x6E						// ASCII: en
				};

	private final byte[] record1 = new byte[] {
					0x70, 0x13,						// Record Template [Size: 19]
					0x5A, 0x08,						// Application Primary Account Number [Size: 08]
					0x12, 0x34, 0x56, 0x78,(byte) 0x87, 0x65, 0x43, 0x21,	// Obviously fake account number ;)
					0x5F, 0x34, 0x01,					// Application Primary Account Number Sequence Number
					0x00,							// PAN Seq No.: 0
					(byte) 0x9F, 0x08, 0x02,				// Application Version Number
					0x00, 0x01						// Ver: 1
				};

	// File for EMV-CAP
	private final byte[] record2 = new byte[] {
					0x70, 0x55,						// Record Template [Size: 85]
					(byte) 0x8C, 0x15,					// Card Risk Management Data Object List 1 (CDOL1) [Size: 21]
					(byte) 0x9F, 0x02, 0x06,(byte) 0x9F, 0x03, 0x06,(byte) 0x9F, 0x1A, 0x02,(byte) 0x95, 0x05, 0x5F, 0x2A, 0x02,(byte) 0x9A, 0x03,(byte) 0x9C, 0x01,(byte) 0x9F, 0x37, 0x04,
					(byte) 0x8D, 0x17,					// Card Risk Management Data Object List 2 (CDOL2) [Size: 23]
					(byte) 0x8A, 0x02,(byte) 0x9F, 0x02, 0x06,(byte) 0x9F, 0x03, 0x06,(byte) 0x9F, 0x1A, 0x02,(byte) 0x95, 0x05, 0x5F, 0x2A, 0x02,(byte) 0x9A, 0x03,(byte) 0x9C, 0x01,(byte) 0x9F, 0x37, 0x04,
					(byte) 0x8E, 0x0A,					// Cardholder Verification Method List (CVM) [Size: 10]
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
					(byte) 0x9F, 0x55, 0x01,				// Unknown
					(byte) 0xA0,
					(byte) 0x9F, 0x56, 0x12,				// CAP Bit Filter [Size: 18]
					(byte) 0x80, 0x00,(byte) 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,(byte) 0xFF,(byte) 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				};

	/*
	 * Return the length of the data specified in the CDOL1
	 */
	public short getCDOL1DataLength() {
		return 0x15;
	}

	/*
	 * Return the length of the data specified in the CDOL2
	 */
	public short getCDOL2DataLength() {
		return 0x17;
	}

	public byte[] getFCI() {
		return fci;
	}

	public short getFCILength() {
		return (short) fci.length;
	}

	/*
	 * Provide the response to INS_READ_RECORD in the response buffer
	 */
	public void readRecord(byte[] apduBuffer, byte[] response){
		if ((apduBuffer[OFFSET_P2] == 0x0C) && (apduBuffer[OFFSET_P1] == 0x01))
		{
			// SFI 1, Record 1
			Util.arrayCopyNonAtomic(record1, (short) 0, response, (short) 0, (short) record1.length);
			response[1] = (byte) (record1.length - 2);
		}
		else if ((apduBuffer[OFFSET_P2] == 0x0C) && (apduBuffer[OFFSET_P1] == 0x02))
		{
			// SFI 1, Record 2
			Util.arrayCopyNonAtomic(record2, (short) 0, response, (short) 0, (short) record2.length);
			response[1] = (byte) (record2.length - 2);
		}
		else
		{
			// File does not exist
			ISOException.throwIt(SW_FILE_NOT_FOUND);
		}
	}
}
