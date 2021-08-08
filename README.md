# PinSentry-OTP
A Javacard applet to provide a OTP (One Time Password) implementation which can be used in conjunction with a Barclays PinSentry device.

## Introduction
With increasing attacks on networked devices, OTP provides a simple but effective additional layer of defense. However looking at existing implementations a number of problems are apparent:

* Small number of keys supported
* Cost
* Air gap

Many tokens providing OTP capabilities have only a limited number of key slots which means either sharing keys between devices (bad), or having to buy and manage multiple tokens (also bad cost wise, and potentially confusing!). While prices for single devices can be quite reasonable, starting at about £20, if multiple devices are required that cost soon escalates. Another factor is that whether using an app on a smartphone, or hardware token connected to a computer, the key store is connected to a potentially compromised machine. While a hardware token should in theory be imprevious to a corrupted host's attacks, the integrity of any particular hardware implementation can only be verified by the manufacturer due to the closed nature of these devices. Smartphone apps provide a similar problem in that there is no way to reasonably audit key handling (and therefore potential for leakage), and the recent reporting of the Pegasus spyware reminds us of the vunerability of smartphones. So a method OTP generation that is air gapped (ie. not internet connected), providing a larger number of key slots (>128), and at low cost, would be useful.

## Implementation
Barclays Bank has distributed a large number of PinSentry devices to their (UK?) customers to facilitate internet banking. These devices are used in conjunction with an issued bank card to generate OTPs to authenticate login and transactions on their internet portal, they use fairly standard EMV (Europay/Mastercard/Visa) routines to acheive this[1]. Having a device to hand it seemed logical to use this as a base for building a generic OTP authentication system. On the other side (of the interface), bank cards are not just simple memory cards, but contain a processing unit as well. So to take the place of the bank card a programable smartcard is needed. There are different types of programable smartcard available, but using one which uses the Javacard standard makes the implementation easier in terms of language used and software tools needed. A Javacard applet emulating an EMV bank card was already available[2], so this was used as the starting point for the project. That project was configured for a dutch bank and the PinSentry just rejected the card as it was configured. So having spent a couple of hours trying to reading data off an (expired!) Barclays card the code was updated to the point that the PinSentry device would interact correctly with it (recognise card/accept PIN/perform action/return result). Having proved the basic premise, the key store and OTP generation classes/methods were written. HTOP[3] and TOTP[4] specifications are readily available, and while easy to implement on a modern architecture proved a little more problematic using the Javacard interface (2.2.2). While the selected card implements SHA-1 which is the core of OTP, it lacks SHA-1 HMAC and more importantly Integer support. This made things like the final stage of the OTP generation (integer divide) awkward. It should be noted that later versions (>3) of the Javacard specification can avoid these problems. The final package contains two applets, one which is the EMV PinSentry interface, and the second is for management of the key store.

## Requirements
* Javacard, minimum version: 2.2.2, with SHA-1 support (I used NXP J2A080)
* Javacard Kit (in this case 2.2.2)
* Java JDK (to compile Javacard Kit 2.2.2, JDK <= 1.8 is needed)
* GPShell (is used to install the applet CAP file to the smartcard, any other GlobalPlatform tool should work here)
* PC with card slot (this was written on Linux, so anything with PC/SC compatibility recommended. Should be okay with serial, with USB YMMV)
* Linux (Mac probably okay), while not strictly necessary, you're on your own in regards to the management tool if you use anything else.

## Compilation
Assuming you don't have Java 1.3 installed, compile with 1.3 format (Java 8 was used):
```
javac -g -source 1.3 -target 1.3 -classpath <path to javacard kit>/java_card_kit-2_2_2/lib/api.jar psotp/EMV* psotp/PinSentryOTP.java
java -classpath <path to javacard kit>/java_card_kit-2_2_2/lib/converter.jar:<path to javacard kit>/java_card_kit-2_2_2/lib/offcardverifier.jar com.sun.javacard.converter.Converter -config PinSentry-OTP.opt
```

## Install
```
gpshell gpshell/PinSentryOTP_Install.gpshell
```

## Testing
```
./scripts/test_card.sh 
Testing SHA1 algorithm: OK
Testing SHA1 HMAC (Test vectors from RFC2202):
	Test Case 1: OK
	Test Case 2: OK
	Test Case 3: OK
	Test Case 4: OK
	Test Case 5: OK
	Test Case 6: Failed (Bad Command: Received (SW1=0x67, SW2=0x00))
	Test Case 7: Failed (Bad Command: Received (SW1=0x67, SW2=0x00))
Testing SHA1 HMAC HTOP (Test vectors from RFC4226):
	Test Case 1: OK
	Test Case 2: OK
	Test Case 3: OK
	Test Case 4: OK
	Test Case 5: OK
	Test Case 6: OK
	Test Case 7: OK
	Test Case 8: OK
	Test Case 9: OK
	Test Case 10: OK
```
N.B.: SHA-1 HMAC test case 6 & 7 failure: expected, currently doesn't support oversized (ie. >keysize) operations. Not needed for OTP, wrote the test cases anyway. Not OTP but OTT!

## Configuration and Use

## References
1. [Optimised to Fail: Card Readers for Online Banking](<https://murdoch.is/papers/fc09optimised.pdf>)

2. [OpenEMV](<https://github.com/JavaCardOS/OpenEMV.git>)

3. [HOTP: An HMAC-Based One-Time Password Algorithm](<https://www.ietf.org/rfc/rfc4226.txt>)

4. [TOTP: Time-Based One-Time Password Algorithm](<https://www.ietf.org/rfc/rfc6238.txt>)

## Additional Reading
1. [EMV, Book 3: Application Specification](<https://www.emvco.com/wp-content/uploads/2017/05/EMV_v4.3_Book_3_Application_Specification_20120607062110791.pdf>)

2. [EMV (Chip and PIN) Project](<http://khuong.uk/Papers/EMVThesis.pdf>)

3. [HMAC: Keyed-Hashing for Message Authentication](<https://www.ietf.org/rfc/rfc2104.txt>)

4. [Test Cases for HMAC-MD5 and HMAC-SHA-1](<https://www.ietf.org/rfc/rfc2202.txt>)
