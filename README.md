# PinSentry-OTP
A Javacard applet to provide a OTP (One Time Password) implementation which can be used in conjunction with a Barclays PinSentry device.

## Introduction
With increasing attacks on networked devices, OTP provides a simple but effective additional layer of defense. However looking at existing implementations a number of problems are apparent:

* Small number of keys supported
* Cost
* Air gap

Many tokens providing OTP capabilities have only a very limited number of key slots which means either sharing keys between devices (bad), or having to buy and manage multiple tokens (also bad cost wise, and potentially confusing!). While prices for single devices can be quite reasonable, starting at about £20, if multiple devices are required that cost soon escalates. Another factor is that whether using an app on a smartphone, or hardware token connected to a computer, the key store is connected to a potentially compromised machine. While a hardware token should in theory be imprevious to a corrupted host's attacks, the integrity of any particular hardware implementation can only be verified by the manufacturer due to the closed nature of these devices. Smartphone apps provide a similar problem in that there is no way to reasonably audit key handling (and therefore potential for leakage), and the recent reporting of the Pegasus spyware reminds us of the vunerability of smartphones. So providing a method

## Requirements

## Compilation
Assuming you don't have Java 1.3 installed, compile with 1.3 format (I used Java 8):

javac -g -source 1.3 -target 1.3 -classpath <path to javacard kit>/java_card_kit-2_2_2/lib/api.jar psotp/EMV* psotp/PinSentryOTP.java
java -classpath <path to javacard kit>/java_card_kit-2_2_2/lib/converter.jar:<path to javacard kit>/java_card_kit-2_2_2/lib/offcardverifier.jar com.sun.javacard.converter.Converter -config PinSentry-OTP.opt

## Install
LD_LIBRARY_PATH=~/globalplatform/globalplatform/src/:~/globalplatform/gppcscconnectionplugin/src/ ~/globalplatform/gpshell/src/gpshell gpshell/PinSentryOTP_Install.gpshell

## Testing
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


## References
HMAC implementation RFC2104
HMAC test cases RFC2202
TOTP: Time-Based One-Time Password Algorithm RFC6238
HTOP: An HMAC-Based One-Time Password Algorithm RFC4226

Optimised to Fail: Card Readers for Online Banking
EMV Intergrated Circuit Card: Specifications for Payment Systems (Book 3)
EMV (Chip and PIN) Project

https://github.com/JavaCardOS/OpenEMV.git
