# PinSentry-OTP
The purpose of this applet is to provide a OTP (One Time Password) implementation which can be accessed using a Barclays PinSentry device.

## Introduction

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
