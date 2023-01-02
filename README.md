# PinSentry-OTP
A Javacard applet to provide an OTP (One Time Password) implementation which can be used in conjunction with a Barclays PinSentry device.

## Introduction
With increasing attacks on networked devices, OTP provides a simple but effective additional layer of defense. However looking at existing implementations a
number of problems are apparent:

* Small number of keys supported
* Cost
* Air gap

Many tokens providing OTP capabilities have only a limited number of key slots which means either sharing keys between devices (bad), or having to buy and
manage multiple tokens (also bad cost wise, and potentially confusing!). While prices for single devices can be quite reasonable, starting at about £20, if
multiple devices are required that cost soon escalates. Another factor is that whether using an app on a smartphone, or hardware token connected to a computer,
the key store is connected to a potentially compromised machine. While a hardware token should in theory be impervious to a corrupted host's attacks, the
integrity of any particular hardware implementation can only be verified by the manufacturer due to the closed nature of these devices. Smartphone apps provide
a similar problem in that there is no way to reasonably audit key handling (and therefore potential for leakage), and the recent reporting of the Pegasus 
spyware reminds us of the vunerability of smartphones. So a method OTP generation that is air gapped (ie. not internet connected), providing a larger number of
key slots (>128), and at low cost, would be useful.

## Implementation
Barclays Bank has distributed a large number of PinSentry devices to their (UK?) customers to facilitate internet banking. These devices are used in conjunction
with an issued bank card to generate OTPs to authenticate login and transactions on their internet portal, they use fairly standard EMV (Europay/Mastercard/Visa)
routines to acheive this[1]. Having a device to hand it seemed logical to use this as a base for building a generic OTP authentication system. On the other side
(of the interface), bank cards are not just simple memory cards, but contain a processing unit as well. So to take the place of the bank card a programable 
smartcard is needed. There are different types of programable smartcard available, but using one which uses the Javacard standard makes the implementation easier
in terms of language used and software tools needed. A Javacard applet emulating an EMV bank card was already available[2], so this was used as the starting 
point for the project. That project was configured for a Dutch bank and the PinSentry just rejected the card as it was configured. So having spent a couple of
hours trying to reading data off an (expired!) Barclays card the code was updated to the point that the PinSentry device would interact correctly with it 
(recognise card/accept PIN/perform action/return result). Having proved the basic premise, the key store and OTP generation classes/methods were written. 
HTOP[3] and TOTP[4] specifications are readily available, and while easy to implement on a modern architecture proved a little more problematic using the 
Javacard interface (2.2.2). While the selected card implements SHA-1 which is the core of OTP, it lacks SHA-1 HMAC and more importantly Integer support. This
made things like the final stage of the OTP generation (integer divide) awkward. It should be noted that later versions (>3) of the Javacard specification can
avoid these problems. The final package contains two applets, one which is the EMV PinSentry interface, and the second is for management of the key store.

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
javac -g -source 1.3 -target 1.3 -classpath <path to javacard kit>/java_card_kit-2_2_2/lib/api.jar psotp/EMV* psotp/KeyS* psotp/PinSentryOTP.java psotp/PinSentryOTPAdmin.java
java -classpath <path to javacard kit>/java_card_kit-2_2_2/lib/converter.jar:<path to javacard kit>/java_card_kit-2_2_2/lib/offcardverifier.jar com.sun.javacard.converter.Converter -config PinSentry-OTP.opt
```

## Install
```
gpshell gpshell/PinSentryOTP_Install.gpshell
```

## Testing
Basic card algorithm operation can be tested (note that this interfaces directly with the algorithms bypassing the key store):
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

Test multiple random keys in HTOP mode (requires oathtool to be installed):
```
./scripts/test_slots.sh 
test_slots.sh: Writing test key [iGO2uJTBcUIxf3AyKG2hp37O3YeTR/dYBMgcfscOD/DbvAg94dU/IazmtnJnQ+D/] to slot 0.
Update Slot[0]: OK
test_slots.sh: Writing test key [MoRvuq8f/2qdOb0IcS6/uJreJpPrYHamX0jvinCNmEbObHRJ0ZfciIwsGMG8kSuB] to slot 1.
Update Slot[1]: OK
test_slots.sh: Writing test key [9kCRwt7qlBmjpQ3Jmegg/UiH7DPOdGp0wIhaUPVQDX3+dJe3gE5tivNyAONQCYZL] to slot 2.
Update Slot[2]: OK
test_slots.sh: Writing test key [vE9nL1TwcpyYOodSIRbPgj/7F21ZhX7e+5ePu+TjTd5WjmAm9Gp8BMvD4M5QbNB8] to slot 3.
Update Slot[3]: OK
test_slots.sh: Writing test key [SMF9BaOyRGfRrVKvgWpKZ/L68LfvvT39aaK5ydxeYunZPN5uTS1NIHO8E6WfSOoY] to slot 4.
Update Slot[4]: OK
test_slots.sh: Writing test key [q7PHxIDeEhVT5OlGOanYLr2VJi1OD4HtBpmTA6yOTe24SL+RZwzrmgtPavv/W5I/] to slot 5.
Update Slot[5]: OK
test_slots.sh: Writing test key [+ug0UBApFzbNSDUIvst6VEEN5HvkVPp0tPfgyoiIumi57F1qiGWu/RHb0tYO+LG9] to slot 6.
Update Slot[6]: OK
test_slots.sh: Writing test key [U6OWkSjXT40f1dpV2tZhn2futN8vwzxVILwBLTVVTjpAOY8OO/7KbdqhVJhnsB2R] to slot 7.
Update Slot[7]: OK
test_slots.sh: Writing test key [TXSiWwUJYH64BfxPodc0ZCI3qdEs0tSRziw6APsfVXS1rU6BwcFpb5jIgmconCpP] to slot 8.
Update Slot[8]: OK
test_slots.sh: Writing test key [PQDcLl+G5bIUxtDbvTjpM43pz6eQa/Z6XPn60uyz6KyDU4P4tijBZr6y79ozlIgm] to slot 9.
Update Slot[9]: OK
Check count: 0
	Slot 0: 007856 - 7856
	Slot 1: 652305 - 652305
	Slot 2: 066785 - 66785
	Slot 3: 424971 - 424971
	Slot 4: 894291 - 894291
	Slot 5: 360687 - 360687
	Slot 6: 816906 - 816906
	Slot 7: 603884 - 603884
	Slot 8: 157360 - 157360
	Slot 9: 032341 - 32341
Check count: 1
	Slot 0: 508555 - 508555
	Slot 1: 029160 - 29160
	Slot 2: 586636 - 586636
	Slot 3: 350457 - 350457
	Slot 4: 032524 - 32524
	Slot 5: 931366 - 931366
	Slot 6: 514185 - 514185
	Slot 7: 110236 - 110236
	Slot 8: 512036 - 512036
	Slot 9: 899118 - 899118
Check count: 2
	Slot 0: 109351 - 109351
	Slot 1: 320334 - 320334
	Slot 2: 455588 - 455588
	...
	...
	...
```

## Configuration and Use
### Initial card setup
Once the card has been programmed, it is adviserable to change the default PINs. There are 2 PINs used to access features of the card, when inserted into
a PinSentry device the EMV PIN is asked for, this is set to a default of 1234. When plugged into a computer, the management PIN is used to authenticate card
operations, this is set to a default of 12345678. To update the PINs:

```
./scripts/psotp-admin.sh -m 12345678 -n 41328576		// Updates the management PIN to 41328576
./scripts/psotp-admin.sh -m 41328576 -e 4132			// Updates the EMV PIN to 4132
```

### PAM configuration
The Google Authenticator PAM module was used to implement host side 2FA checking, and this is generally available in distribution repositories. 
Having been installed, it needs to be called when autheticating to a system. The desire was to secure network based authentication while leaving
physical logins untouched, so the PAM files for just sshd and sudo (in /etc/pam.d) were updated as below.

```
auth       required     pam_google_authenticator.so secret=/etc/google-authenticator/default user=root no_increment_hotp [authtok_prompt=HOTP Code(210): ]
```

This should be inserted prior to any additional 'auth' rules, eg: pam_unix. The included configuration sets:
* secret - Path to user's key (hardwired here so that user & root use the same key. Would generally include wildcard to select keys for different users)
* user - User to use to access key file
* no_increment_hotp - Don't increment stored HOTP counter on authentication failure.
* authtok_prompt - Change the text of the 2FA prompt so as to include keyslot number.

N.B. The 'secret' path shouldn't use a link of any kind (sym/hard). It'll possibly read okay, but after using the key the new counter value is written back
to a NEW file which messes up the point of using a link.

With the PAM configuration updated, a keyfile(s) is needed. First off generate a key.

```
root@host:~# new_key=`head -c 64 /dev/random`; echo -n "${new_key}"| base32; echo -n "${new_key}"| xxd -p
AZOKDOMRXJWEVD5GTQ7NCPSBCSWTWMXYYBDBYJSRMP6AZA4HC4QYJ4GAE2ZGMLAITFXYXJI3MH2U
7KGXW5ROWP5W73HQ33DSKKNJTJA=
065ca1b991ba6c4a8fa69c3ed13e4114ad3b32f8c0461c265163fc0c8387
172184f0c026b2662c08996f8ba51b61f54fa8d7b762eb3fb6fecf0dec72
529a99a4
```

This produces a random key of maximum length using the RNG of the machine (make sure your RNG is actually working! ;) ). The key is printed twice, once as
'Base32' (for Google Authenticator), and next as hexadecimal (for programming the card). Next program a slot on the card:

```
./scripts/psotp-admin.sh -m <Admin PIN> -a -k <key in hexadecimal> -s <slot num>


./scripts/psotp-admin.sh -m 41328576 -a -k 065ca1b991ba6c4a8fa69c3ed13e4114ad3b32f8c0461c265163fc0c8387172184f0c026b2662c08996f8ba51b61f54fa8d7b762eb3fb6fecf0dec72529a99a4 -s 210
```

Note: You can set a slot's HOTP counter value when you add a key, useful if you are reusing an existing key.


Next create a key file, in this case '/etc/google-authenticator/default'.

```
AZOKDOMRXJWEVD5GTQ7NCPSBCSWTWMXYYBDBYJSRMP6AZA4HC4QYJ4GAE2ZGMLAITFXYXJI3MH2U7KGXW5ROWP5W73HQ33DSKKNJTJA-
" RATE_LIMIT 3 30
" WINDOW_SIZE 5
" HOTP_COUNTER 1
```

Note that the '=' in the key generated needs to be converted to a '-' for the key to work, this is down to the way characters are represented between the 2
programs. Also the key file should only be readable by the user only, so 'chmod 400 <keyfile>'.
	
<b>N.B. google-authenticator needs the OTP value padded with '0's if it's less than 6 digits!</b>

### PinSentry & 2FA generation
The PinSentry offers 3 different methods of generating a 2FA response, these are selected by the 'Identify', 'Respond', and 'Sign' buttons. Only 2 of these
are actually useful in combination with a Javacard. This is because they will all do the same operation, but some will just zero a parameter field. The modes, 
and expected input/output are listed below.

* Identify -> PIN:
	Returns a HOTP code for slot 0.
* Respond -> PIN -> Enter 6 Number:
	Returns a HOTP code for slot #<Enter Number>.
* Sign -> PIN -> Enter Ref -> Enter Amount:
	Returns a OTP code for slot #<Enter Ref>, using value <Enter Amount> instead of the slot's HOTP counter.

So normally you would press the 'Respond' button, enter the EMV PIN, enter the slot number, and the HOTP response will then be displayed (after a few seconds).
The 'Sign' mode could be used as partial implementation of TOTP, but the time value would have to be supplied from a device with an actual RTC.

## Todo

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
