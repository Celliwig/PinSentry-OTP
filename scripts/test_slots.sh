#!/bin/bash

SCRIPTDIR=`dirname ${0}`
SCRIPTNAME=`basename ${0}`

SLOT_KEY0=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY0_b16=`echo -n "${SLOT_KEY0}"| xxd -p| tr -d '\n'`
SLOT_KEY1=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY1_b16=`echo -n "${SLOT_KEY1}"| xxd -p| tr -d '\n'`
SLOT_KEY2=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY2_b16=`echo -n "${SLOT_KEY2}"| xxd -p| tr -d '\n'`
SLOT_KEY3=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY3_b16=`echo -n "${SLOT_KEY3}"| xxd -p| tr -d '\n'`
SLOT_KEY4=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY4_b16=`echo -n "${SLOT_KEY4}"| xxd -p| tr -d '\n'`
SLOT_KEY5=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY5_b16=`echo -n "${SLOT_KEY5}"| xxd -p| tr -d '\n'`
SLOT_KEY6=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY6_b16=`echo -n "${SLOT_KEY6}"| xxd -p| tr -d '\n'`
SLOT_KEY7=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY7_b16=`echo -n "${SLOT_KEY7}"| xxd -p| tr -d '\n'`
SLOT_KEY8=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY8_b16=`echo -n "${SLOT_KEY8}"| xxd -p| tr -d '\n'`
SLOT_KEY9=`head -c 48 /dev/urandom | base64| tr -d '\n'`
SLOT_KEY9_b16=`echo -n "${SLOT_KEY9}"| xxd -p| tr -d '\n'`

echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY0}] to slot 0."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 0 -k "${SLOT_KEY0_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY1}] to slot 1."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 1 -k "${SLOT_KEY1_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY2}] to slot 2."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 2 -k "${SLOT_KEY2_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY3}] to slot 3."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 3 -k "${SLOT_KEY3_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY4}] to slot 4."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 4 -k "${SLOT_KEY4_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY5}] to slot 5."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 5 -k "${SLOT_KEY5_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY6}] to slot 6."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 6 -k "${SLOT_KEY6_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY7}] to slot 7."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 7 -k "${SLOT_KEY7_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY8}] to slot 8."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 8 -k "${SLOT_KEY8_b16}"
echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY9}] to slot 9."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 9 -k "${SLOT_KEY9_b16}"

iteration=0

while [ true ]; do
	echo "Check count: ${iteration}"

	# Select HOTP mode
	totp_value="000000000000"

	# Slot 0
	slot_num="00000000"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY0_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 0: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 0: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 1
	slot_num="00000001"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY1_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 1: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 1: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 2
	slot_num="00000002"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY2_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 2: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 2: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 3
	slot_num="00000003"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY3_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 3: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 3: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 4
	slot_num="00000004"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY4_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 4: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 4: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 5
	slot_num="00000005"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY5_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 5: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 5: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 6
	slot_num="00000006"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY6_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 6: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 6: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 7
	slot_num="00000007"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY7_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 7: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 7: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 8
	slot_num="00000008"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY8_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 8: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 8: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	# Slot 9
	slot_num="00000009"
	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d${totp_value}00000000000000000000000000000000000000${slot_num}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`
	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		oathtool_response=`oathtool --hotp -c "${iteration}" "${SLOT_KEY9_b16}"`
		otp_response_reply=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${oathtool_response}" -eq "${otp_response_reply}" ]; then
			echo "	Slot 9: ${oathtool_response} - ${otp_response_reply}"
		else
			echo "	Slot 9: OTP Response mismatch: ${oathtool_response} - ${oathtool_response}"
			exit -1
		fi
	fi

	iteration=$((${iteration}+1))
done
