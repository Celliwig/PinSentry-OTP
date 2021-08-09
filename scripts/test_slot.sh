#!/bin/bash

SCRIPTDIR=`dirname ${0}`
SCRIPTNAME=`basename ${0}`

SLOT_KEY0="12345678901234567890"
SLOT_KEY0_b16=`echo -n "${SLOT_KEY0}"| xxd -p| tr -d '\n'`

echo "${SCRIPTNAME}: Writing test key [${SLOT_KEY0}] to slot 0."
${SCRIPTDIR}/psotp-admin.sh -m 12345678 -a -s 0 -k "${SLOT_KEY0_b16}"

#htop_resp0="755224"
htop_resp1="287082"

iteration=0

while [ true ]; do
	clear
	echo "Check count: ${iteration}"

	otp_response=`opensc-tool -s "00A4040007a0000000038002" -s "0020008008241234ffffffffff" -s "80ae80001d0000000000010000000000000000000000000000000000000000000000" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	otp_response_reply=`echo "${otp_response}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +19| head -c 8`

	if [[ "${otp_response_reply}" == "" ]]; then
		otp_response_errcode=`echo "${otp_response}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${otp_response_errcode})"
		exit -1
	else
		otp_response_b10=`printf "%d" $((16#${otp_response_reply}))`
		if [ "${htop_resp1}" -eq "${otp_response_b10}" ]; then
			iteration=$((iteration+1))
		else
			echo "OTP Response mismatch: ${htop_resp1} - ${otp_response_b10}"
			exit -1
		fi
	fi
done
