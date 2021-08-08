#!/bin/bash

COUNTERVALUE_EXPECTED=""

while [ true ]; do
	printf "\x0d"
	counterVal=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "000101000412345678" -s "00ffff0000" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	counterVal_reply=`echo "${counterVal}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"| tail -c +3| head -c 16`

	if [[ "${counterVal_reply}" == "" ]]; then
		counterVal_errcode=`echo "${counterVal}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${counterVal_errcode})"
		exit -1
	else
		echo -n ${counterVal_reply}
		if [[ "${COUNTERVALUE_EXPECTED}" == "" ]]; then
			COUNTERVALUE_EXPECTED="${counterVal_reply}"
		fi
		if [[ "${COUNTERVALUE_EXPECTED}" != "${counterVal_reply}" ]]; then
			echo
			echo "	Failed, expected: ${COUNTERVALUE_EXPECTED}"
			exit
		fi
		COUNTERVALUE_EXPECTED=`printf "%016X" "$((16#${COUNTERVALUE_EXPECTED}+1))"`
	fi
done
