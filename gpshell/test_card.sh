#!/bin/bash

echo -n "Testing SHA1 algorithm: "
# Compute SHA1 hash locally
sha1_native=`echo -n 'hello' | sha1sum| awk '{ print $1 }'`
# Test on card SHA1 algorithm
sha1_card=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff01000568656C6C6F00" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1_card_reply=`echo "${sha1_card}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
# Extract length of reply
sha1_card_dlen_hex=`echo "${sha1_card_reply}" | head -c 2`
sha1_card_dlen=`printf "%d" $((16#${sha1_card_dlen_hex}))`
# Extract reply
sha1_card_reply=`echo ${sha1_card_reply}| tail -c +3 | head -c $((${sha1_card_dlen} * 2))`
echo "${sha1_native}"| grep -i "${sha1_card_reply}" > /dev/null
if [ ${?} -eq 0 ]; then
	echo "OK"
else
	echo "Failed: ${sha1_native} != ${sha1_card_reply}"
	exit -1
fi

tc1_digest="b617318655057264e28bc0b6fb378c8ef146be00"
tc2_digest="effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
tc3_digest="125d7342b9ac11cd91a39af48aa17b4f63f175d3"
tc4_digest="4c9007f4026250c6bc8414f9bf50c86c2d7235da"
tc5_digest="4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
tc6_digest="aa4ae5e15272d00e95705637ce8a3b55ed402112"
tc7_digest="e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
echo "Testing SHA1 HMAC (Test vectors from RFC2202):"

# Test Case 1
echo -n "	Test Case 1: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff02001e140b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b084869205468657265" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc1_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc1_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi

# Test Case 2
echo -n "	Test Case 2: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff020022044a6566651c7768617420646f2079612077616e7420666f72206e6f7468696e673f" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc2_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc2_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi

# Test Case 3
echo -n "	Test Case 3: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff02004814aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa32dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc3_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc3_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi

# Test Case 4
echo -n "	Test Case 4: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff02004d190102030405060708090a0b0c0d0e0f1011121314151617181932cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc4_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc4_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi

# Test Case 5
echo -n "	Test Case 5: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff02002a140c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c14546573742057697468205472756e636174696f6e" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc5_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc5_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi

# Test Case 6
echo -n "	Test Case 6: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff02008250aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3054657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	# This is expected to fail so don't exit
	#exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc6_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc6_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi

# Test Case 7
echo -n "	Test Case 7: "
sha1hmac=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "00ff02009b50aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa496554747355206973676e4c2072616567207268546e6142206f6c6b63532d7a692065654b20796e612064614c6772726554206168206e6e4f20656c42636f2d6b6953657a442074610a61" 2>/dev/null`
if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
sha1hmac_reply=`echo "${sha1hmac}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 2 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
if [[ "${sha1hmac_reply}" == "" ]]; then
	sha1hmac_errcode=`echo "${sha1hmac}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
	echo "Failed (Bad Command: ${sha1hmac_errcode})"
	# This is expected to fail so don't exit
	#exit -1
else
	# Extract length of reply
	sha1hmac_dlen_hex=`echo "${sha1hmac_reply}" | head -c 2`
	sha1hmac_dlen=`printf "%d" $((16#${sha1hmac_dlen_hex}))`
	# Extract reply
	sha1hmac_reply=`echo "${sha1hmac_reply}"| tail -c +3 | head -c $((${sha1hmac_dlen} * 2))`
	echo "${tc7_digest}"| grep -i "${sha1hmac_reply}" > /dev/null
	if [ ${?} -eq 0 ]; then
		echo "OK"
	else
		echo "Failed: ${tc7_digest} != ${sha1hmac_reply}"
		exit -1
	fi
fi
