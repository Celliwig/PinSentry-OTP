#!/bin/bash

KEY_HEX=""
PIN_ADMIN=""
PIN_NEW=""
PSTOPT_ACTION=""
SCRIPTNAME=`basename ${0}`

usage() {
	echo "${SCRIPTNAME}: PSTOTP Admin Tool"
	echo "	-a		Add key"
	echo "	-k <key>	Key"
	echo "	-h		Help text (this)"
	echo "	-i		Print card info"
	echo "	-m		Management PIN"
	echo "	-n		Update management PIN"
	echo "	-s <slot num>	Slot number"
	exit 0
}

# Get CLI arguments
while getopts ":htaie:k:m:n:s:" opt; do
	case ${opt} in
		a )
			PSTOPT_ACTION="addkey"
			;;
		e )
			PSTOPT_ACTION="updatepinemv"
			PIN_NEW="${OPTARG}"
			;;
		k )
			KEY_HEX="${OPTARG}"
			;;
		h )
			usage
			;;
		i )
			PSTOPT_ACTION="printinfo"
			;;
		m )
			PIN_ADMIN="${OPTARG}"
			;;
		n )
			PSTOPT_ACTION="updatepin"
			PIN_NEW="${OPTARG}"
			;;
		\? )
			echo "Invalid Argument: -${OPTARG}" 1>&2
			;;
	esac
done

check_pin() {
	local pin_txt=${1}
	local pin_length=${2}
	local pin_txt_len=`echo -n ${pin_txt}| wc -c`
	local pin_len=`echo -n ${pin_txt}| sed 's|[^0-9]||g'| wc -c`
	if [[ "${pin_txt}" == "" ]]; then
		echo "${SCRIPTNAME}: Error: No PIN given"
		exit -1
	fi
	if [ "${pin_txt_len}" -ne "${pin_len}" ]; then
		echo "${SCRIPTNAME}: Error: Invalid PIN"
		exit -1
	fi
	if [ "${pin_len}" -ne "${pin_length}" ]; then
		echo "${SCRIPTNAME}: Error: Incorrect PIN length: |${pin_txt}|"
		exit -1
	fi
}

# Try PIN verification to see if PIN correct
check_auth() {
	local pin_txt="${1}"
	local card_auth=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "0001010004${pin_txt}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	local card_auth_errcode=`echo "${card_auth}"| grep "Received " | tail -n 1`
	echo "${card_auth_errcode}"| grep 'Received (SW1=0x90, SW2=0x00)' > /dev/null
	if [ "${?}" -ne 0 ]; then
		echo "${SCRIPTNAME}: Auth failed: Bad PIN [${card_auth_errcode}]"
		exit -1
	fi
}

# Fetch card info result (it's processed seperately)
fetch_cardinfo() {
	local pin_txt="${1}"
	check_pin "${pin_txt}" 8
	check_auth "${pin_txt}"

	local card_info=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "0001010004${pin_txt}" -s "0002010000" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	local card_info_reply=`echo -n "${card_info}"| awk 'BEGIN { RECEIVED=0 } RECEIVED == 3 { print $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 } $0 ~ /Received \(SW1=0x90, SW2=0x00\)/ { RECEIVED=RECEIVED+1 }'| tr -d "\n"`
	if [[ "${card_info_reply}" == "" ]]; then
		local card_info_errcode=`echo -n "${card_info}"| grep "^Received "| grep -v "Received (SW1=0x90, SW2=0x00)"`
		echo "Failed (Bad Command: ${card_info_errcode})"
		exit -1
	else
		echo "${card_info_reply}"
	fi
}

# Process cardinfo reply, extract card ID
fetch_cardinfo_cardid() {
	local card_info_reply="${1}"

	# Extract length of reply
	local card_info_dlen_hex=`echo -n "${card_info_reply}" | head -c 2`
	local card_info_dlen=`printf "%d" $((16#${card_info_dlen_hex}))`
	# Extract reply
	local card_info_reply=`echo -n "${card_info_reply}"| tail -c +3 | head -c $((${card_info_dlen} * 2))`

	# Extract card ID
	local cardid_size_hex=`echo -n "${card_info_reply}" | head -c 2`
	local cardid_size=`printf "%d" $((16#${cardid_size_hex}))`
	local card_info_reply=`echo -n "${card_info_reply}" | tail -c +3`
	local cardid=`echo -n "${card_info_reply}" | head -c $((${cardid_size} * 2))`

	echo "${cardid}"
}

# Print contents of cardinfo reply
display_info() {
	local pin_txt="${1}"
	check_pin "${pin_txt}" 8
	check_auth "${pin_txt}"
	local card_info_reply=`fetch_cardinfo "${pin_txt}"`

	# Extract length of reply
	local card_info_dlen_hex=`echo -n "${card_info_reply}" | head -c 2`
	local card_info_dlen=`printf "%d" $((16#${card_info_dlen_hex}))`
	# Extract reply
	local card_info_reply=`echo -n "${card_info_reply}"| tail -c +3 | head -c $((${card_info_dlen} * 2))`

	# Extract card ID
	local cardid_size_hex=`echo -n "${card_info_reply}" | head -c 2`
	local cardid_size=`printf "%d" $((16#${cardid_size_hex}))`
	local card_info_reply=`echo -n "${card_info_reply}" | tail -c +3`
	local cardid=`echo -n "${card_info_reply}" | head -c $((${cardid_size} * 2))`
	local card_info_reply=`echo -n "${card_info_reply}" | tail -c +$(((${cardid_size} * 2) + 1))`

	# Extract number of slots
	local num_slots=`echo -n "${card_info_reply}" | head -c 4`
	local card_info_reply=`echo -n "${card_info_reply}" | tail -c +5`

	echo "Card Info:"
	echo "	Number of Slots: 0x${num_slots}"
	echo "	Card ID [Size: 0x${cardid_size_hex}]: 0x${cardid}"
}

# Update management PIN
update_pin() {
	local pin_txt="${1}"
	local pin_new="${2}"
	check_pin "${pin_txt}" 8
	check_pin "${pin_new}" 8
	check_auth "${pin_txt}"
	local card_info_reply=`fetch_cardinfo "${pin_txt}"`
	local cardid=`fetch_cardinfo_cardid "${card_info_reply}"`

	# Build hash data
	local hash_data=`echo -n "${pin_new}${cardid}"| xxd -r -p - |sha1sum | sed "s|  -||g"`
	# Build command
	local update_pin_cmd=`printf "%02x%s%02x%s" $((8/2)) ${pin_new} $((${#hash_data}/2)) ${hash_data}`
	local update_pin_cmd=`printf "00010200%02x%s" $((${#update_pin_cmd}/2)) ${update_pin_cmd}`

	# Execute command
	echo -n "Update Management PIN: "
	local update_pin=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "0001010004${pin_txt}" -s "${update_pin_cmd}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	local update_pin_errcode=`echo "${update_pin}"| grep "Received " | tail -n 1`
	echo "${update_pin_errcode}"| grep 'Received (SW1=0x90, SW2=0x00)' > /dev/null
	if [ "${?}" -ne 0 ]; then
		echo "failed [${card_auth_errcode}]"
		exit -1
	fi
	echo "OK"
}

# Execute action
case "${PSTOPT_ACTION}" in
	addkey )
		echo "Hello"
		;;
	printinfo )
		display_info "${PIN_ADMIN}"
		;;
	updatepin )
		update_pin "${PIN_ADMIN}" "${PIN_NEW}"
		;;
	updatepinemv )
		echo "Here"
		;;
esac
