#!/bin/bash

COUNTER_VALUE=""
KEY_HEX=""
PIN_ADMIN=""
PIN_NEW=""
PSTOPT_ACTION=""
SCRIPTNAME=`basename ${0}`
SLOT_NUM=""

usage() {
	echo "${SCRIPTNAME}: PSOTP Admin Tool"
	echo "	-a			Add key"
	echo "	-c <counter value>	HOTP counter value"
	echo "	-e <new PIN>		Update EMV PIN"
	echo "	-k <key>		Key (as hex)"
	echo "	-h			Help text (this)"
	echo "	-i			Print card info"
	echo "	-m <PIN>		Management PIN"
	echo "	-n <new PIN>		Update management PIN"
	echo "	-s <slot num>		Slot number"
	exit 0
}

# Get CLI arguments
while getopts ":htaic:e:k:m:n:s:" opt; do
	case ${opt} in
		a )
			PSTOPT_ACTION="addkey"
			;;
		c )
			COUNTER_VALUE="${OPTARG}"
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
		s )
			SLOT_NUM="${OPTARG}"
			;;
		\? )
			echo "Invalid Argument: -${OPTARG}" 1>&2
			;;
	esac
done
if [[ "${PSTOPT_ACTION}" == "" ]]; then
	usage
fi

check_pin() {
	local pin_txt=${1}
	local pin_length=${2}
	local pin_txt_len=${#pin_txt}
	# Strip non-numeric characters from PIN
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

check_slotnum() {
	local slot_txt=${1}
	local slot_max=${2}
	local slot_txt_len=${#slot_txt}
	# Strip non-numeric characters from slot number
	local slot_len=`echo -n ${slot_txt}| sed 's|[^0-9]||g'| wc -c`
	if [[ "${slot_txt}" == "" ]]; then
		echo "${SCRIPTNAME}: Error: No slot number given"
		exit -1
	fi
	if [ "${slot_txt_len}" -ne "${slot_len}" ]; then
		echo "${SCRIPTNAME}: Error: Invalid slot number"
		exit -1
	fi
	if [ "${slot_txt}" -gt "$((${slot_max}-1))" ]; then
		echo "${SCRIPTNAME}: Error: Invalid slot number"
		exit -1
	fi
}

check_key() {
	local key_txt=${1}
	local key_txt_len=${#key_txt}
	# Strip non-hex characters from slot number
	local key_len=`echo -n ${key_txt}| sed 's|[^0-9a-fA-F]||g'| wc -c`
	if [[ "${key_txt}" == "" ]]; then
		echo "${SCRIPTNAME}: Error: No key given"
		exit -1
	fi
	if [ "${key_txt_len}" -ne "${key_len}" ]; then
		echo "${SCRIPTNAME}: Error: Invalid key"
		exit -1
	fi
}

check_counterval() {
	local counter_value=${1}
	local counter_value_len=${#counter_value}
	# Strip non-hex characters from counter value
	local countval_len=`echo -n ${counter_value}| sed 's|[^0-9]||g'| wc -c`
	if [ "${counter_value_len}" -ne "${countval_len}" ]; then
		echo "${SCRIPTNAME}: Error: Counter value"
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

# Process cardinfo reply, extract max slots
fetch_cardinfo_maxslots() {
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
	local card_info_reply=`echo -n "${card_info_reply}" | tail -c +$(((${cardid_size} * 2) + 1))`

	# Extract number of slots
	local num_slots=`echo -n "${card_info_reply}" | head -c 4`

	printf "%d" $((16#${num_slots}))
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
		echo "failed [${update_pin_errcode}]"
		exit -1
	fi
	echo "OK"
}

# Update EMV PIN
update_pin_emv() {
	local pin_txt="${1}"
	local pin_new="${2}"
	check_pin "${pin_txt}" 8
	check_pin "${pin_new}" 4
	check_auth "${pin_txt}"
	local card_info_reply=`fetch_cardinfo "${pin_txt}"`
	local cardid=`fetch_cardinfo_cardid "${card_info_reply}"`

	# Build hash data
	local hash_data=`echo -n "${pin_new}${cardid}"| xxd -r -p - |sha1sum | sed "s|  -||g"`
	# Build command
	local update_pin_cmd=`printf "%02x%s%02x%s" $((4/2)) ${pin_new} $((${#hash_data}/2)) ${hash_data}`
	local update_pin_cmd=`printf "00010300%02x%s" $((${#update_pin_cmd}/2)) ${update_pin_cmd}`

	# Execute command
	echo -n "Update EMV PIN: "
	local update_pin=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "0001010004${pin_txt}" -s "${update_pin_cmd}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	local update_pin_errcode=`echo "${update_pin}"| grep "Received " | tail -n 1`
	echo "${update_pin_errcode}"| grep 'Received (SW1=0x90, SW2=0x00)' > /dev/null
	if [ "${?}" -ne 0 ]; then
		echo "failed [${update_pin_errcode}]"
		exit -1
	fi
	echo "OK"
}

update_key_slot() {
	local pin_txt="${1}"
	local slot_num="${2}"
	local key_hex="${3}"
	local counter_value="${4}"
	check_pin "${pin_txt}" 8
	check_auth "${pin_txt}"
	local card_info_reply=`fetch_cardinfo "${pin_txt}"`
	local cardid=`fetch_cardinfo_cardid "${card_info_reply}"`
	local cardslots=`fetch_cardinfo_maxslots "${card_info_reply}"`
	check_slotnum "${slot_num}" "${cardslots}"
	check_key "${key_hex}"
	check_counterval "${counter_value}"

	# keyN<size bytes><slot number>
	local update_cmd_slotnum=`printf "6b65794e02%04x" ${slot_num}`
	# keyK<size bytes><key data>
	local update_cmd_keydata=`printf "6b65794b%02x%s" $((${#key_hex}/2)) ${key_hex}`
	# keyC<size bytes><counter value>
	local update_cmd_counterval=""
	if [[ "${counter_value}" != "" ]]; then
		local update_cmd_counterval=`printf "6b65794308%016x" ${counter_value}`
	fi
	# Build command primitive
	local update_cmd=`printf "%s%s%s" ${update_cmd_slotnum} ${update_cmd_keydata} ${update_cmd_counterval}`
	# Build hash data
	local hashdata=`echo -n "${update_cmd}${cardid}"| xxd -r -p - |sha1sum | sed "s|  -||g"`
	# keyH<size bytes><hash data>
	local update_cmd_hashdata=`printf "6b657948%02x%s" $((${#hashdata}/2)) ${hashdata}`
	# Build command
	local update_cmd=`printf "%s%s" ${update_cmd} ${update_cmd_hashdata}`
	local update_cmd=`printf "00020200%02x%s" $((${#update_cmd}/2)) ${update_cmd}`

	# Execute command
	echo -n "Update Slot[${slot_num}]: "
	local update_slot=`opensc-tool -s "00A404000da00000000380022e61646d696e" -s "0001010004${pin_txt}" -s "${update_cmd}" 2>/dev/null`
	if [ ${?} -ne 0 ]; then echo "Failed (Bad APDU)"; exit -1; fi
	local update_slot_errcode=`echo "${update_slot}"| grep "Received " | tail -n 1`
	echo "${update_slot_errcode}"| grep 'Received (SW1=0x90, SW2=0x00)' > /dev/null
	if [ "${?}" -ne 0 ]; then
		echo "failed [${update_slot_errcode}]"
		exit -1
	fi
	echo "OK"
}

# Execute action
case "${PSTOPT_ACTION}" in
	addkey )
		update_key_slot "${PIN_ADMIN}" "${SLOT_NUM}" "${KEY_HEX}" "${COUNTER_VALUE}"
		;;
	printinfo )
		display_info "${PIN_ADMIN}"
		;;
	updatepin )
		update_pin "${PIN_ADMIN}" "${PIN_NEW}"
		;;
	updatepinemv )
		update_pin_emv "${PIN_ADMIN}" "${PIN_NEW}"
		;;
esac
