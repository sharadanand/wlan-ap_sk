. /lib/functions/system.sh

RAMFS_COPY_BIN='fw_printenv fw_setenv'
RAMFS_COPY_DATA='/etc/fw_env.config /var/lock/fw_printenv.lock'

qca_do_upgrade() {
        local tar_file="$1"

        local board_dir=$(tar tf $tar_file | grep -m 1 '^sysupgrade-.*/$')
        board_dir=${board_dir%/}
	local dev=$(find_mtd_chardev "0:HLOS")

        tar Oxf $tar_file ${board_dir}/kernel | mtd write - ${dev}

        if [ -n "$UPGRADE_BACKUP" ]; then
                tar Oxf $tar_file ${board_dir}/root | mtd -j "$UPGRADE_BACKUP" write - rootfs
        else
                tar Oxf $tar_file ${board_dir}/root | mtd write - rootfs
        fi
}

find_mmc_part() {
	local DEVNAME PARTNAME

	if grep -q "$1" /proc/mtd; then
		echo "" && return 0
	fi

	for DEVNAME in /sys/block/mmcblk*/mmcblk*p*; do
		PARTNAME=$(grep PARTNAME ${DEVNAME}/uevent | cut -f2 -d'=')
		[ "$PARTNAME" = "$1" ] && echo "/dev/$(basename $DEVNAME)" && return 0
	done
}

do_flash_emmc() {
	local tar_file=$1
	local emmcblock=$(find_mmc_part $2)
	local board_dir=$3
	local part=$4

	[ -z "$emmcblock" ] && {
		echo failed to find $2
		return
	}

	echo erase $4
	dd if=/dev/zero of=${emmcblock} 2> /dev/null
	echo flash $4
	tar Oxf $tar_file ${board_dir}/$part | dd of=${emmcblock}
}

emmc_do_upgrade() {
	local tar_file="$1"

	local board_dir=$(tar tf $tar_file | grep -m 1 '^sysupgrade-.*/$')
	board_dir=${board_dir%/}
	do_flash_emmc $tar_file '0:HLOS' $board_dir kernel
	do_flash_emmc $tar_file 'rootfs' $board_dir root

	local emmcblock="$(find_mmc_part "rootfs_data")"
        if [ -e "$emmcblock" ]; then
                mkfs.ext4 -F "$emmcblock"
        fi
}

platform_check_image() {
	local magic_long="$(get_magic_long "$1")"
	board=$(board_name)
	case $board in
	cig,wf188|\
	cig,wf188n|\
	cig,wf194c|\
	cig,wf194c4|\
	cig,wf196|\
	cybertan,eww622-a1|\
	glinet,ax1800|\
	glinet,axt1800|\
	wallys,dr6018|\
	wallys,dr6018-v4|\
	edgecore,eap101|\
	edgecore,eap102|\
	edgecore,eap104|\
	edgecore,eap106|\
	hfcl,ion4xi|\
	hfcl,ion4xe|\
	tplink,ex227|\
	tplink,ex447|\
	yuncore,ax840|\
	motorola,q14|\
	qcom,ipq6018-cp01|\
	qcom,ipq807x-hk01|\
	qcom,ipq807x-hk14|\
	qcom,ipq5018-mp03.3|\
	kaiwoo,pax5400)
		[ "$magic_long" = "73797375" ] && return 0
		;;
	esac
	return 1
}

do_flash_mtd() {
	local bin=$1
	local mtdname=$2
	local append=""

	local mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')

	local pgsz=$(cat /sys/class/mtd/${mtdpart}/writesize)

	[ -f "$CONF_TAR" -a "$SAVE_CONFIG" -eq 1 -a "$2" == "rootfs" ] && append="-j $CONF_TAR"

	dd if=/tmp/${bin}.bin bs=${pgsz} conv=sync | mtd $append -e "/dev/${mtdpart}" write - "/dev/${mtdpart}"
}

do_flash_bootconfig() {
	local bin=$1
	local mtdname=$2

	# Fail safe upgrade
	if [ -f /proc/boot_info/getbinary_${bin} ]; then
		cat /proc/boot_info/getbinary_${bin} > /tmp/${bin}.bin
		do_flash_mtd $bin $mtdname
	fi
}

nand_do_upgrade_success_ipq() {
	local conf_tar="/tmp/sysupgrade.tgz"
	sync
	do_flash_bootconfig bootconfig "0:BOOTCONFIG"
	do_flash_bootconfig bootconfig1 "0:BOOTCONFIG1"
	[ -f "$conf_tar" ] && nand_restore_config "$conf_tar"
	echo "sysupgrade successful"
	umount -a
	reboot -f
}

nand_upgrade_tar_ipq() {
	local tar_file="$1"
	local kernel_mtd="$(find_mtd_index $CI_KERNPART)"

	local board_dir=$(tar tf "$tar_file" | grep -m 1 '^sysupgrade-.*/$')
	board_dir=${board_dir%/}

	kernel_length=$( (tar xf "$tar_file" ${board_dir}/kernel -O | wc -c) 2> /dev/null)
	local has_rootfs=0
	local rootfs_length
	local rootfs_type

	tar tf "$tar_file" ${board_dir}/root 1>/dev/null 2>/dev/null && has_rootfs=1
	[ "$has_rootfs" = "1" ] && {
		rootfs_length=$( (tar xf "$tar_file" ${board_dir}/root -O | wc -c) 2> /dev/null)
		rootfs_type="$(identify_tar "$tar_file" ${board_dir}/root)"
	}

	local has_kernel=1
	local has_env=0

	[ "$CI_IPQ807X" = 0 -a "$kernel_length" != 0 -a -n "$kernel_mtd" ] && {
		tar xf $tar_file ${board_dir}/kernel -O | mtd write - $CI_KERNPART
	}
	[ "$CI_IPQ807X" = 0 ] && {
		[ "$kernel_length" = 0 -o ! -z "$kernel_mtd" ] && has_kernel=
	}

	nand_upgrade_prepare_ubi "$rootfs_length" "$rootfs_type" "${has_kernel:+$kernel_length}" "$has_env"

	local ubidev="$( nand_find_ubi "$CI_UBIPART" )"
	[ "$has_kernel" = "1" ] && {
		local kern_ubivol="$( nand_find_volume $ubidev $CI_KERNPART )"
		tar xf "$tar_file" ${board_dir}/kernel -O | \
			ubiupdatevol /dev/$kern_ubivol -s $kernel_length -
	}

	[ "$has_rootfs" = "1" ] && {
		local root_ubivol="$( nand_find_volume $ubidev $CI_ROOTPART )"
		tar xf "$tar_file" ${board_dir}/root -O | \
			ubiupdatevol /dev/$root_ubivol -s $rootfs_length -
	}
	nand_do_upgrade_success_ipq
}


platform_do_upgrade() {
	CI_UBIPART="rootfs"
	CI_ROOTPART="ubi_rootfs"
	CI_IPQ807X=1

	board=$(board_name)
	case $board in
	cig,wf188)
		qca_do_upgrade $1
		;;
	motorola,q14)
		emmc_do_upgrade $1
		;;
	cig,wf188n|\
	cig,wf194c|\
	cig,wf194c4|\
	cig,wf196|\
	cybertan,eww622-a1|\
	edgecore,eap104|\
	glinet,ax1800|\
	glinet,axt1800|\
	qcom,ipq6018-cp01|\
	qcom,ipq807x-hk01|\
	qcom,ipq807x-hk14|\
	qcom,ipq5018-mp03.3|\
	wallys,dr6018|\
	wallys,dr6018-v4|\
	yuncore,ax840|\
	tplink,ex447|\
	tplink,ex227)
		nand_upgrade_tar "$1"
		;;
	hfcl,ion4xi|\
	hfcl,ion4xe)
		if grep -q rootfs_1 /proc/cmdline; then
			CI_UBIPART="rootfs"
			fw_setenv primary 0 || exit 1
		else
			CI_UBIPART="rootfs_1"
			fw_setenv primary 1 || exit 1
		fi
		nand_upgrade_tar "$1"
		;;
	edgecore,eap106)
		CI_UBIPART="rootfs1"
		[ "$(find_mtd_chardev rootfs)" ] && CI_UBIPART="rootfs"
		nand_upgrade_tar "$1"
		;;
	edgecore,eap101|\
	edgecore,eap102)
		if [ "$(find_mtd_chardev rootfs)" ]; then
			CI_UBIPART="rootfs"
		else
			if grep -q rootfs1 /proc/cmdline; then
				CI_UBIPART="rootfs2"
				fw_setenv active 2 || exit 1
			else
				CI_UBIPART="rootfs1"
				fw_setenv active 1 || exit 1
			fi
		fi
		nand_upgrade_tar "$1"
		;;
	kaiwoo,pax5400)
		CI_UBIPART="rootfs"

		#FIXME: Write better code here!
		[ -f /proc/boot_info/$CI_UBIPART/upgradepartition ] && {
			primaryboot=$(cat /proc/boot_info/$CI_UBIPART/primaryboot)
			if [ $primaryboot -eq 0 ]; then
				echo 1 > /proc/boot_info/$CI_UBIPART/primaryboot
			else
				echo 0 > /proc/boot_info/$CI_UBIPART/primaryboot
			fi
			CI_UBIPART=$(cat /proc/boot_info/$CI_UBIPART/upgradepartition)
		}

		nand_upgrade_tar_ipq "$1"
		;;
	esac
}
