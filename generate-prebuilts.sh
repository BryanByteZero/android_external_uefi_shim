#
# This script is used to generate gnu_efi prebuilts for both ia32 and x86_64.
# The resulting binaries will be copied into prebuilts/{ia32, x86_64}.
#
# Please make sure you have Android's build system setup first, and lunch
# target defined.
#
# Also, it requires the pesign utility from
#     https://github.com/vathpela/pesign
# You will need to build this by yourself using GCC 4.7.
#
# Specify "-a" in command line to add these prebuilt binaries for
# git commit.
#
# Note:
# 1. ARCH ia32 and x86 are interchangable here.
#    Android uses x86, but EFI uses ia32.
#

set -e
PREBUILT_TOP=$ANDROID_BUILD_TOP/hardware/intel/efi_prebuilts/

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "[ERROR] \$ANDROID_BUILD_TOP not set, please run lunch"
    exit 2
fi

DB_KEY_PAIR=$ANDROID_BUILD_TOP/device/intel/build/testkeys/DB
VENDOR_KEY_PAIR=$ANDROID_BUILD_TOP/device/intel/build/testkeys/vendor

rm -f db.key
openssl pkcs8 -nocrypt -inform DER -outform PEM -in ${DB_KEY_PAIR}.pk8 -out db.key

rm -f vendor.cer
openssl x509 -outform der -in ${VENDOR_KEY_PAIR}.x509.pem -out vendor.cer

copy_to_prebuilts()
{
    PREBUILT_FILES="MokManager.efi.signed shim.efi Cryptlib/OpenSSL/libopenssl.a"

    # Sanity check
    have_prebuilt_files=1
    for F in $PREBUILT_FILES; do
        if [ ! -s "$F" ] ; then
            echo "[ERROR] --- $1: $F does not exist or has size 0. aborting..."
            have_prebuilt_files=0
        fi
    done
    if [ "$have_prebuilt_files" == "0" ]; then
        echo "[ERROR] *** All build artifacts are not found for ARCH=$1. aborting..."
        exit 1
    fi

    # All files present. Copy them into prebuilts/
    rm -rf $PREBUILT_TOP/uefi_shim/linux-$1/
    mkdir -p $PREBUILT_TOP/uefi_shim/linux-$1/
    cp -v MokManager.efi.signed $PREBUILT_TOP/uefi_shim/linux-$1/MokManager.efi

    sbsign --key db.key --cert ${DB_KEY_PAIR}.x509.pem \
	    --output shim.efi.signed shim.efi

    cp -v shim.efi.signed $PREBUILT_TOP/uefi_shim/linux-$1/shim.efi
    cp -v Cryptlib/OpenSSL/libopenssl.a $PREBUILT_TOP/uefi_shim/linux-$1/libopenssl.a
    cp -rf Cryptlib/Include $PREBUILT_TOP/uefi_shim/linux-$1/
}

add_prebuilts=0
while getopts "a" opt; do
    case "$opt" in
        a) add_prebuilts=1;;
    esac
done

# Check gnu-efi prebuilts are in place
NEEDED_FILES=" \
    gnu-efi/linux-x86_64/lib/crt0-efi-x86_64.o \
    gnu-efi/linux-x86_64/lib/libefi.a
    gnu-efi/linux-x86_64/lib/libgnuefi.a \
    gnu-efi/linux-x86_64/lib/elf_x86_64_efi.lds \
    gnu-efi/linux-x86/lib/crt0-efi-ia32.o \
    gnu-efi/linux-x86/lib/libefi.a
    gnu-efi/linux-x86/lib/libgnuefi.a \
    gnu-efi/linux-x86/lib/elf_ia32_efi.lds \
    "

have_all_files=1
for file in $NEEDED_FILES; do
    if [ ! -s "$PREBUILT_TOP/$file" ]; then
        echo "[ERROR] --- $file does not exists in $PREBUILT_TOP."
        have_all_files=0
    fi
done
if [ "$have_all_files" == "0" ]; then
    echo "[ERROR] *** Please generate all necessary prebuilt binaries under external/gnu-efi before building uefi_shim."
    echo "[ERROR] *** Dependencies not satisfied. aborting..."
    exit 1
fi

# Clean up everything and create prebuilts directory
mkdir -p $PREBUILT_TOP/linux-x86/uefi_shim
mkdir -p $PREBUILT_TOP/linux-x86_64/uefi_shim

# Upstream Makefile heavily biased towards Fedora, we need to override
# a bunch of Make variables
EFI_PATH_64=$PREBUILT_TOP/gnu-efi/linux-x86_64
EFI_PATH_32=$PREBUILT_TOP/gnu-efi/linux-x86
LIB_PATH_64=$EFI_PATH_64/lib
LIB_PATH_32=$EFI_PATH_32/lib
EFI_INCLUDE_64=$EFI_PATH_64/include/efi
EFI_INCLUDE_32=$EFI_PATH_32/include/efi
EFI_CRT_OBJS_64=$LIB_PATH_64/crt0-efi-x86_64.o
EFI_CRT_OBJS_32=$LIB_PATH_32/crt0-efi-ia32.o
EFI_LDS_64=$LIB_PATH_64/elf_x86_64_efi.lds
EFI_LDS_32=$LIB_PATH_32/elf_ia32_efi.lds

MAKE_CMD="make -j12 DEFAULT_LOADER=\\\\\\\\gummiboot.efi"

$MAKE_CMD ARCH=x86_64 clean
$MAKE_CMD ARCH=ia32 clean

# Generate prebuilts for x86_64
$MAKE_CMD ARCH=x86_64 EFI_PATH=$EFI_PATH_64 LIB_PATH=$LIB_PATH_64 \
          EFI_INCLUDE=$EFI_INCLUDE_64 EFI_CRT_OBJS=$EFI_CRT_OBJS_64 \
          EFI_LDS=$EFI_LDS_64 VENDOR_CERT_FILE=vendor.cer
copy_to_prebuilts x86_64
$MAKE_CMD ARCH=x86_64 clean

# Generate prebuilts for ia32
$MAKE_CMD ARCH=ia32 EFI_PATH=$EFI_PATH_32 LIB_PATH=$LIB_PATH_32 \
          EFI_INCLUDE=$EFI_INCLUDE_32 EFI_CRT_OBJS=$EFI_CRT_OBJS_32 \
          EFI_LDS=$EFI_LDS_32 VENDOR_CERT_FILE=vendor.cer
copy_to_prebuilts x86
$MAKE_CMD ARCH=ia32 clean

if [ "$add_prebuilts" == "1" ]; then
    export GIT_DIR=$PREBUILT_TOP/.git
    export GIT_WORK_TREE=$PREBUILT_TOP

    git add -- linux-x86/uefi_shim/*
    git add -- linux-x86_64/uefi_shim/*

    unset GIT_DIR
    unset GIT_WORK_TREE

    echo "[NOTICE] Please remember to commit the prebuilts under $PREBUILT_TOP"
fi


echo "All done!"
