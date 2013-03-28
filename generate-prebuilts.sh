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

PREBUILT_TOP=$ANDROID_BUILD_TOP/prebuilts/tools

copy_to_prebuilts()
{
    PREBUILT_FILES=" \
        MokManager.efi MokManager.unsigned.efi MokManager.debug.efi \
        shim.efi shim.unsigned.efi shim.debug.efi \
        "

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
    for F in $PREBUILT_FILES; do
        cp -v $F $PREBUILT_TOP/linux-$1/uefi_shim/
    done
}

add_prebuilts=0
while getopts "a" opt; do
    case "$opt" in
        a) add_prebuilts=1;;
    esac
done

# Check gnu-efi prebuilts are in place
NEEDED_FILES=" \
    linux-x86_64/gnu-efi/lib/crt0-efi-x86_64.o \
    linux-x86_64/gnu-efi/lib/libefi.a
    linux-x86_64/gnu-efi/lib/libgnuefi.a \
    linux-x86_64/gnu-efi/lib/elf_x86_64_efi.lds \
    linux-x86/gnu-efi/lib/crt0-efi-ia32.o \
    linux-x86/gnu-efi/lib/libefi.a
    linux-x86/gnu-efi/lib/libgnuefi.a \
    linux-x86/gnu-efi/lib/elf_ia32_efi.lds \
    "
have_all_files=1
for file in $NEEDED_FILES; do
    if [ ! -s "$PREBUILT_TOP/$file" ]; then
        echo "[ERROR] --- $file does not exists in external/gnu-efi/prebuilts/."
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

MAKE_CMD="make -f Makefile.android"

$MAKE_CMD ARCH=x86_64 clean
$MAKE_CMD ARCH=ia32 clean

# Generate prebuilts for x86_64
$MAKE_CMD -j10 ARCH=x86_64 \
    CC=$ANDROID_BUILD_TOP/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.7-4.6/bin/x86_64-linux-gcc
copy_to_prebuilts x86_64
$MAKE_CMD ARCH=x86_64 clean

# Generate prebuilts for ia32
$MAKE_CMD -j10 ARCH=ia32 \
    CC=$ANDROID_BUILD_TOP//prebuilts/gcc/linux-x86/host/i686-linux-glibc2.7-4.6/bin/i686-linux-gcc
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
