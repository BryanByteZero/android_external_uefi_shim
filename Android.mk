LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_UEFI_ARCH),i386)
arch_name := x86
else
arch_name := x86_64
endif

include $(CLEAR_VARS)
LOCAL_MODULE := MokManager.efi
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/efi
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
LOCAL_SRC_FILES := ../../prebuilts/tools/linux-$(arch_name)/uefi_shim/MokManager.efi
LOCAL_CERTIFICATE := SBSIGN
LOCAL_SBSIGN_CERTIFICATE := uefi_bios_db_key
include $(BUILD_PREBUILT)

MOKMANAGER_EFI := $(PRODUCT_OUT)/efi/MokManager.efi

include $(CLEAR_VARS)
LOCAL_MODULE := shim.efi
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/efi
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
LOCAL_SRC_FILES := ../../prebuilts/tools/linux-$(arch_name)/uefi_shim/shim.efi
LOCAL_CERTIFICATE := SBSIGN
LOCAL_SBSIGN_CERTIFICATE := uefi_bios_db_key
ifeq ($(USE_SHIM_KEY),true)
LOCAL_SBSIGN_BINARY_REPLACE_CERTIFICATE := device/intel/support/testkeys/shim/shim.crt:uefi_shim_key
endif
include $(BUILD_PREBUILT)

UEFI_SHIM_EFI := $(PRODUCT_OUT)/efi/shim.efi

ifeq ($(USE_SHIM_KEY),true)
# This will be packaged into the target file
# so that the certificate in the shim can be
# replace later.
TARGET_FILES_PACKAGE_DISCARD_FILES += \
	device/intel/support/testkeys/shim/shim.crt
endif
