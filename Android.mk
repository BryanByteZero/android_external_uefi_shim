LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_KERNEL_ARCH),i386)
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
LOCAL_SRC_FILES := ../../prebuilts/tools/linux-$(arch_name)/uefi_shim/MokManager.efi.signed
include $(BUILD_PREBUILT)

MOKMANAGER_EFI := $(PRODUCT_OUT)/efi/MokManager.efi

include $(CLEAR_VARS)
LOCAL_MODULE := shim.efi
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/efi
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
LOCAL_SRC_FILES := ../../prebuilts/tools/linux-$(arch_name)/uefi_shim/shim.efi
include $(BUILD_PREBUILT)

UEFI_SHIM_EFI := $(PRODUCT_OUT)/efi/shim.efi

