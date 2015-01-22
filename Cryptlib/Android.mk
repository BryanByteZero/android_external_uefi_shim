LIBCRYPTLIB_LOCAL_PATH := $(call my-dir)
include $(call all-subdir-makefiles)
LOCAL_PATH := $(LIBCRYPTLIB_LOCAL_PATH)

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  Hash/CryptMd4.c \
		    Hash/CryptMd5.c \
		    Hash/CryptSha1.c \
		    Hash/CryptSha256.c \
		    Hmac/CryptHmacMd5.c \
		    Hmac/CryptHmacSha1.c \
		    Cipher/CryptAes.c \
		    Cipher/CryptTdes.c \
		    Cipher/CryptArc4.c \
		    Rand/CryptRand.c \
		    Pk/CryptRsaBasic.c \
		    Pk/CryptRsaExtNull.c \
		    Pk/CryptPkcs7SignNull.c \
		    Pk/CryptPkcs7Verify.c \
		    Pk/CryptDhNull.c \
		    Pk/CryptX509.c \
		    Pk/CryptAuthenticode.c \
		    Pem/CryptPem.c \
		    SysCall/CrtWrapper.c \
		    SysCall/TimerWrapper.c \
		    SysCall/BaseMemAllocation.c \
		    SysCall/BaseStrings.c

LOCAL_MODULE := libcryptlib
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/Include $(LOCAL_PATH)/Library $(LOCAL_PATH)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/Include
LOCAL_STATIC_LIBRARIES := libefi libgnuefi libopenssl-efi
include $(BUILD_EFI_STATIC_LIBRARY)

