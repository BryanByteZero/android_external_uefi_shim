#ifndef SHIM_LOCK_H
#define SHIM_LOCK_H

#include "efi.h"
#include "efiapi.h"
#include "efilib.h"

#include "PeImage.h"

extern EFI_GUID SHIM_LOCK_GUID;

INTERFACE_DECL(_SHIM_LOCK);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_VERIFY) (
	IN VOID *buffer,
	IN UINT32 size
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_HASH) (
	IN char *data,
	IN int datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT *context,
	UINT8 *sha256hash,
	UINT8 *sha1hash
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_CONTEXT) (
	IN VOID *data,
	IN unsigned int datasize,
	PE_COFF_LOADER_IMAGE_CONTEXT *context
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_VERIFY_BLOB) (
	IN VOID *data,
	IN UINTN datasize,
	IN VOID *sig,
	IN UINTN sigsize
	);

typedef
EFI_STATUS
(*EFI_SHIM_LOCK_START_IMAGE) (
	IN EFI_HANDLE image_handle,
	IN CHAR16 *ImagePath
	);

typedef struct _SHIM_LOCK {
	EFI_SHIM_LOCK_VERIFY Verify;
	EFI_SHIM_LOCK_HASH Hash;
	EFI_SHIM_LOCK_CONTEXT Context;
	EFI_SHIM_LOCK_VERIFY_BLOB VerifyBlob;
	EFI_SHIM_LOCK_START_IMAGE StartImage;
} SHIM_LOCK;

#endif
