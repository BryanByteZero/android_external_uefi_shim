/*
 * shim - trivial UEFI first-stage bootloader
 *
 * Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Significant portions of this code are derived from Tianocore
 * (http://tianocore.sf.net) and are Copyright 2009-2012 Intel
 * Corporation.
 */

#include <efi.h>
#include <efilib.h>
#include <Library/BaseCryptLib.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "PeImage.h"
#include "shim.h"
#include "signature.h"
#include "netboot.h"

#include "ucs2.h"

#ifdef USE_SHIM_KEY
#include "shim_cert.h"
#endif

#define pr_error(fmt, ...) do { \
	Print(fmt, ##__VA_ARGS__); \
	pause(2); \
} while(0)

#define DEBUG_MESSAGES 0

#if DEBUG_MESSAGES
#define pr_debug(fmt, ...) do { \
	Print(fmt, ##__VA_ARGS__); \
	pause(2); \
} while(0)
#else
#define pr_debug(...) (void)0
#endif

#define DEFAULT_LOADER L"\\gummiboot.efi"
#define FALLBACK L"\\fallback.efi"
#define MOK_MANAGER L"\\MokManager.efi"

static EFI_SYSTEM_TABLE *systab;
static EFI_STATUS (EFIAPI *entry_point) (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);

static CHAR16 *second_stage;
static void *load_options;
static UINT32 load_options_size;

/*
 * The vendor certificate used for validating the second stage loader
 */
extern UINT8 vendor_cert[];
extern UINT32 vendor_cert_size;
extern EFI_SIGNATURE_LIST *vendor_dbx;
extern UINT32 vendor_dbx_size;

#define EFI_IMAGE_SECURITY_DATABASE_GUID { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }}

static UINT8 insecure_mode;

typedef enum {
	DATA_FOUND,
	DATA_NOT_FOUND,
	VAR_NOT_FOUND
} CHECK_STATUS;

typedef struct {
	UINT32 MokSize;
	UINT8 *Mok;
} MokListNode;


static void pause(int seconds)
{
	uefi_call_wrapper(BS->Stall, 1,  seconds * 1000000);
}

static EFI_STATUS get_variable (CHAR16 *name, EFI_GUID guid, UINT32 *attributes,
				UINTN *size, void **buffer)
{
	EFI_STATUS efi_status;
	char allocate = !(*size);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, name, &guid,
				       attributes, size, buffer);

	if (efi_status != EFI_BUFFER_TOO_SMALL || !allocate) {
		return efi_status;
	}

	*buffer = AllocatePool(*size);

	if (!*buffer) {
		pr_error(L"Unable to allocate variable buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, name, &guid,
				       attributes, size, *buffer);

	return efi_status;
}

/*
 * Perform basic bounds checking of the intra-image pointers
 */
static void *ImageAddress (void *image, int size, unsigned int address)
{
	if (address > size)
		return NULL;

	return image + address;
}

/*
 * Perform the actual relocation
 */
static EFI_STATUS relocate_coff (PE_COFF_LOADER_IMAGE_CONTEXT *context,
				 void *data)
{
	EFI_IMAGE_BASE_RELOCATION *RelocBase, *RelocBaseEnd;
	UINT64 Adjust;
	UINT16 *Reloc, *RelocEnd;
	char *Fixup, *FixupBase, *FixupData = NULL;
	UINT16 *Fixup16;
	UINT32 *Fixup32;
	UINT64 *Fixup64;
	int size = context->ImageSize;
	void *ImageEnd = (char *)data + size;

#if __LP64__
	context->PEHdr->Pe32Plus.OptionalHeader.ImageBase = (UINT64)data;
#else
	context->PEHdr->Pe32.OptionalHeader.ImageBase = (UINT32)data;
#endif

	if (context->NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		pr_error(L"Image has no relocation entry\n");
		return EFI_UNSUPPORTED;
	}

	RelocBase = ImageAddress(data, size, context->RelocDir->VirtualAddress);
	RelocBaseEnd = ImageAddress(data, size, context->RelocDir->VirtualAddress + context->RelocDir->Size - 1);

	if (!RelocBase || !RelocBaseEnd) {
		pr_error(L"Reloc table overflows binary\n");
		return EFI_UNSUPPORTED;
	}

	Adjust = (UINTN)data - context->ImageAddress;

	while (RelocBase < RelocBaseEnd) {
		Reloc = (UINT16 *) ((char *) RelocBase + sizeof (EFI_IMAGE_BASE_RELOCATION));
		RelocEnd = (UINT16 *) ((char *) RelocBase + RelocBase->SizeOfBlock);

		if ((void *)RelocEnd < data || (void *)RelocEnd > ImageEnd) {
			pr_error(L"Reloc entry overflows binary\n");
			return EFI_UNSUPPORTED;
		}

		FixupBase = ImageAddress(data, size, RelocBase->VirtualAddress);
		if (!FixupBase) {
			pr_error(L"Invalid fixupbase\n");
			return EFI_UNSUPPORTED;
		}

		while (Reloc < RelocEnd) {
			Fixup = FixupBase + (*Reloc & 0xFFF);
			switch ((*Reloc) >> 12) {
			case EFI_IMAGE_REL_BASED_ABSOLUTE:
				break;

			case EFI_IMAGE_REL_BASED_HIGH:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16 = (UINT16) (*Fixup16 + ((UINT16) ((UINT32) Adjust >> 16)));
				if (FixupData != NULL) {
					*(UINT16 *) FixupData = *Fixup16;
					FixupData             = FixupData + sizeof (UINT16);
				}
				break;

			case EFI_IMAGE_REL_BASED_LOW:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16  = (UINT16) (*Fixup16 + (UINT16) Adjust);
				if (FixupData != NULL) {
					*(UINT16 *) FixupData = *Fixup16;
					FixupData             = FixupData + sizeof (UINT16);
				}
				break;

			case EFI_IMAGE_REL_BASED_HIGHLOW:
				Fixup32   = (UINT32 *) Fixup;
				*Fixup32  = *Fixup32 + (UINT32) Adjust;
				if (FixupData != NULL) {
					FixupData             = ALIGN_POINTER (FixupData, sizeof (UINT32));
					*(UINT32 *)FixupData  = *Fixup32;
					FixupData             = FixupData + sizeof (UINT32);
				}
				break;

			case EFI_IMAGE_REL_BASED_DIR64:
				Fixup64 = (UINT64 *) Fixup;
				*Fixup64 = *Fixup64 + (UINT64) Adjust;
				if (FixupData != NULL) {
					FixupData = ALIGN_POINTER (FixupData, sizeof(UINT64));
					*(UINT64 *)(FixupData) = *Fixup64;
					FixupData = FixupData + sizeof(UINT64);
				}
				break;

			default:
				pr_error(L"Unknown relocation\n");
				return EFI_UNSUPPORTED;
			}
			Reloc += 1;
		}
		RelocBase = (EFI_IMAGE_BASE_RELOCATION *) RelocEnd;
	}

	return EFI_SUCCESS;
}

static CHECK_STATUS check_db_cert_in_ram(EFI_SIGNATURE_LIST *CertList,
					 UINTN dbsize,
					 WIN_CERTIFICATE_EFI_PKCS *data,
					 UINT8 *hash)
{
	EFI_SIGNATURE_DATA *Cert;
	UINTN CertCount, Index;
	BOOLEAN IsFound = FALSE;
	EFI_GUID CertType = EfiCertX509Guid;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if (CompareGuid (&CertList->SignatureType, &CertType) == 0) {
			CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
			for (Index = 0; Index < CertCount; Index++) {
				IsFound = AuthenticodeVerify (data->CertData,
							      data->Hdr.dwLength - sizeof(data->Hdr),
							      Cert->SignatureData,
							      CertList->SignatureSize,
							      hash, SHA256_DIGEST_SIZE);
				if (IsFound)
					break;

				Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
			}

		}

		if (IsFound)
			break;

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	if (IsFound)
		return DATA_FOUND;

	return DATA_NOT_FOUND;
}

static CHECK_STATUS check_db_cert(CHAR16 *dbname, EFI_GUID guid,
				  WIN_CERTIFICATE_EFI_PKCS *data, UINT8 *hash)
{
	CHECK_STATUS rc;
	EFI_STATUS efi_status;
	EFI_SIGNATURE_LIST *CertList;
	UINTN dbsize = 0;
	UINT32 attributes;
	void *db;

	efi_status = get_variable(dbname, guid, &attributes, &dbsize, &db);

	if (efi_status != EFI_SUCCESS)
		return VAR_NOT_FOUND;

	CertList = db;

	rc = check_db_cert_in_ram(CertList, dbsize, data, hash);

	FreePool(db);

	return rc;
}

/*
 * Check a hash against an EFI_SIGNATURE_LIST in a buffer
 */
static CHECK_STATUS check_db_hash_in_ram(EFI_SIGNATURE_LIST *CertList,
					 UINTN dbsize, UINT8 *data,
					 int SignatureSize, EFI_GUID CertType)
{
	EFI_SIGNATURE_DATA *Cert;
	UINTN CertCount, Index;
	BOOLEAN IsFound = FALSE;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
		Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
		if (CompareGuid(&CertList->SignatureType, &CertType) == 0) {
			for (Index = 0; Index < CertCount; Index++) {
				if (CompareMem (Cert->SignatureData, data, SignatureSize) == 0) {
					//
					// Find the signature in database.
					//
					IsFound = TRUE;
					break;
				}

				Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
			}
			if (IsFound) {
				break;
			}
		}

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	if (IsFound)
		return DATA_FOUND;

	return DATA_NOT_FOUND;
}

/*
 * Check a hash against an EFI_SIGNATURE_LIST in a UEFI variable
 */
static CHECK_STATUS check_db_hash(CHAR16 *dbname, EFI_GUID guid, UINT8 *data,
				  int SignatureSize, EFI_GUID CertType)
{
	EFI_STATUS efi_status;
	EFI_SIGNATURE_LIST *CertList;
	UINT32 attributes;
	UINTN dbsize = 0;
	void *db;

	efi_status = get_variable(dbname, guid, &attributes, &dbsize, &db);

	if (efi_status != EFI_SUCCESS) {
		return VAR_NOT_FOUND;
	}

	CertList = db;

	CHECK_STATUS rc = check_db_hash_in_ram(CertList, dbsize, data,
						SignatureSize, CertType);
	FreePool(db);
	return rc;

}

/*
 * Check whether the binary signature or hash are present in dbx or the
 * built-in blacklist
 */
static EFI_STATUS check_blacklist (WIN_CERTIFICATE_EFI_PKCS *cert,
				   UINT8 *sha256hash, UINT8 *sha1hash)
{
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;

	if (check_db_hash_in_ram(vendor_dbx, vendor_dbx_size, sha256hash,
				 SHA256_DIGEST_SIZE, EfiHashSha256Guid) ==
				DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_hash_in_ram(vendor_dbx, vendor_dbx_size, sha1hash,
				 SHA1_DIGEST_SIZE, EfiHashSha1Guid) ==
				DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_cert_in_ram(vendor_dbx, vendor_dbx_size, cert,
				 sha256hash) == DATA_FOUND)
		return EFI_ACCESS_DENIED;

	if (check_db_hash(L"dbx", secure_var, sha256hash, SHA256_DIGEST_SIZE,
			  EfiHashSha256Guid) == DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_hash(L"dbx", secure_var, sha1hash, SHA1_DIGEST_SIZE,
			  EfiHashSha1Guid) == DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_cert(L"dbx", secure_var, cert, sha256hash) == DATA_FOUND)
		return EFI_ACCESS_DENIED;

	return EFI_SUCCESS;
}

/*
 * Check whether the binary signature or hash are present in db or MokList
 */
static EFI_STATUS check_whitelist (WIN_CERTIFICATE_EFI_PKCS *cert,
				   UINT8 *sha256hash, UINT8 *sha1hash)
{
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	EFI_GUID shim_var = SHIM_LOCK_GUID;

	if (check_db_hash(L"db", secure_var, sha256hash, SHA256_DIGEST_SIZE,
			  EfiHashSha256Guid) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_hash(L"db", secure_var, sha1hash, SHA1_DIGEST_SIZE,
			  EfiHashSha1Guid) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_hash(L"MokList", shim_var, sha256hash, SHA256_DIGEST_SIZE,
			  EfiHashSha256Guid) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_cert(L"db", secure_var, cert, sha256hash) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_cert(L"MokList", shim_var, cert, sha256hash) == DATA_FOUND)
		return EFI_SUCCESS;

	return EFI_ACCESS_DENIED;
}

/*
 * Check whether we're in Secure Boot and user mode
 */

static BOOLEAN secure_mode (void)
{
	EFI_STATUS status;
	EFI_GUID global_var = EFI_GLOBAL_VARIABLE;
	UINTN charsize = sizeof(char);
	UINT8 sb, setupmode;
	UINT32 attributes;

	if (insecure_mode)
		return FALSE;

	status = get_variable(L"SecureBoot", global_var, &attributes, &charsize,
			      (void *)&sb);

	/* FIXME - more paranoia here? */
	if (status != EFI_SUCCESS || sb != 1) {
		pr_debug(L"Secure boot not enabled\n");
		return FALSE;
	}
	status = get_variable(L"SetupMode", global_var, &attributes, &charsize,
			      (void *)&setupmode);

	if (status == EFI_SUCCESS && setupmode == 1) {
		pr_debug(L"Platform is in setup mode\n");
		return FALSE;
	}

	return TRUE;
}

/*
 * Calculate the SHA1 and SHA256 hashes of a binary
 */

static EFI_STATUS generate_hash (char *data, int datasize,
				 PE_COFF_LOADER_IMAGE_CONTEXT *context,
				 UINT8 *sha256hash, UINT8 *sha1hash)

{
	unsigned int sha256ctxsize, sha1ctxsize;
	unsigned int size = datasize;
	void *sha256ctx = NULL, *sha1ctx = NULL;
	char *hashbase;
	unsigned int hashsize;
	unsigned int SumOfBytesHashed, SumOfSectionBytes;
	unsigned int index, pos;
	EFI_IMAGE_SECTION_HEADER  *Section;
	EFI_IMAGE_SECTION_HEADER  *SectionHeader = NULL;
	EFI_IMAGE_SECTION_HEADER  *SectionCache;
	EFI_STATUS status = EFI_SUCCESS;

	sha256ctxsize = Sha256GetContextSize();
	sha256ctx = AllocatePool(sha256ctxsize);

	sha1ctxsize = Sha1GetContextSize();
	sha1ctx = AllocatePool(sha1ctxsize);

	if (!sha256ctx || !sha1ctx) {
		pr_error(L"Unable to allocate memory for hash context\n");
		return EFI_OUT_OF_RESOURCES;
	}

	if (!Sha256Init(sha256ctx) || !Sha1Init(sha1ctx)) {
		pr_error(L"Unable to initialise hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash start to checksum */
	hashbase = data;
	hashsize = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum -
		hashbase;

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		pr_error(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash post-checksum to start of certificate table */
	hashbase = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum +
		sizeof (int);
	hashsize = (char *)context->SecDir - hashbase;

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		pr_error(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash end of certificate table to end of image header */
#if __LP64__
	hashbase = (char *) &context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
	hashsize = context->PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders -
		(int) ((char *) (&context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1]) - data);
#else
	hashbase = (char *) &context->PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
	hashsize = context->PEHdr->Pe32.OptionalHeader.SizeOfHeaders -
		(int) ((char *) (&context->PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1]) - data);
#endif

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		pr_error(L"Unable to generate hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Sort sections */
#if __LP64__
	SumOfBytesHashed = context->PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
#else
	SumOfBytesHashed = context->PEHdr->Pe32.OptionalHeader.SizeOfHeaders;
#endif

	Section = (EFI_IMAGE_SECTION_HEADER *) (
		(char *)context->PEHdr + sizeof (UINT32) +
		sizeof (EFI_IMAGE_FILE_HEADER) +
		context->PEHdr->Pe32.FileHeader.SizeOfOptionalHeader
		);

	SectionCache = Section;

	for (index = 0, SumOfSectionBytes = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++, SectionCache++) {
		SumOfSectionBytes += SectionCache->SizeOfRawData;
	}

	if (SumOfSectionBytes >= datasize) {
		pr_error(L"Malformed binary: %x %x\n", SumOfSectionBytes, size);
		status = EFI_INVALID_PARAMETER;
		goto done;
	}

	SectionHeader = (EFI_IMAGE_SECTION_HEADER *) AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER) * context->PEHdr->Pe32.FileHeader.NumberOfSections);
	if (SectionHeader == NULL) {
		pr_error(L"Unable to allocate section header\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Sort the section headers */
	for (index = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++) {
		pos = index;
		while ((pos > 0) && (Section->PointerToRawData < SectionHeader[pos - 1].PointerToRawData)) {
			CopyMem (&SectionHeader[pos], &SectionHeader[pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		CopyMem (&SectionHeader[pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
		Section += 1;
	}

	/* Hash the sections */
	for (index = 0; index < context->PEHdr->Pe32.FileHeader.NumberOfSections; index++) {
		Section = &SectionHeader[index];
		if (Section->SizeOfRawData == 0) {
			continue;
		}
		hashbase  = ImageAddress(data, size, Section->PointerToRawData);
		hashsize  = (unsigned int) Section->SizeOfRawData;

		if (!hashbase) {
			pr_error(L"Malformed section header\n");
			status = EFI_INVALID_PARAMETER;
			goto done;
		}

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			pr_error(L"Unable to generate hash\n");
			status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
		SumOfBytesHashed += Section->SizeOfRawData;
	}

	/* Hash all remaining data */
	if (size > SumOfBytesHashed) {
		hashbase = data + SumOfBytesHashed;
		hashsize = (unsigned int)(
			size -
#if __LP64__
			context->PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size -
#else
			context->PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size -
#endif
			SumOfBytesHashed);

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			pr_error(L"Unable to generate hash\n");
			status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
	}

	if (!(Sha256Final(sha256ctx, sha256hash)) ||
	    !(Sha1Final(sha1ctx, sha1hash))) {
		pr_error(L"Unable to finalise hash\n");
		status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

done:
	if (SectionHeader)
		FreePool(SectionHeader);
	if (sha1ctx)
		FreePool(sha1ctx);
	if (sha256ctx)
		FreePool(sha256ctx);

	return status;
}

/*
 * Ensure that the MOK database hasn't been set or modified from an OS
 */
static EFI_STATUS verify_mok (void) {
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS status = EFI_SUCCESS;
	void *MokListData = NULL;
	UINTN MokListDataSize = 0;
	UINT32 attributes;

	status = get_variable(L"MokList", shim_lock_guid, &attributes,
			      &MokListDataSize, &MokListData);

	if (!EFI_ERROR(status) && attributes & EFI_VARIABLE_RUNTIME_ACCESS) {
		pr_error(L"MokList is compromised!\nErase all keys in MokList!\n");
		if (LibDeleteVariable(L"MokList", &shim_lock_guid) != EFI_SUCCESS) {
			pr_error(L"Failed to erase MokList\n");
			return EFI_ACCESS_DENIED;
		}
	}

	return EFI_SUCCESS;
}


static VOID pr_error_openssl(void)
{
	unsigned long code;

	while ( (code = ERR_get_error()) )
		/* Sadly, can't print out the friendly error string  because
		 * all the BIO snprintf() functions are stubbed out due to the
		 * lack of most 8-bit string functions in gnu-efi. Look up the
		 * codes using 'openssl errstr' in a shell */
		pr_error(L"openssl error code %08X\n", code);
}


static EVP_PKEY *get_pkey(UINT8 *cert, UINTN certsize)
{
	BIO *bio;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;

	/* BIO is the OpenSSL input/output abstraction. Instantiate
	 * one using a memory buffer containing the certificate */
	bio = BIO_new_mem_buf(cert, certsize);
	if (!bio) {
		return NULL;
	}

	/* Obtain an x509 structure from the DER cert data */
	x509 = d2i_X509_bio(bio, NULL);
	if (!x509) {
		goto done;
	}

        /* And finally get the public key out of the certificate */
	pkey = X509_get_pubkey(x509);
	if (!pkey) {
		goto done;
	}

	if (EVP_PKEY_RSA != EVP_PKEY_type(pkey->type)) {
		pr_error(L"not an RSA key!");
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
done:
	if (bio != NULL)
		BIO_free(bio);
	if (x509 != NULL)
		X509_free(x509);
	return pkey;
}


static BOOLEAN openssl_verify(
		IN UINT8 *sig, IN UINTN sigsize,
		IN UINT8 *cert, IN UINTN certsize,
		IN UINT8 *hash, IN UINTN hashsize)
{
	EVP_PKEY *pkey;
	UINTN ret;

	if (!sig || !cert || !hash)
		return FALSE;

	pkey = get_pkey(cert, certsize);
	if (!pkey) {
		pr_error(L"Unable to extract public key from certificate\n");
		return FALSE;
	}

	ret = RSA_verify(NID_sha256, hash, hashsize, sig, sigsize,
			EVP_PKEY_get1_RSA(pkey));
	EVP_PKEY_free(pkey);
	return (ret == 1) ? TRUE : FALSE;
}


static CHECK_STATUS check_db_blob_sig_in_ram(
		IN EFI_SIGNATURE_LIST *CertList,
		IN UINTN dbsize,
		IN UINT8 *data,
		IN UINTN datasize,
		IN UINT8 *hash)
{
	EFI_SIGNATURE_DATA *Cert;
	UINTN CertCount, Index;
	BOOLEAN IsFound = FALSE;
	EFI_GUID CertType = EfiCertX509Guid;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if (CompareGuid (&CertList->SignatureType, &CertType) == 0) {
			CertCount = (CertList->SignatureListSize - CertList->SignatureHeaderSize) / CertList->SignatureSize;
			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
			for (Index = 0; Index < CertCount; Index++) {
				IsFound = openssl_verify (data, datasize,
							  Cert->SignatureData,
							  CertList->SignatureSize,
							  hash, SHA256_DIGEST_SIZE);
				if (IsFound)
					break;

				Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
			}

		}

		if (IsFound)
			break;

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	if (IsFound)
		return DATA_FOUND;

	return DATA_NOT_FOUND;
}


static CHECK_STATUS check_db_blob_sig(
		CHAR16 *dbname, EFI_GUID guid,
		UINT8 *data, UINTN datasize,
		UINT8 *hash)
{
	CHECK_STATUS rc;
	EFI_STATUS efi_status;
	EFI_SIGNATURE_LIST *CertList;
	UINTN dbsize = 0;
	UINT32 attributes;
	void *db;

	efi_status = get_variable(dbname, guid, &attributes, &dbsize, &db);

	if (efi_status != EFI_SUCCESS)
		return VAR_NOT_FOUND;

	CertList = db;

	rc = check_db_blob_sig_in_ram(CertList, dbsize, data, datasize, hash);

	FreePool(db);

	return rc;
}

/*
 * Check whether the binary signature or hash are present in dbx or the
 * built-in blacklist
 */
static EFI_STATUS blob_check_blacklist (
	IN UINT8 *sig,
	IN UINTN sigsize,
	UINT8 *sha256hash)
{
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;

	if (check_db_hash_in_ram(vendor_dbx, vendor_dbx_size, sha256hash,
				 SHA256_DIGEST_SIZE, EfiHashSha256Guid) ==
				DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_blob_sig_in_ram(vendor_dbx, vendor_dbx_size, sig, sigsize,
				 sha256hash) == DATA_FOUND)
		return EFI_ACCESS_DENIED;

	if (check_db_hash(L"dbx", secure_var, sha256hash, SHA256_DIGEST_SIZE,
			  EfiHashSha256Guid) == DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_blob_sig(L"dbx", secure_var, sig, sigsize, sha256hash) == DATA_FOUND)
		return EFI_ACCESS_DENIED;

	return EFI_SUCCESS;
}

/*
 * Check whether the binary signature or hash are present in db or MokList
 */
static EFI_STATUS blob_check_whitelist (
		IN UINT8 *sig,
		IN UINTN sigsize,
		UINT8 *sha256hash)
{
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	EFI_GUID shim_var = SHIM_LOCK_GUID;

	if (check_db_hash(L"db", secure_var, sha256hash, SHA256_DIGEST_SIZE,
			EfiHashSha256Guid) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_hash(L"MokList", shim_var, sha256hash, SHA256_DIGEST_SIZE,
			EfiHashSha256Guid) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_blob_sig(L"db", secure_var, sig, sigsize, sha256hash) == DATA_FOUND)
		return EFI_SUCCESS;
	if (check_db_blob_sig(L"MokList", shim_var, sig, sigsize, sha256hash) == DATA_FOUND)
		return EFI_SUCCESS;

	return EFI_ACCESS_DENIED;
}


static EFI_STATUS verify_generic_blob (VOID *data, UINTN datasize,
			VOID *sig, UINTN sigsize)
{
	SHA256_CTX sha_ctx;
	UINT8 digest[SHA256_DIGEST_LENGTH];

	if (1 != SHA256_Init(&sha_ctx))
		return EFI_INVALID_PARAMETER;

	if (1 != SHA256_Update(&sha_ctx, data, datasize))
		return EFI_INVALID_PARAMETER;

	if (1 != SHA256_Final(digest, &sha_ctx))
		return EFI_INVALID_PARAMETER;

	if (EFI_ERROR(verify_mok())) {
		pr_error(L"MokList is compromised and could not be erased");
		return EFI_ACCESS_DENIED;
	}

	pr_debug(L"Check black/whitelists\n");
	if (EFI_ERROR(blob_check_blacklist(sig, sigsize, digest))) {
		pr_error(L"Binary is blacklisted");
		return EFI_ACCESS_DENIED;
	}

	if (EFI_SUCCESS == blob_check_whitelist(sig, sigsize, digest)) {
		pr_debug(L"Binary is whitelisted");
		return EFI_SUCCESS;
	}
#ifdef USE_SHIM_KEY
	pr_debug(L"Try verifying with shim certificate\n");
	if (openssl_verify(sig, sigsize, shim_cert, sizeof(shim_cert),
				digest, SHA256_DIGEST_LENGTH)) {
		pr_debug(L"Blob is verified by the shim certificate\n");
		return EFI_SUCCESS;
	}
#endif
	pr_debug(L"Try verifying with vendor certificate\n");
	if (openssl_verify(sig, sigsize, vendor_cert, vendor_cert_size,
				digest, SHA256_DIGEST_LENGTH)) {
		pr_debug(L"Blob is verified by the vendor certificate\n");
		return EFI_SUCCESS;
	}

	pr_error_openssl();
	pr_error(L"Invalid signature\n");
	return EFI_ACCESS_DENIED;
}


/*
 * Check that the signature is valid and matches the binary
 */
static EFI_STATUS verify_buffer (char *data, int datasize,
			 PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	UINT8 sha256hash[SHA256_DIGEST_SIZE];
	UINT8 sha1hash[SHA1_DIGEST_SIZE];
	EFI_STATUS status = EFI_ACCESS_DENIED;
	WIN_CERTIFICATE_EFI_PKCS *cert;
	unsigned int size = datasize;

	if (context->SecDir->Size == 0) {
		pr_error(L"Empty security header\n");
		return EFI_INVALID_PARAMETER;
	}

	cert = ImageAddress (data, size, context->SecDir->VirtualAddress);

	if (!cert) {
		pr_error(L"Certificate located outside the image\n");
		return EFI_INVALID_PARAMETER;
	}

	if (cert->Hdr.wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
		pr_error(L"Unsupported certificate type %x\n",
		      cert->Hdr.wCertificateType);
		return EFI_UNSUPPORTED;
	}

	status = generate_hash(data, datasize, context, sha256hash, sha1hash);

	if (status != EFI_SUCCESS)
		return status;

	/*
	 * Check that the MOK database hasn't been modified
	 */
	status = verify_mok();
	if (status != EFI_SUCCESS)
		return status;

	/*
	 * Ensure that the binary isn't blacklisted
	 */
	status = check_blacklist(cert, sha256hash, sha1hash);

	if (status != EFI_SUCCESS) {
		pr_error(L"Binary is blacklisted\n");
		return status;
	}

	/*
	 * Check whether the binary is whitelisted in any of the firmware
	 * databases
	 */
	status = check_whitelist(cert, sha256hash, sha1hash);

	if (status == EFI_SUCCESS) {
		pr_debug(L"Binary is whitelisted\n");
		return status;
	}

#ifdef USE_SHIM_KEY
	/*
	 * Check against the shim build key
	 */
	if (AuthenticodeVerify(cert->CertData,
			       context->SecDir->Size - sizeof(cert->Hdr),
			       shim_cert, sizeof(shim_cert), sha256hash,
			       SHA256_DIGEST_SIZE)) {
		status = EFI_SUCCESS;
		pr_debug(L"Binary is verified by the shim certificate\n");
		return status;
	}
#endif

	/*
	 * And finally, check against shim's built-in key
	 */
	if (AuthenticodeVerify(cert->CertData,
			       context->SecDir->Size - sizeof(cert->Hdr),
			       vendor_cert, vendor_cert_size, sha256hash,
			       SHA256_DIGEST_SIZE)) {
		status = EFI_SUCCESS;
		pr_debug(L"Binary is verified by the vendor certificate\n");
		return status;
	}

	pr_error(L"Invalid signature\n");
	status = EFI_ACCESS_DENIED;

	return status;
}

/*
 * Read the binary header and grab appropriate information from it
 */
static EFI_STATUS read_header(void *data, unsigned int datasize,
			      PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	EFI_IMAGE_DOS_HEADER *DosHdr = data;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;

	if (datasize < sizeof(EFI_IMAGE_DOS_HEADER)) {
		pr_error(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE)
		PEHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);

	if ((((UINT8 *)PEHdr - (UINT8 *)data) + sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION)) > datasize) {
		pr_error(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		pr_error(L"Unsupported image type\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		pr_error(L"Unsupported image - Relocations have been stripped\n");
		return EFI_UNSUPPORTED;
	}

	context->PEHdr = PEHdr;
#if __LP64__
	context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
	context->ImageSize = (UINT64)PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
	context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
	context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
	context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
	context->SecDir = (EFI_IMAGE_DATA_DIRECTORY *) &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
#else
	context->ImageAddress = PEHdr->Pe32.OptionalHeader.ImageBase;
	context->ImageSize = (UINT64)PEHdr->Pe32.OptionalHeader.SizeOfImage;
	context->SizeOfHeaders = PEHdr->Pe32.OptionalHeader.SizeOfHeaders;
	context->EntryPoint = PEHdr->Pe32.OptionalHeader.AddressOfEntryPoint;
	context->RelocDir = &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	context->NumberOfRvaAndSizes = PEHdr->Pe32.OptionalHeader.NumberOfRvaAndSizes;
	context->SecDir = (EFI_IMAGE_DATA_DIRECTORY *) &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
#endif
	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;
	context->FirstSection = (EFI_IMAGE_SECTION_HEADER *)((char *)PEHdr + PEHdr->Pe32.FileHeader.SizeOfOptionalHeader + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER));
	if (context->ImageSize < context->SizeOfHeaders) {
		pr_error(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (((UINT8 *)context->SecDir - (UINT8 *)data) > (datasize - sizeof(EFI_IMAGE_DATA_DIRECTORY))) {
		pr_error(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (context->SecDir->VirtualAddress >= datasize) {
		pr_error(L"Malformed security header\n");
		return EFI_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

/*
 * Once the image has been loaded it needs to be validated and relocated
 */
static EFI_STATUS handle_image (void *data, unsigned int datasize,
				EFI_LOADED_IMAGE *li)
{
	EFI_STATUS efi_status;
	char *buffer;
	int i, size;
	EFI_IMAGE_SECTION_HEADER *Section;
	char *base, *end;
	PE_COFF_LOADER_IMAGE_CONTEXT context;

	/*
	 * The binary header contains relevant context and section pointers
	 */
	efi_status = read_header(data, datasize, &context);
	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Failed to read header\n");
		return efi_status;
	}

	/*
	 * We only need to verify the binary if we're in secure mode
	 */
	if (secure_mode ()) {
		efi_status = verify_buffer(data, datasize, &context);

		if (efi_status != EFI_SUCCESS) {
			pr_error(L"Verification failed\n");
			return efi_status;
		}
	}

	buffer = AllocatePool(context.ImageSize);

	if (!buffer) {
		pr_error(L"Failed to allocate image buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}

	CopyMem(buffer, data, context.SizeOfHeaders);

	/*
	 * Copy the executable's sections to their desired offsets
	 */
	Section = context.FirstSection;
	for (i = 0; i < context.NumberOfSections; i++) {
		size = Section->Misc.VirtualSize;

		if (size > Section->SizeOfRawData)
			size = Section->SizeOfRawData;

		base = ImageAddress (buffer, context.ImageSize, Section->VirtualAddress);
		end = ImageAddress (buffer, context.ImageSize, Section->VirtualAddress + size - 1);

		if (!base || !end) {
			pr_error(L"Invalid section size\n");
			return EFI_UNSUPPORTED;
		}

		if (Section->SizeOfRawData > 0)
			CopyMem(base, data + Section->PointerToRawData, size);

		if (size < Section->Misc.VirtualSize)
			ZeroMem (base + size, Section->Misc.VirtualSize - size);

		Section += 1;
	}

	/*
	 * Run the relocation fixups
	 */
	efi_status = relocate_coff(&context, buffer);

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Relocation failed\n");
		FreePool(buffer);
		return efi_status;
	}

	entry_point = ImageAddress(buffer, context.ImageSize, context.EntryPoint);
	/*
	 * grub needs to know its location and size in memory, so fix up
	 * the loaded image protocol values
	 */
	li->ImageBase = buffer;
	li->ImageSize = context.ImageSize;

	/* Pass the load options to the second stage loader */
	li->LoadOptions = load_options;
	li->LoadOptionsSize = load_options_size;

	if (!entry_point) {
		pr_error(L"Invalid entry point\n");
		FreePool(buffer);
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

static int
should_use_fallback(EFI_HANDLE image_handle)
{
	EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
	EFI_LOADED_IMAGE *li;
	EFI_DEVICE_PATH *devpath;
	int i;
	unsigned int pathlen = 0;
	CHAR16 *bootpath;
	EFI_FILE_IO_INTERFACE *fio = NULL;
	EFI_FILE_HANDLE vh;
	EFI_FILE_HANDLE fh;
	EFI_STATUS rc;

	rc = uefi_call_wrapper(BS->HandleProtocol, 3, image_handle,
				       &loaded_image_protocol, (void **)&li);
	if (EFI_ERROR(rc))
		return 0;

	devpath = li->FilePath;

	bootpath = DevicePathToStr(devpath);

	/* Check the beginning of the string and the end, to avoid
	 * caring about which arch this is. */
	/* I really don't know why, but sometimes bootpath gives us
	 * L"\\EFI\\BOOT\\/BOOTX64.EFI".  So just handle that here...
	 */
	if (StrnCaseCmp(bootpath, L"\\EFI\\BOOT\\BOOT", 14) &&
			StrnCaseCmp(bootpath, L"\\EFI\\BOOT\\/BOOT", 15))
		return 0;
	pathlen = StrLen(bootpath);
	if (pathlen < 5 || StrCaseCmp(bootpath + pathlen - 4, L".EFI"))
		return 0;

	for (i=pathlen; i>0; i--) {
		if (bootpath[i] == '\\')
			break;
	}

	bootpath[i+1] = '\0';

	rc = uefi_call_wrapper(BS->HandleProtocol, 3, li->DeviceHandle,
			       &FileSystemProtocol, &fio);
	if (EFI_ERROR(rc))
		return 0;
	
	rc = uefi_call_wrapper(fio->OpenVolume, 2, fio, &vh);
	if (EFI_ERROR(rc))
		return 0;

	rc = uefi_call_wrapper(vh->Open, 5, vh, &fh, L"\\EFI\\BOOT" FALLBACK,
			       EFI_FILE_READ_ONLY, 0);
	if (EFI_ERROR(rc)) {
		uefi_call_wrapper(vh->Close, 1, vh);
		return 0;
	}
	uefi_call_wrapper(fh->Close, 1, fh);
	uefi_call_wrapper(vh->Close, 1, vh);

	return 1;
}

/*
 * Generate the path of an executable given shim's path and the name
 * of the executable
 */
static EFI_STATUS generate_path(EFI_LOADED_IMAGE *li, CHAR16 *ImagePath,
				EFI_DEVICE_PATH **grubpath, CHAR16 **PathName)
{
	EFI_DEVICE_PATH *devpath;
	EFI_HANDLE device;
	int i;
	unsigned int pathlen = 0;
	EFI_STATUS efi_status = EFI_SUCCESS;
	CHAR16 *bootpath;

	device = li->DeviceHandle;
	devpath = li->FilePath;

	bootpath = DevicePathToStr(devpath);

	pathlen = StrLen(bootpath);

	for (i=pathlen; i>0; i--) {
		if (bootpath[i] == '\\')
			break;
	}

	bootpath[i+1] = '\0';

	if (i == 0 || bootpath[i-i] == '\\')
		bootpath[i] = '\0';

	*PathName = AllocatePool(StrSize(bootpath) + StrSize(ImagePath));

	if (!*PathName) {
		pr_error(L"Failed to allocate path buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	*PathName[0] = '\0';
	if (StrnCaseCmp(bootpath, ImagePath, StrLen(bootpath)))
		StrCat(*PathName, bootpath);
	StrCat(*PathName, ImagePath);

	*grubpath = FileDevicePath(device, *PathName);

error:
	return efi_status;
}

/*
 * Open the second stage bootloader and read it into a buffer
 */
static EFI_STATUS load_image (EFI_LOADED_IMAGE *li, void **data,
			      int *datasize, CHAR16 *PathName, CHAR16 *PathName2)
{
	EFI_GUID simple_file_system_protocol = SIMPLE_FILE_SYSTEM_PROTOCOL;
	EFI_GUID file_info_id = EFI_FILE_INFO_ID;
	EFI_STATUS efi_status;
	EFI_HANDLE device;
	EFI_FILE_INFO *fileinfo = NULL;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_FILE *root, *grub;
	UINTN buffersize = sizeof(EFI_FILE_INFO);

	device = li->DeviceHandle;

	/*
	 * Open the device
	 */
	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, device,
				       &simple_file_system_protocol,
				       (void **)&drive);

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Failed to find fs\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Failed to open fs\n");
		goto error;
	}

	/*
	 * And then open the file
	 */
	efi_status = uefi_call_wrapper(root->Open, 5, root, &grub, PathName,
				       EFI_FILE_MODE_READ, 0);

	if (efi_status != EFI_SUCCESS) {
		efi_status = uefi_call_wrapper(root->Open, 5, root, &grub, PathName2,
				       EFI_FILE_MODE_READ, 0);
		if (efi_status != EFI_SUCCESS) {
			pr_error(L"Failed to open %s - %lx\n", PathName, efi_status);
			goto error;
		}
	}

	fileinfo = AllocatePool(buffersize);

	if (!fileinfo) {
		pr_error(L"Unable to allocate file info buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	/*
	 * Find out how big the file is in order to allocate the storage
	 * buffer
	 */
	efi_status = uefi_call_wrapper(grub->GetInfo, 4, grub, &file_info_id,
				       &buffersize, fileinfo);

	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(fileinfo);
		fileinfo = AllocatePool(buffersize);
		if (!fileinfo) {
			pr_error(L"Unable to allocate file info buffer\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto error;
		}
		efi_status = uefi_call_wrapper(grub->GetInfo, 4, grub,
					       &file_info_id, &buffersize,
					       fileinfo);
	}

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Unable to get file info\n");
		goto error;
	}

	buffersize = fileinfo->FileSize;

	*data = AllocatePool(buffersize);

	if (!*data) {
		pr_error(L"Unable to allocate file buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	/*
	 * Perform the actual read
	 */
	efi_status = uefi_call_wrapper(grub->Read, 3, grub, &buffersize,
				       *data);

	if (efi_status == EFI_BUFFER_TOO_SMALL) {
		FreePool(*data);
		*data = AllocatePool(buffersize);
		efi_status = uefi_call_wrapper(grub->Read, 3, grub,
					       &buffersize, *data);
	}

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Unexpected return from initial read: %x, buffersize %x\n", efi_status, buffersize);
		goto error;
	}

	*datasize = buffersize;

	FreePool(fileinfo);

	return EFI_SUCCESS;
error:
	if (*data) {
		FreePool(*data);
		*data = NULL;
	}

	if (fileinfo)
		FreePool(fileinfo);
	return efi_status;
}

/*
 * Protocol entry point. If secure boot is enabled, verify that the provided
 * buffer is signed with a trusted key.
 */
EFI_STATUS shim_verify (void *buffer, UINT32 size)
{
	EFI_STATUS status;
	PE_COFF_LOADER_IMAGE_CONTEXT context;

	if (!secure_mode())
		return EFI_SUCCESS;

	status = read_header(buffer, size, &context);

	if (status != EFI_SUCCESS)
		return status;

	status = verify_buffer(buffer, size, &context);

	return status;
}

/*
 * Load and run an EFI executable
 */
EFI_STATUS start_image(EFI_HANDLE image_handle, CHAR16 *ImagePath)
{
	EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
	EFI_STATUS efi_status;
	EFI_LOADED_IMAGE *li, li_bak;
	EFI_DEVICE_PATH *path;
	CHAR16 *PathName = NULL;
	void *sourcebuffer = NULL;
	UINTN sourcesize = 0;
	void *data = NULL;
	int datasize;

	/*
	 * We need to refer to the loaded image protocol on the running
	 * binary in order to find our path
	 */
	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, image_handle,
				       &loaded_image_protocol, (void **)&li);

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Unable to init protocol\n");
		return efi_status;
	}

	/*
	 * Build a new path from the existing one plus the executable name
	 */
	efi_status = generate_path(li, ImagePath, &path, &PathName);

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Unable to generate path: %s\n", ImagePath);
		goto done;
	}

	if (findNetboot(image_handle)) {
		efi_status = parseNetbootinfo(image_handle);
		if (efi_status != EFI_SUCCESS) {
			pr_error(L"Netboot parsing failed: %d\n", efi_status);
			return EFI_PROTOCOL_ERROR;
		}
		efi_status = FetchNetbootimage(image_handle, &sourcebuffer,
					       &sourcesize);
		if (efi_status != EFI_SUCCESS) {
			pr_error(L"Unable to fetch TFTP image\n");
			return efi_status;
		}
		data = sourcebuffer;
		datasize = sourcesize;
	} else {
		/*
		 * Read the new executable off disk
		 */
		efi_status = load_image(li, &data, &datasize, PathName, ImagePath);

		if (efi_status != EFI_SUCCESS) {
			pr_error(L"Failed to load image\n");
			goto done;
		}
	}

	/*
	 * We need to modify the loaded image protocol entry before running
	 * the new binary, so back it up
	 */
	CopyMem(&li_bak, li, sizeof(li_bak));

	/*
	 * Verify and, if appropriate, relocate and execute the executable
	 */
	efi_status = handle_image(data, datasize, li);

	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Failed to load image\n");
		CopyMem(li, &li_bak, sizeof(li_bak));
		goto done;
	}

	/*
	 * The binary is trusted and relocated. Run it
	 */
	efi_status = uefi_call_wrapper(entry_point, 2, image_handle, systab);

	/*
	 * Restore our original loaded image values
	 */
	CopyMem(li, &li_bak, sizeof(li_bak));
done:
	if (PathName)
		FreePool(PathName);

	if (data)
		FreePool(data);

	return efi_status;
}

/*
 * Load and run grub. If that fails because grub isn't trusted, load and
 * run MokManager.
 */
EFI_STATUS init_grub(EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;

	if (should_use_fallback(image_handle))
		efi_status = start_image(image_handle, FALLBACK);
	else
		efi_status = start_image(image_handle, second_stage);

	if (efi_status != EFI_SUCCESS)
		efi_status = start_image(image_handle, MOK_MANAGER);

	return efi_status;
}

/*
 * Copy the boot-services only MokList variable to the runtime-accessible
 * MokListRT variable. It's not marked NV, so the OS can't modify it.
 */
EFI_STATUS mirror_mok_list()
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS efi_status;
	UINT32 attributes;
	void *Data = NULL;
	UINTN DataSize = 0;

	efi_status = get_variable(L"MokList", shim_lock_guid, &attributes,
				  &DataSize, &Data);

	if (efi_status != EFI_SUCCESS) {
		goto done;
	}

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"MokListRT",
				       &shim_lock_guid,
				       EFI_VARIABLE_BOOTSERVICE_ACCESS
				       | EFI_VARIABLE_RUNTIME_ACCESS,
				       DataSize, Data);
	if (efi_status != EFI_SUCCESS) {
		pr_error(L"Failed to set MokListRT %d\n", efi_status);
	}

done:
	return efi_status;
}

/*
 * Check if a variable exists
 */
static BOOLEAN check_var(CHAR16 *varname)
{
	EFI_STATUS efi_status;
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	UINTN size = sizeof(UINT32);
	UINT32 MokVar;
	UINT32 attributes;

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, varname,
				       &shim_lock_guid, &attributes,
				       &size, (void *)&MokVar);

	if (efi_status == EFI_SUCCESS || efi_status == EFI_BUFFER_TOO_SMALL)
		return TRUE;

	return FALSE;
}

/*
 * If the OS has set any of these variables we need to drop into MOK and
 * handle them appropriately
 */
EFI_STATUS check_mok_request(EFI_HANDLE image_handle)
{
	EFI_STATUS efi_status;

	if (check_var(L"MokNew") || check_var(L"MokSB") ||
	    check_var(L"MokPW") || check_var(L"MokAuth") ||
	    check_var(L"MokDel")) {
		efi_status = start_image(image_handle, MOK_MANAGER);

		if (efi_status != EFI_SUCCESS) {
			pr_error(L"Failed to start MokManager\n");
			return efi_status;
		}
	}

	return EFI_SUCCESS;
}

/*
 * Verify that MokSBState is valid, and if appropriate set insecure mode
 */

static EFI_STATUS check_mok_sb (void)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	EFI_STATUS status = EFI_SUCCESS;
	void *MokSBState = NULL;
	UINTN MokSBStateSize = 0;
	UINT32 attributes;

	status = get_variable(L"MokSBState", shim_lock_guid, &attributes,
			      &MokSBStateSize, &MokSBState);

	if (status != EFI_SUCCESS)
		return EFI_ACCESS_DENIED;

	/*
	 * Delete and ignore the variable if it's been set from or could be
	 * modified by the OS
	 */
	if (attributes & EFI_VARIABLE_RUNTIME_ACCESS) {
		pr_error(L"MokSBState is compromised! Clearing it\n");
		if (LibDeleteVariable(L"MokSBState", &shim_lock_guid) != EFI_SUCCESS) {
			pr_error(L"Failed to erase MokSBState\n");
		}
		status = EFI_ACCESS_DENIED;
	} else {
		if (*(UINT8 *)MokSBState == 1) {
			insecure_mode = 1;
		}
	}

	return status;
}

/*
 * Check the load options to specify the second stage loader
 */
EFI_STATUS set_second_stage (EFI_HANDLE image_handle)
{
	EFI_STATUS status;
	EFI_LOADED_IMAGE *li;
	CHAR16 *start = NULL, *c;
	int i, remaining_size = 0;
	CHAR16 *loader_str = NULL;
	int loader_len = 0;

	second_stage = DEFAULT_LOADER;
	load_options = NULL;
	load_options_size = 0;

	status = uefi_call_wrapper(BS->HandleProtocol, 3, image_handle,
				   &LoadedImageProtocol, (void **) &li);
	if (status != EFI_SUCCESS) {
		pr_error (L"Failed to get load options\n");
		return status;
	}

	/* Expect a CHAR16 string with at least one CHAR16 */
	if (li->LoadOptionsSize < 4 || li->LoadOptionsSize % 2 != 0) {
		return EFI_BAD_BUFFER_SIZE;
	}
	c = (CHAR16 *)(li->LoadOptions + (li->LoadOptionsSize - 2));
	if (*c != L'\0') {
		return EFI_BAD_BUFFER_SIZE;
	}

	/*
	 * UEFI shell copies the whole line of the command into LoadOptions.
	 * We ignore the string before the first L' ', i.e. the name of this
	 * program.
	 */
	for (i = 0; i < li->LoadOptionsSize; i += 2) {
		c = (CHAR16 *)(li->LoadOptions + i);
		if (*c == L' ') {
			*c = L'\0';
			start = c + 1;
			remaining_size = li->LoadOptionsSize - i - 2;
			break;
		}
	}

	if (!start || remaining_size <= 0)
		return EFI_SUCCESS;

	for (i = 0; start[i] != '\0'; i++) {
		if (start[i] == L' ' || start[i] == L'\0')
			break;
		loader_len++;
	}

	/*
	 * Setup the name of the alternative loader and the LoadOptions for
	 * the loader
	 */
	if (loader_len > 0) {
		loader_str = AllocatePool((loader_len + 1) * sizeof(CHAR16));
		if (!loader_str) {
			Print(L"Failed to allocate loader string\n");
			return EFI_OUT_OF_RESOURCES;
		}
		for (i = 0; i < loader_len; i++)
			loader_str[i] = start[i];
		loader_str[loader_len] = L'\0';

		second_stage = loader_str;
		load_options = start;
		load_options_size = remaining_size;
	}

	return EFI_SUCCESS;
}

EFI_STATUS efi_main (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *passed_systab)
{
	EFI_GUID shim_lock_guid = SHIM_LOCK_GUID;
	static SHIM_LOCK shim_lock_interface;
	EFI_HANDLE handle = NULL;
	EFI_STATUS efi_status;

	/*
	 * Set up the shim lock protocol so that grub and MokManager can
	 * call back in and use shim functions
	 */
	shim_lock_interface.Verify = shim_verify;
	shim_lock_interface.Hash = generate_hash;
	shim_lock_interface.Context = read_header;
	shim_lock_interface.VerifyBlob = verify_generic_blob;
	shim_lock_interface.StartImage = start_image;

	systab = passed_systab;

	/*
	 * Ensure that gnu-efi functions are available
	 */
	InitializeLib(image_handle, systab);

	/* Set the second stage loader */
	set_second_stage (image_handle);

	/*
	 * Check whether the user has configured the system to run in
	 * insecure mode
	 */
	check_mok_sb();

	/*
	 * Tell the user that we're in insecure mode if necessary
	 */
	if (insecure_mode) {
		Print(L"Booting in insecure mode\n");
		uefi_call_wrapper(BS->Stall, 1, 2000000);
	}

	/*
	 * Install the protocol
	 */
	uefi_call_wrapper(BS->InstallProtocolInterface, 4, &handle,
			  &shim_lock_guid, EFI_NATIVE_INTERFACE,
			  &shim_lock_interface);

	/*
	 * Enter MokManager if necessary
	 */
	efi_status = check_mok_request(image_handle);

	/*
	 * Copy the MOK list to a runtime variable so the kernel can make
	 * use of it
	 */
	efi_status = mirror_mok_list();

	/*
	 * Hand over control to the second stage bootloader
	 */

	efi_status = init_grub(image_handle);

	/*
	 * If we're back here then clean everything up before exiting
	 */
	uefi_call_wrapper(BS->UninstallProtocolInterface, 3, handle,
			  &shim_lock_guid, &shim_lock_interface);

	/*
	 * Free the space allocated for the alternative 2nd stage loader
	 */
	if (load_options_size > 0)
		FreePool(second_stage);

	return efi_status;
}
