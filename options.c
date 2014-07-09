/*
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Author: Andrew Boie <andrew.p.boie@intel.com>
 * Author: Anisha Dattatraya Kulkarni <anisha.dattatraya.kulkarni@intel.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <efi.h>
#include <efilib.h>

/*
 * Parameters Passed : character  : char to be converted to int
 *                     base       : the base of convertion ( hex, dec etc)
 *
 * Returns           :   value    : character after conversion to int
 *
 * This function converts character to integer.
 */



static INTN to_digit(CHAR16 character, UINTN base)
{
        UINTN value = -1;

        if (character >= '0' && character <= '9')
                value = character - '0';
        else if (character >= 'a' && character <= 'z')
                value = 0xA + character - 'a';
        else if (character >= 'A' && character <= 'Z')
                value = 0xA + character - 'A';

        return value < base ? (INTN)value : -1;
}

/*
 * Parameters Passed : nptr  : Pointer to the string to be converted to int
 *                     base  : the base of convertion ( hex, dec etc)
 *               endptr: Reference to the next character after the converted string
 * Returns           : value : coverted unsigned long int
 *
 * This function converts String to unsigned long int.
 */


UINTN strtoul16(const CHAR16 *nptr, CHAR16 **endptr, UINTN base)
{
        UINTN value = 0;

        if (!nptr)
                goto out;

        if ((base == 0 || base == 16) &&
            (StrLen(nptr) > 2 && nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X'))) {
                nptr += 2;
                base = 16;
        }

        if (base == 0)
                base = 10;

        for (; *nptr != '\0' ; nptr++) {
                INTN t = to_digit(*nptr, base);
                if (t == -1)
                        goto out;
                value = (value * base) + t;
        }

out:
        if (endptr)
                *endptr = (CHAR16 *)nptr;
        return value;
}


static CHAR16 *tokenize(CHAR16 *str)
{
        static CHAR16 *saveptr;
        CHAR16 *ret;

        if (str)
                saveptr = str;

        if (!saveptr)
                return NULL;

        // skip leading delimiters
        while (*saveptr == L' ')
                saveptr++;

        // end of the string, no more tokens
        if (*saveptr == L'\0')
                return NULL;

        ret = saveptr;
        // now scan until we find another delimiter or the end of the string
        while (*saveptr != L' ' && *saveptr != L'\0')
                saveptr++;

        if (*saveptr != L'\0') {
                *saveptr = L'\0';
                saveptr++;
        }

        return ret;
}


EFI_STATUS
get_argv(EFI_HANDLE *image, CHAR16 **cmdline_p, UINTN *argc_p, CHAR16 ***argv_p)
{
        CHAR16* token, *str, *cur, *cmdline;
        UINTN argc, i;
        CHAR16 **argv;
        EFI_LOADED_IMAGE *loaded_image;
        EFI_STATUS ret;

        ret = uefi_call_wrapper(BS->OpenProtocol, 6, image, &LoadedImageProtocol,
                        (VOID **)&loaded_image, image, NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(ret))
                return ret;

        cmdline = StrDuplicate((CHAR16 *)loaded_image->LoadOptions);
        if (!cmdline)
                return EFI_OUT_OF_RESOURCES;

        // Count up the number of arguments
        str = StrDuplicate(cmdline);
        if (!str) {
                FreePool(cmdline);
                return EFI_OUT_OF_RESOURCES;
        }

        for (argc = 0, cur = str; ; cur = NULL) {
                token = tokenize(cur);
                if (token == NULL)
                        break;
                argc++;
        }
        FreePool(str);

        argv = AllocatePool((argc + 1) * sizeof(CHAR16 *));
        if (!argv)
                return EFI_OUT_OF_RESOURCES;

        for (i = 0, cur = cmdline; ; cur = NULL, i++) {
                token = tokenize(cur);
                if (token == NULL) {
                        argv[i] = NULL;
                        break;
                }
                argv[i] = token;
        }

        *argc_p = argc;
        *argv_p = argv;
        *cmdline_p = cmdline;

        return EFI_SUCCESS;
}

/* vim: softtabstop=8:shiftwidth=8:expandtab
 */

