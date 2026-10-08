// Copyright (c) 2026 Nuvoton Technology Corporation.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef TPM_TO_MBEDTLS_SYM_H
#define TPM_TO_MBEDTLS_SYM_H

#ifndef SYM_LIB_DEFINED
#define SYM_LIB_DEFINED

#define SYM_LIB_MBEDTLS

#include <mbedtls/aes.h>

typedef void (*TpmCryptSetSymKeyCall_t)(void *keySchedule, BYTE *out,
	const BYTE *in);

#define SWIZZLE(keySchedule, in, out) \
	(void *)(keySchedule), (BYTE *)(out), (const BYTE *)(in)

typedef mbedtls_aes_context tpmKeyScheduleAES;

int TpmMbedtlsSetEncryptKeyAES(const BYTE *key, UINT16 keySizeInBits,
	tpmKeyScheduleAES *schedule);
int TpmMbedtlsSetDecryptKeyAES(const BYTE *key, UINT16 keySizeInBits,
	tpmKeyScheduleAES *schedule);
void TpmMbedtlsEncryptAES(void *schedule, BYTE *out, const BYTE *in);
void TpmMbedtlsDecryptAES(void *schedule, BYTE *out, const BYTE *in);

#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule) \
	TpmMbedtlsSetEncryptKeyAES(key, keySizeInBits, schedule)
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule) \
	TpmMbedtlsSetDecryptKeyAES(key, keySizeInBits, schedule)
#define TpmCryptEncryptAES TpmMbedtlsEncryptAES
#define TpmCryptDecryptAES TpmMbedtlsDecryptAES

typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

#define SymLibSimulationEnd()

#endif
#endif