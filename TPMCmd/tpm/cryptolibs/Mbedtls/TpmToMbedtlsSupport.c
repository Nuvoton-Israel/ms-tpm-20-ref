// Copyright (c) 2026 Nuvoton Technology Corporation.
// SPDX-License-Identifier: BSD-3-Clause

#include "Tpm.h"

#if defined(HASH_LIB_MBEDTLS) || defined(MATH_LIB_MBEDTLS) || defined(SYM_LIB_MBEDTLS)

#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

LIB_EXPORT int BnSupportLibInit(void)
{
	return TRUE;
}

void TpmMbedtlsHashStartSha1(mbedtls_sha1_context *state)
{
	mbedtls_sha1_init(state);
	(void) mbedtls_sha1_starts(state);
}

void TpmMbedtlsHashDataSha1(mbedtls_sha1_context *state,
	const BYTE *buffer, size_t size)
{
	(void) mbedtls_sha1_update(state, buffer, size);
}

void TpmMbedtlsHashEndSha1(mbedtls_sha1_context *state, BYTE *buffer)
{
	(void) mbedtls_sha1_finish(state, buffer);
	mbedtls_sha1_free(state);
}

void TpmMbedtlsHashStartSha256(mbedtls_sha256_context *state)
{
	mbedtls_sha256_init(state);
	(void) mbedtls_sha256_starts(state, 0);
}

void TpmMbedtlsHashDataSha256(mbedtls_sha256_context *state,
	const BYTE *buffer, size_t size)
{
	(void) mbedtls_sha256_update(state, buffer, size);
}

void TpmMbedtlsHashEndSha256(mbedtls_sha256_context *state, BYTE *buffer)
{
	(void) mbedtls_sha256_finish(state, buffer);
	mbedtls_sha256_free(state);
}

void TpmMbedtlsHashStartSha384(mbedtls_sha512_context *state)
{
	mbedtls_sha512_init(state);
	(void) mbedtls_sha512_starts(state, 1);
}

void TpmMbedtlsHashDataSha384(mbedtls_sha512_context *state,
	const BYTE *buffer, size_t size)
{
	(void) mbedtls_sha512_update(state, buffer, size);
}

void TpmMbedtlsHashEndSha384(mbedtls_sha512_context *state, BYTE *buffer)
{
	BYTE digest[SHA512_DIGEST_SIZE];

	(void) mbedtls_sha512_finish(state, digest);
	memcpy(buffer, digest, SHA384_DIGEST_SIZE);
	mbedtls_sha512_free(state);
}

int TpmMbedtlsSetEncryptKeyAES(const BYTE *key, UINT16 keySizeInBits,
	mbedtls_aes_context *schedule)
{
	mbedtls_aes_init(schedule);
	return mbedtls_aes_setkey_enc(schedule, key, keySizeInBits);
}

int TpmMbedtlsSetDecryptKeyAES(const BYTE *key, UINT16 keySizeInBits,
	mbedtls_aes_context *schedule)
{
	mbedtls_aes_init(schedule);
	return mbedtls_aes_setkey_dec(schedule, key, keySizeInBits);
}

void TpmMbedtlsEncryptAES(void *schedule, BYTE *out, const BYTE *in)
{
	(void) mbedtls_aes_crypt_ecb(schedule, MBEDTLS_AES_ENCRYPT, in, out);
}

void TpmMbedtlsDecryptAES(void *schedule, BYTE *out, const BYTE *in)
{
	(void) mbedtls_aes_crypt_ecb(schedule, MBEDTLS_AES_DECRYPT, in, out);
}

#endif