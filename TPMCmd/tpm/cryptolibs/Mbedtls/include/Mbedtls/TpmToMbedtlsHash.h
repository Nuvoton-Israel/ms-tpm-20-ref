// Copyright (c) 2026 Nuvoton Technology Corporation.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef TPM_TO_MBEDTLS_HASH_H
#define TPM_TO_MBEDTLS_HASH_H

#ifndef HASH_LIB_DEFINED
#define HASH_LIB_DEFINED

#define HASH_LIB_MBEDTLS

#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#define tpmHashStateSHA1_t   mbedtls_sha1_context
#define tpmHashStateSHA256_t mbedtls_sha256_context
#define tpmHashStateSHA384_t mbedtls_sha512_context
#define tpmHashStateSHA512_t mbedtls_sha512_context

#ifdef _CRYPT_HASH_C_

typedef BYTE *PBYTE;
typedef const BYTE *PCBYTE;

#define HASH_START_METHOD_DEF void(HASH_START_METHOD)(PANY_HASH_STATE state)
#define HASH_START(hashState) ((hashState)->def->method.start)(&(hashState)->state)
#define HASH_DATA_METHOD_DEF \
	void(HASH_DATA_METHOD)(PANY_HASH_STATE state, PCBYTE buffer, size_t size)
#define HASH_DATA(hashState, dInSize, dIn) \
	((hashState)->def->method.data)(&(hashState)->state, dIn, dInSize)
#define HASH_END_METHOD_DEF void(HASH_END_METHOD)(PANY_HASH_STATE state, BYTE *buffer)
#define HASH_END(hashState, buffer) \
	((hashState)->def->method.end)(&(hashState)->state, buffer)
#define HASH_STATE_COPY_METHOD_DEF \
	void(HASH_STATE_COPY_METHOD)(PANY_HASH_STATE to, PCANY_HASH_STATE from, size_t size)
#define HASH_STATE_COPY(hashStateOut, hashStateIn) \
	((hashStateIn)->def->method.copy)(&(hashStateOut)->state, \
		&(hashStateIn)->state, (hashStateIn)->def->contextSize)
#define HASH_STATE_EXPORT_METHOD_DEF \
	void(HASH_STATE_EXPORT_METHOD)(BYTE *to, PCANY_HASH_STATE from, size_t size)
#define HASH_STATE_EXPORT(to, hashStateFrom) \
	((hashStateFrom)->def->method.copyOut)( \
		&(((BYTE *)(to))[offsetof(HASH_STATE, state)]), \
		&(hashStateFrom)->state, (hashStateFrom)->def->contextSize)
#define HASH_STATE_IMPORT_METHOD_DEF \
	void(HASH_STATE_IMPORT_METHOD)(PANY_HASH_STATE to, const BYTE *from, size_t size)
#define HASH_STATE_IMPORT(hashStateTo, from) \
	((hashStateTo)->def->method.copyIn)(&(hashStateTo)->state, \
		&(((const BYTE *)(from))[offsetof(HASH_STATE, state)]), \
		(hashStateTo)->def->contextSize)

void TpmMbedtlsHashStartSha1(mbedtls_sha1_context *state);
void TpmMbedtlsHashDataSha1(mbedtls_sha1_context *state,
	const BYTE *buffer, size_t size);
void TpmMbedtlsHashEndSha1(mbedtls_sha1_context *state, BYTE *buffer);
void TpmMbedtlsHashStartSha256(mbedtls_sha256_context *state);
void TpmMbedtlsHashDataSha256(mbedtls_sha256_context *state,
	const BYTE *buffer, size_t size);
void TpmMbedtlsHashEndSha256(mbedtls_sha256_context *state, BYTE *buffer);
void TpmMbedtlsHashStartSha384(mbedtls_sha512_context *state);
void TpmMbedtlsHashDataSha384(mbedtls_sha512_context *state,
	const BYTE *buffer, size_t size);
void TpmMbedtlsHashEndSha384(mbedtls_sha512_context *state, BYTE *buffer);

#define tpmHashStart_SHA1        TpmMbedtlsHashStartSha1
#define tpmHashData_SHA1         TpmMbedtlsHashDataSha1
#define tpmHashEnd_SHA1          TpmMbedtlsHashEndSha1
#define tpmHashStart_SHA256      TpmMbedtlsHashStartSha256
#define tpmHashData_SHA256       TpmMbedtlsHashDataSha256
#define tpmHashEnd_SHA256        TpmMbedtlsHashEndSha256
#define tpmHashStart_SHA384      TpmMbedtlsHashStartSha384
#define tpmHashData_SHA384       TpmMbedtlsHashDataSha384
#define tpmHashEnd_SHA384        TpmMbedtlsHashEndSha384

#define tpmHashStateCopy_SHA1      memcpy
#define tpmHashStateExport_SHA1    memcpy
#define tpmHashStateImport_SHA1    memcpy
#define tpmHashStateCopy_SHA256    memcpy
#define tpmHashStateExport_SHA256  memcpy
#define tpmHashStateImport_SHA256  memcpy
#define tpmHashStateCopy_SHA384    memcpy
#define tpmHashStateExport_SHA384  memcpy
#define tpmHashStateImport_SHA384  memcpy

#endif

#define LibHashInit()
#define HashLibSimulationEnd()

#endif
#endif