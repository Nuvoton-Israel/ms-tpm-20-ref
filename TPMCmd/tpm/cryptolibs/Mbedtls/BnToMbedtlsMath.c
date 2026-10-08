// Copyright (c) 2026 Nuvoton Technology Corporation.
// SPDX-License-Identifier: BSD-3-Clause

#include "Tpm.h"

#ifdef MATH_LIB_MBEDTLS

#include <string.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#include "BnConvert_fp.h"
#include "crypto/backend.h"

static int mbedtls_rng(void *context, unsigned char *output, size_t length)
{
	(void) context;
	return cop_crypto_get_entropy(output, length);
}

static int mpi_from_bn(mbedtls_mpi *mpi, bigConst value)
{
	if (value == NULL || value->size == 0)
		return 0;
	return mbedtls_mpi_read_binary_le(mpi, (const unsigned char *) value->d,
		value->size * sizeof(crypt_uword_t));
}

static BOOL bn_from_mpi(bigNum value, const mbedtls_mpi *mpi)
{
	size_t bytes;
	size_t capacity;

	if (value == NULL)
		return TRUE;
	bytes = mbedtls_mpi_size(mpi);
	capacity = BnGetAllocated(value) * sizeof(crypt_uword_t);
	if (bytes > capacity)
		return FALSE;
	memset(value->d, 0, capacity);
	if (mbedtls_mpi_write_binary_le(mpi, (unsigned char *) value->d, capacity) != 0)
		return FALSE;
	BnSetTop(value, (bytes + sizeof(crypt_uword_t) - 1u) / sizeof(crypt_uword_t));
	return TRUE;
}

static int point_from_tpm(mbedtls_ecp_point *point, pointConst value)
{
	if (mpi_from_bn(&point->MBEDTLS_PRIVATE(X), value->x) != 0 ||
		mpi_from_bn(&point->MBEDTLS_PRIVATE(Y), value->y) != 0 ||
		mpi_from_bn(&point->MBEDTLS_PRIVATE(Z), value->z) != 0)
		return -1;
	return 0;
}

static BOOL point_to_tpm(bigPoint value, const mbedtls_ecp_point *point)
{
	return bn_from_mpi(value->x, &point->MBEDTLS_PRIVATE(X)) &&
		bn_from_mpi(value->y, &point->MBEDTLS_PRIVATE(Y)) &&
		bn_from_mpi(value->z, &point->MBEDTLS_PRIVATE(Z));
}

static mbedtls_ecp_group_id curve_group(TPM_ECC_CURVE curve)
{
	switch (curve) {
	case TPM_ECC_NIST_P256:
		return MBEDTLS_ECP_DP_SECP256R1;
	case TPM_ECC_NIST_P384:
		return MBEDTLS_ECP_DP_SECP384R1;
	default:
		return MBEDTLS_ECP_DP_NONE;
	}
}

LIB_EXPORT BOOL BnModMult(bigNum result, bigConst op1, bigConst op2,
	bigConst modulus)
{
	mbedtls_mpi a, b, m, product;
	BOOL ok = FALSE;

	mbedtls_mpi_init(&a); mbedtls_mpi_init(&b);
	mbedtls_mpi_init(&m); mbedtls_mpi_init(&product);
	if (mpi_from_bn(&a, op1) != 0 || mpi_from_bn(&b, op2) != 0 ||
		mpi_from_bn(&m, modulus) != 0) goto cleanup;
	ok = (mbedtls_mpi_mul_mpi(&product, &a, &b) == 0) &&
		(mbedtls_mpi_mod_mpi(&product, &product, &m) == 0) &&
		bn_from_mpi(result, &product);

cleanup:
	mbedtls_mpi_free(&product); mbedtls_mpi_free(&m);
	mbedtls_mpi_free(&b); mbedtls_mpi_free(&a);
	return ok;
}

LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
	mbedtls_mpi a, b, product;
	BOOL ok = FALSE;

	mbedtls_mpi_init(&a); mbedtls_mpi_init(&b); mbedtls_mpi_init(&product);
	if (mpi_from_bn(&a, multiplicand) != 0 || mpi_from_bn(&b, multiplier) != 0)
		goto cleanup;
	ok = (mbedtls_mpi_mul_mpi(&product, &a, &b) == 0) && bn_from_mpi(result, &product);

cleanup:
	mbedtls_mpi_free(&product); mbedtls_mpi_free(&b); mbedtls_mpi_free(&a);
	return ok;
}

LIB_EXPORT BOOL BnDiv(bigNum quotient, bigNum remainder, bigConst dividend,
	bigConst divisor)
{
	mbedtls_mpi a, b, q, r;
	BOOL ok = FALSE;

	mbedtls_mpi_init(&a); mbedtls_mpi_init(&b);
	mbedtls_mpi_init(&q); mbedtls_mpi_init(&r);
	if (mpi_from_bn(&a, dividend) != 0 || mpi_from_bn(&b, divisor) != 0)
		goto cleanup;
	ok = (mbedtls_mpi_div_mpi(&q, &r, &a, &b) == 0) &&
		bn_from_mpi(quotient, &q) && bn_from_mpi(remainder, &r);

cleanup:
	mbedtls_mpi_free(&r); mbedtls_mpi_free(&q);
	mbedtls_mpi_free(&b); mbedtls_mpi_free(&a);
	return ok;
}

#if ALG_RSA
LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2)
{
	mbedtls_mpi a, b, result;
	BOOL ok = FALSE;

	mbedtls_mpi_init(&a); mbedtls_mpi_init(&b); mbedtls_mpi_init(&result);
	if (mpi_from_bn(&a, number1) != 0 || mpi_from_bn(&b, number2) != 0)
		goto cleanup;
	ok = (mbedtls_mpi_gcd(&result, &a, &b) == 0) && bn_from_mpi(gcd, &result);

cleanup:
	mbedtls_mpi_free(&result); mbedtls_mpi_free(&b); mbedtls_mpi_free(&a);
	return ok;
}

LIB_EXPORT BOOL BnModExp(bigNum result, bigConst number, bigConst exponent,
	bigConst modulus)
{
	mbedtls_mpi n, e, m, output;
	BOOL ok = FALSE;

	mbedtls_mpi_init(&n); mbedtls_mpi_init(&e);
	mbedtls_mpi_init(&m); mbedtls_mpi_init(&output);
	if (mpi_from_bn(&n, number) != 0 || mpi_from_bn(&e, exponent) != 0 ||
		mpi_from_bn(&m, modulus) != 0) goto cleanup;
	ok = (mbedtls_mpi_exp_mod(&output, &n, &e, &m, NULL) == 0) &&
		bn_from_mpi(result, &output);

cleanup:
	mbedtls_mpi_free(&output); mbedtls_mpi_free(&m);
	mbedtls_mpi_free(&e); mbedtls_mpi_free(&n);
	return ok;
}
#endif

LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
	mbedtls_mpi n, m, output;
	BOOL ok = FALSE;

	mbedtls_mpi_init(&n); mbedtls_mpi_init(&m); mbedtls_mpi_init(&output);
	if (mpi_from_bn(&n, number) != 0 || mpi_from_bn(&m, modulus) != 0)
		goto cleanup;
	ok = (mbedtls_mpi_inv_mod(&output, &n, &m) == 0) && bn_from_mpi(result, &output);

cleanup:
	mbedtls_mpi_free(&output); mbedtls_mpi_free(&m); mbedtls_mpi_free(&n);
	return ok;
}

#if ALG_ECC
LIB_EXPORT BOOL BnEccModMult(bigPoint result, pointConst point, bigConst scalar,
	const bigCurveData *curve)
{
	mbedtls_ecp_group group;
	mbedtls_ecp_point input, output;
	mbedtls_mpi d;
	pointConst source = point;
	BOOL ok = FALSE;

	mbedtls_ecp_group_init(&group);
	mbedtls_ecp_point_init(&input); mbedtls_ecp_point_init(&output);
	mbedtls_mpi_init(&d);
	if (mbedtls_ecp_group_load(&group, curve_group(BnCurveGetCurveId(*curve))) != 0)
		goto cleanup;
	if (source == NULL) source = BnCurveGetG(*curve);
	if (point_from_tpm(&input, source) != 0 || mpi_from_bn(&d, scalar) != 0)
		goto cleanup;
	ok = (mbedtls_ecp_mul(&group, &output, &d, &input, mbedtls_rng, NULL) == 0) &&
		point_to_tpm(result, &output);
cleanup:
	mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&input);
	mbedtls_ecp_point_free(&output); mbedtls_ecp_group_free(&group);
	return ok;
}

LIB_EXPORT BOOL BnEccModMult2(bigPoint result, pointConst point1,
	bigConst scalar1, pointConst point2, bigConst scalar2,
	const bigCurveData *curve)
{
	mbedtls_ecp_group group;
	mbedtls_ecp_point p1, p2, output;
	mbedtls_mpi d1, d2;
	BOOL ok = FALSE;

	mbedtls_ecp_group_init(&group);
	mbedtls_ecp_point_init(&p1); mbedtls_ecp_point_init(&p2);
	mbedtls_ecp_point_init(&output);
	mbedtls_mpi_init(&d1); mbedtls_mpi_init(&d2);
	if (mbedtls_ecp_group_load(&group, curve_group(BnCurveGetCurveId(*curve))) != 0)
		goto cleanup;
	if (point1 == NULL) point1 = BnCurveGetG(*curve);
	if (point_from_tpm(&p1, point1) != 0 || point_from_tpm(&p2, point2) != 0 ||
		mpi_from_bn(&d1, scalar1) != 0 || mpi_from_bn(&d2, scalar2) != 0)
		goto cleanup;
	ok = (mbedtls_ecp_muladd(&group, &output, &d1, &p1, &d2, &p2) == 0) &&
		point_to_tpm(result, &output);
cleanup:
	mbedtls_mpi_free(&d2); mbedtls_mpi_free(&d1);
	mbedtls_ecp_point_free(&p2); mbedtls_ecp_point_free(&p1);
	mbedtls_ecp_point_free(&output); mbedtls_ecp_group_free(&group);
	return ok;
}

LIB_EXPORT BOOL BnEccAdd(bigPoint result, pointConst point1, pointConst point2,
	const bigCurveData *curve)
{
	BN_VAR(one1, 32); BN_VAR(one2, 32);
	BnSetWord(one1, 1); BnSetWord(one2, 1);
	return BnEccModMult2(result, point1, one1, point2, one2, curve);
}

LIB_EXPORT bigCurveData *BnCurveInitialize(bigCurveData *curve,
	TPM_ECC_CURVE curveId)
{
	*curve = BnGetCurveData(curveId);
	return (*curve == NULL) ? NULL : curve;
}

LIB_EXPORT void BnCurveFree(bigCurveData *curve)
{
	(void) curve;
}
#endif

#if CRYPTO_LIB_REPORTING
void BnGetImplementation(_CRYPTO_IMPL_DESCRIPTION *result)
{
	snprintf(result->name, sizeof(result->name), "mbedTLS");
	snprintf(result->version, sizeof(result->version), "3.6.7");
}
#endif

#endif