// Copyright (c) 2026 Nuvoton Technology Corporation.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef BN_TO_MBEDTLS_MATH_H
#define BN_TO_MBEDTLS_MATH_H

#ifndef BN_MATH_LIB_DEFINED
#define BN_MATH_LIB_DEFINED

#define MATH_LIB_MBEDTLS

#ifndef MATH_LIB_TPMBIGNUM
#error this mbedTLS interface expects TpmBigNum
#endif

typedef const TPMBN_ECC_CURVE_CONSTANTS *bigCurveData;

TPM_INLINE const TPMBN_ECC_CURVE_CONSTANTS *AccessCurveConstants(
	const bigCurveData *curve)
{
	return *curve;
}

#define MathLibSimulationEnd()

#else
#error BN_MATH_LIB_DEFINED already defined
#endif
#endif