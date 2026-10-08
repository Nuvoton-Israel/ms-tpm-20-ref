//** Introduction
// The functions in this file are designed to support self-test of cryptographic
// functions in the TPM. The TPM allows the user to decide whether to run self-test
// on a demand basis or to run all the self-tests before proceeding.
//
// The self-tests are controlled by a set of bit vectors. The
// 'g_untestedDecryptionAlgorithms' vector has a bit for each decryption algorithm
// that needs to be tested and 'g_untestedEncryptionAlgorithms' has a bit for
// each encryption algorithm that needs to be tested. Before an algorithm
// is used, the appropriate vector is checked (indexed using the algorithm ID).
// If the bit is 1, then the test function should be called.
//
// For more information, see TpmSelfTests.txt

#include "Tpm.h"

//** Functions

typedef enum {
    COP_SELF_TEST_IDLE = 0,
    COP_SELF_TEST_ACTIVE,
    COP_SELF_TEST_COMPLETE
} COP_SELF_TEST_STATE;

static COP_SELF_TEST_STATE s_copFullSelfTestState = COP_SELF_TEST_IDLE;

LIB_EXPORT UINT32 CryptSelfTestGetState(void)
{
    return (UINT32)s_copFullSelfTestState;
}

LIB_EXPORT UINT32 CryptSelfTestGetPendingAlgorithm(void)
{
    TPM_ALG_ID alg;

    for(alg = TPM_ALG_FIRST; alg <= TPM_ALG_LAST; alg++)
    {
        if(TEST_BIT(alg, g_toTest))
            return alg;
    }
    return TPM_ALG_ERROR;
}

LIB_EXPORT BOOL CryptSelfTestIsPending(void)
{
    return CryptSelfTestGetPendingAlgorithm() != TPM_ALG_ERROR;
}

//*** RunSelfTest()
// Local function to run self-test
static TPM_RC CryptRunSelfTests(
    ALGORITHM_VECTOR* toTest  // IN: the vector of the algorithms to test
)
{
    TPM_ALG_ID alg;

    // For each of the algorithms that are in the toTestVecor, need to run a
    // test
    for(alg = TPM_ALG_FIRST; alg <= TPM_ALG_LAST; alg++)
    {
        if(TEST_BIT(alg, *toTest))
        {
            TPM_RC result = CryptTestAlgorithm(alg, toTest);
            if(result != TPM_RC_SUCCESS)
                return result;
        }
    }
    return TPM_RC_SUCCESS;
}

//*** CryptSelfTest()
// This function is called to start/complete a full self-test.
// If 'fullTest' is NO, then only the untested algorithms will be run. If
// 'fullTest' is YES, then 'g_untestedDecryptionAlgorithms' is reinitialized and then
// all tests are run.
// This implementation of the reference design does not support processing outside
// the framework of a TPM command. As a consequence, this command does not
// complete until all tests are done. Since this can take a long time, the TPM
// will check after each test to see if the command is canceled. If so, then the
// TPM will returned TPM_RC_CANCELLED. To continue with the self-tests, call
// TPM2_SelfTest(fullTest == No) and the TPM will complete the testing.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED        if the command is canceled
LIB_EXPORT
TPM_RC
CryptSelfTest(TPMI_YES_NO fullTest  // IN: if full test is required
)
{
#if ALLOW_FORCE_FAILURE_MODE
    if(g_forceFailureMode)
        FAIL(FATAL_ERROR_FORCED);
#endif

    // CoP note: CryptInitializeToTest() already arms g_toTest at TPM startup.
    // ESAPI resubmits TPM2_SelfTest(fullTest=YES) while it receives
    // TPM_RC_TESTING. Reinitializing g_toTest on every retry would undo the
    // background drain's progress forever. COMPLETE is latched until the next
    // SelfTest command acknowledges it with SUCCESS; only a later independent
    // full-test request starts a new cycle.
    if(fullTest == YES && s_copFullSelfTestState == COP_SELF_TEST_COMPLETE)
    {
        s_copFullSelfTestState = COP_SELF_TEST_IDLE;
        return TPM_RC_SUCCESS;
    }
    if(fullTest == YES && s_copFullSelfTestState == COP_SELF_TEST_IDLE)
    {
        MemoryCopy(g_toTest, g_implementedAlgorithms, sizeof(g_toTest));
        CryptTestAlgorithm(TPM_ALG_ERROR, &g_toTest);
        s_copFullSelfTestState = COP_SELF_TEST_ACTIVE;
    }
    // CoP modification (do not block the host on the ~9s software self-test):
    // On this platform the cryptographic self-tests run in software (wolfSSL)
    // on a Cortex-M4 and take several seconds in aggregate. A synchronous full
    // run exceeds the host's TPM2_CC_SELF_TEST command timeout (Linux 6.8
    // tpm2_ordinal_duration_map = 3000 ms), which causes the tpm_crb probe to
    // time out during cold boot. Instead, report TPM_RC_TESTING while any
    // testable algorithm is still pending, and rely on the per-algorithm
    // "test on first use" mechanism (TPM_DO_SELF_TEST) to test each algorithm
    // before it is actually used. Per TCG this is valid asynchronous self-test
    // behaviour, and Linux's tpm2_do_selftest() maps TPM_RC_TESTING -> success.
    // Accept the request immediately. TPM2_GetTestResult advances one pending
    // algorithm per command and reports TPM_RC_TESTING until the cycle finishes.
    // This preserves Linux boot latency while giving management clients a
    // bounded, command-driven way to complete the requested full test.
    if(!CryptSelfTestIsPending())
        s_copFullSelfTestState = COP_SELF_TEST_IDLE;
    return TPM_RC_SUCCESS;
}

//*** CryptSelfTestDrainOne()
// CoP background self-test support (Option B). Tests at most ONE pending
// algorithm from g_toTest and clears its bit, then reports whether any
// algorithm still needs testing. This lets the CRB idle loop drain g_toTest
// incrementally so that a full TPM2_SelfTest(YES) eventually converges to
// TPM_RC_SUCCESS (honest GetTestResult and proactive failure detection), while
// the per-command CryptSelfTest() path still returns immediately (Option C).
// MUST be invoked from a context that has established the platform failure
// setjmp (see _plat__RunSelfTestDrain) because a failing self-test calls FAIL()
// which longjmps.
//  Return value: 2 if this call drained the last pending algorithm, 1 if more
//      algorithms still need testing, 0 if nothing was pending before this call,
//      -2 if host activity canceled the background step.
LIB_EXPORT int CryptSelfTestDrainOne(void)
{
    ALGORITHM_VECTOR oneAlgorithm = {0};
    TPM_ALG_ID alg;
    TPM_ALG_ID pending = TPM_ALG_ERROR;
    TPM_RC result;

    // Find the first algorithm still needing test.
    for(alg = TPM_ALG_FIRST; alg <= TPM_ALG_LAST; alg++)
    {
        if(TEST_BIT(alg, g_toTest))
        {
            pending = alg;
            break;
        }
    }
    if(pending == TPM_ALG_ERROR)
    {
        if(s_copFullSelfTestState == COP_SELF_TEST_ACTIVE)
            s_copFullSelfTestState = COP_SELF_TEST_COMPLETE;
        return 0;  // nothing left to test
    }

    // Use a temporary vector so AlgorithmTests enables cancellation. Successful
    // tests clear both this vector and g_toTest. If host activity arrives during
    // a long RSA/ECC test, leave its g_toTest bit pending and retry later.
    SET_BIT(pending, oneAlgorithm);
    result = CryptTestAlgorithm(pending, &oneAlgorithm);
    if(result == TPM_RC_CANCELED)
        return -2;
    if(result != TPM_RC_SUCCESS)
        return -1;

    // Report whether anything still needs testing.
    for(alg = TPM_ALG_FIRST; alg <= TPM_ALG_LAST; alg++)
    {
        if(TEST_BIT(alg, g_toTest))
            return 1;
    }
    s_copFullSelfTestState = COP_SELF_TEST_COMPLETE;
    return 2;
}

//*** CryptIncrementalSelfTest()
// This function is used to perform an incremental self-test. This implementation
// will perform the toTest values before returning. That is, it assumes that the
// TPM cannot perform background tasks between commands.
//
// This command may be canceled. If it is, then there is no return result.
// However, this command can be run again and the incremental progress will not
// be lost.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED         processing of this command was canceled
//      TPM_RC_TESTING          if toTest list is not empty
//      TPM_RC_VALUE            an algorithm in the toTest list is not implemented
TPM_RC
CryptIncrementalSelfTest(TPML_ALG* toTest,   // IN: list of algorithms to be tested
                         TPML_ALG* toDoList  // OUT: list of algorithms needing test
)
{
    ALGORITHM_VECTOR toTestVector = {0};
    TPM_ALG_ID       alg;
    UINT32           i;

    pAssert(toTest != NULL && toDoList != NULL);
    if(toTest->count > 0)
    {
        // Transcribe the toTest list into the toTestVector
        for(i = 0; i < toTest->count; i++)
        {
            alg = toTest->algorithms[i];

            // make sure that the algorithm value is not out of range
            if((alg > TPM_ALG_LAST) || !TEST_BIT(alg, g_implementedAlgorithms))
                return TPM_RC_VALUE;
            SET_BIT(alg, toTestVector);
        }
        // Run the test
        if(CryptRunSelfTests(&toTestVector) == TPM_RC_CANCELED)
            return TPM_RC_CANCELED;
    }
    // Fill in the toDoList with the algorithms that are still untested
    toDoList->count = 0;

    for(alg = TPM_ALG_FIRST;
        toDoList->count < MAX_ALG_LIST_SIZE && alg <= TPM_ALG_LAST;
        alg++)
    {
        if(TEST_BIT(alg, g_toTest))
            toDoList->algorithms[toDoList->count++] = alg;
    }
    return TPM_RC_SUCCESS;
}

//*** CryptInitializeToTest()
// This function will initialize the data structures for testing all the
// algorithms. This should not be called unless CryptAlgsSetImplemented() has
// been called
void CryptInitializeToTest(void)
{
    // Indicate that nothing has been tested
    memset(&g_cryptoSelfTestState, 0, sizeof(g_cryptoSelfTestState));

    // Copy the implemented algorithm vector
    MemoryCopy(g_toTest, g_implementedAlgorithms, sizeof(g_toTest));

    // Setting the algorithm to null causes the test function to just clear
    // out any algorithms for which there is no test.
    CryptTestAlgorithm(TPM_ALG_ERROR, &g_toTest);

    s_copFullSelfTestState = COP_SELF_TEST_ACTIVE;

    return;
}

//*** CryptTestAlgorithm()
// Only point of contact with the actual self tests. If a self-test fails, there
// is no return and the TPM goes into failure mode.
// The call to TestAlgorithm uses an algorithm selector and a bit vector. When the
// test is run, the corresponding bit in 'toTest' and in 'g_toTest' is CLEAR. If
// 'toTest' is NULL, then only the bit in 'g_toTest' is CLEAR.
// There is a special case for the call to TestAlgorithm(). When 'alg' is
// ALG_ERROR, TestAlgorithm() will CLEAR any bit in 'toTest' for which it has
// no test. This allows the knowledge about which algorithms have test to be
// accessed through the interface that provides the test.
//  Return Type: TPM_RC
//      TPM_RC_CANCELED     test was canceled
LIB_EXPORT
TPM_RC
CryptTestAlgorithm(TPM_ALG_ID alg, ALGORITHM_VECTOR* toTest)
{
    TPM_RC result;
#if ENABLE_SELF_TESTS
    result = TestAlgorithm(alg, toTest);
#else
    // If this is an attempt to determine the algorithms for which there is a
    // self test, pretend that all of them do. We do that by not clearing any
    // of the algorithm bits. When/if this function is called to run tests, it
    // will over report. This can be changed so that any call to check on which
    // algorithms have tests, 'toTest' can be cleared.
    if(alg != TPM_ALG_ERROR)
    {
        CLEAR_BIT(alg, g_toTest);
        if(toTest != NULL)
            CLEAR_BIT(alg, *toTest);
    }
    result = TPM_RC_SUCCESS;
#endif
    return result;
}