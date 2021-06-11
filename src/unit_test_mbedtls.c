/*
 *  CUnit - A Unit testing framework library for C.
 *  Copyright (C) 2001        Anil Kumar
 *  Copyright (C) 2004, 2005  Anil Kumar, Jerry St.Clair
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "CUnit.h"
#include "mbedtls_cmac_exa.h"
#include "unit_test_mbedtls.h"

/* WARNING - MAINTENANCE NIGHTMARE AHEAD
 *
 * If you change any of the tests & suites below, you also need
 * to keep track of changes in the result statistics and reflect
 * any changes in the result report counts in print_example_results().
 *
 * Yes, this could have been designed better using a more
 * automated mechanism.  No, it was not done that way.
 */

/* Suite initialization/cleanup functions */
static int suite_success_init(void) {
    printf("suite_succuse_init\n");
    return 0; }
static int suite_success_clean(void) { return 0; }

static int suite_failure_init(void) { return 1;}
static int suite_failure_clean(void) { return 1; }

static void testSuccess1(void) { CU_ASSERT(1); }
static void testSuccess2(void) { CU_ASSERT(2); }
static void testSuccess3(void) { CU_ASSERT(3); }

static void testSuiteFailure1(void) { CU_ASSERT(0); }
static void testSuiteFailure2(void) { CU_ASSERT(2); }

static void testFailure1(void) { CU_ASSERT(0); }
static void testFailure2(void) { CU_ASSERT(0); }
static void testFailure3(void) { CU_ASSERT(0); }

#define TEST_FUN(a)  ((void*)a)

static uint8_t cmac_gd_msg[] = {
        0x6a, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};
static uint8_t cmac_aes_128_ecb_gd_key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
static uint8_t cmac_aes_128_ecb_gd_output[] = {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
};
static uint8_t cmac_aes_192_ecb_gd_key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
static uint8_t cmac_aes_192_ecb_gd_output[] = {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
};
static void test_mbedtls_cmac_aes_128_ecb(void)
{
    int ret = 0;
    uint8_t output[16];
    size_t outlen = 0;
    memset(output, 0, ARRAY_SIZE(output));
    ret = mbedtls_cmac_aes_128_ecb(cmac_aes_128_ecb_gd_key, 128/8,
                                   cmac_gd_msg, ARRAY_SIZE(cmac_gd_msg),
                                   output, &outlen);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_STRING_EQUAL(output, cmac_aes_128_ecb_gd_output);
    PRINTF_ARRAY(output, ARRAY_SIZE(output), "\ncacu output :");
    PRINTF_ARRAY(cmac_aes_128_ecb_gd_output, ARRAY_SIZE(cmac_aes_128_ecb_gd_output), "gldn output :");
}

static void test_mbedtls_cmac_aes_192_ecb(void)
{
    int ret = 0;
    uint8_t output[24];
    size_t outlen = 0;
    memset(output, 0, ARRAY_SIZE(output));
    ret = mbedtls_cmac_aes_192_ecb(cmac_aes_192_ecb_gd_key, 192/8,
                                   cmac_gd_msg, ARRAY_SIZE(cmac_gd_msg),
                                   output, &outlen);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_STRING_EQUAL(output, cmac_aes_192_ecb_gd_output);
    PRINTF_ARRAY(output, ARRAY_SIZE(output), "\noutput :");
    PRINTF_ARRAY(cmac_aes_128_ecb_gd_output, ARRAY_SIZE(cmac_aes_128_ecb_gd_output), "\noutput :");
}

static CU_TestInfo test_cmac_suite[] = {
        {"test mbedtls cmac_aes_128_ecb", TEST_FUN(test_mbedtls_cmac_aes_128_ecb)},
        {"test mbedtls cmac_aes_192_ecb", TEST_FUN(test_mbedtls_cmac_aes_192_ecb)},
        CU_TEST_INFO_NULL
};

static CU_SuiteInfo suites_list[] = {
  { "mbedtls test cmac",  suite_success_init, suite_success_clean, NULL, NULL, test_cmac_suite},
	CU_SUITE_INFO_NULL,
};


void add_mbedtls_testsuite(void)
{
  assert(NULL != CU_get_registry());
  assert(!CU_is_test_running());

	/* Register suites. */
	if (CU_register_suites(suites_list) != CUE_SUCCESS) {
		fprintf(stderr, "suite registration failed - %s\n",
			CU_get_error_msg());
		exit(EXIT_FAILURE);
	}

/* implementation without shortcut registration
  CU_pSuite pSuite;

  pSuite = CU_add_suite("suite_success_both", suite_success_init, suite_success_clean);
  CU_add_test(pSuite, "testSuccess1", testSuccess1);
  CU_add_test(pSuite, "testSuccess2", testSuccess2);
  CU_add_test(pSuite, "testSuccess3", testSuccess3);

  pSuite = CU_add_suite("suite_success_init", suite_success_init, NULL);
  CU_add_test(pSuite, "testSuccess1", testSuccess1);
  CU_add_test(pSuite, "testSuccess2", testSuccess2);
  CU_add_test(pSuite, "testSuccess3", testSuccess3);

  pSuite = CU_add_suite("suite_success_clean", NULL, suite_success_clean);
  CU_add_test(pSuite, "testSuccess1", testSuccess1);
  CU_add_test(pSuite, "testSuccess2", testSuccess2);
  CU_add_test(pSuite, "testSuccess3", testSuccess3);

  pSuite = CU_add_suite("test_failure", NULL, NULL);
  CU_add_test(pSuite, "testFailure1", testFailure1);
  CU_add_test(pSuite, "testFailure2", testFailure2);
  CU_add_test(pSuite, "testFailure3", testFailure3);

  / * tests should not run * /
  pSuite = CU_add_suite("suite_failure_both", suite_failure_init, suite_failure_clean);
  CU_add_test(pSuite, "testSuiteFailure1", testSuiteFailure1);
  CU_add_test(pSuite, "testSuiteFailure2", testSuiteFailure2);

  / * tests should not run * /
  pSuite = CU_add_suite("suite_failure_init", suite_failure_init, NULL);
  CU_add_test(pSuite, "testSuiteFailure1", testSuiteFailure1);
  CU_add_test(pSuite, "testSuiteFailure2", testSuiteFailure2);

  / * tests will run, suite counted as running, but suite tagged as a failure * /
  pSuite = CU_add_suite("suite_success_but_failure_clean", NULL, suite_failure_clean);
  CU_add_test(pSuite, "testSuiteFailure1", testSuiteFailure1);
  CU_add_test(pSuite, "testSuiteFailure2", testSuiteFailure2);

  pSuite = CU_add_suite("TestSimpleAssert", NULL, NULL);
  CU_add_test(pSuite, "testSimpleAssert", testSimpleAssert);
  CU_add_test(pSuite, "testFail", testFail);

  pSuite = CU_add_suite("TestBooleanAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertTrue", testAssertTrue);
  CU_add_test(pSuite, "testAssertFalse", testAssertFalse);

  pSuite = CU_add_suite("TestEqualityAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertEqual", testAssertEqual);
  CU_add_test(pSuite, "testAssertNotEqual", testAssertNotEqual);

  pSuite = CU_add_suite("TestPointerAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertPtrEqual", testAssertPtrEqual);
  CU_add_test(pSuite, "testAssertPtrNotEqual", testAssertPtrNotEqual);

  pSuite = CU_add_suite("TestNullnessAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertPtrNull", testAssertPtrNull);
  CU_add_test(pSuite, "testAssertPtrNotNull", testAssertPtrNotNull);

  pSuite = CU_add_suite("TestStringAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertStringEqual", testAssertStringEqual);
  CU_add_test(pSuite, "testAssertStringNotEqual", testAssertStringNotEqual);

  pSuite = CU_add_suite("TestNStringAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertNStringEqual", testAssertNStringEqual);
  CU_add_test(pSuite, "testAssertNStringNotEqual", testAssertNStringNotEqual);

  pSuite = CU_add_suite("TestDoubleAssert", NULL, NULL);
  CU_add_test(pSuite, "testAssertDoubleEqual", testAssertDoubleEqual);
  CU_add_test(pSuite, "testAssertDoubleNotEqual", testAssertDoubleNotEqual);

  pSuite = CU_add_suite("TestFatal", NULL, NULL);
  CU_add_test(pSuite, "testFatal", testFatal);
*/
}

