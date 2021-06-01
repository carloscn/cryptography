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
#include "OpensslTests.h"

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

static unsigned char* md5_golden_data = "5d41402abc4b2a76b9719d911017c592";
static int test_hash_md5(void)
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;
    /*open ssl MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_md5(input_str, strlen(input_str), outmd);
    CU_ASSERT_EQUAL(ret, 0);
    CU_ASSERT_STRING_EQUAL(outmd, md5_golden_data);
}
static int test_hash_sha1(void)
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;
    /*open ssl MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_md5(input_str, strlen(input_str), outmd);
    CU_ASSERT_EQUAL(ret, 1);
    CU_ASSERT_STRING_EQUAL(outmd, md5_golden_data);
}

static int test_hash_sha224(void)
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;
    /*open ssl MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_md5(input_str, strlen(input_str), outmd);
    CU_ASSERT_EQUAL(ret, 1);
}

static int test_hash_sha256(void)
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;
    /*open ssl MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_md5(input_str, strlen(input_str), outmd);
    CU_ASSERT_EQUAL(ret, 1);
}

static int test_hash_sha512(void)
{
    unsigned char input_str[] = "hello";
    unsigned char outmd[32];
    int ret = 0, i = 0;
    /*open ssl MD5 using*/
    memset(outmd, 0, 32);
    ret = openssl_md5(input_str, strlen(input_str), outmd);
    CU_ASSERT_EQUAL(ret, 1);
    CU_ASSERT_STRING_EQUAL(outmd, md5_golden_data);
}

static CU_TestInfo test_hash_md5_suite[] = {
        {"test openssl md5", TEST_FUN(test_hash_md5)},
        {"test openssl sha1", TEST_FUN(test_hash_sha1)},
        {"test openssl sha224", TEST_FUN(test_hash_sha224)},
        {"test openssl sha256", TEST_FUN(test_hash_sha256)},
        {"test openssl sha512", TEST_FUN(test_hash_sha512)},
        CU_TEST_INFO_NULL,
};

static CU_SuiteInfo suites[] = {
  { "openssl test hash and md5",  suite_success_init, suite_success_clean, NULL, NULL, test_hash_md5_suite},
	CU_SUITE_INFO_NULL,
};

static CU_SuiteInfo regression_suites[] = {

};

void add_openssl_testsuite(void)
{
  assert(NULL != CU_get_registry());
  assert(!CU_is_test_running());

	/* Register suites. */
	if (CU_register_suites(suites) != CUE_SUCCESS) {
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

void print_openssl_results(void)
{
  fprintf(stdout, "\n\nExpected Test Results:"
                  "\n\n  Error Handling  Type      # Run   # Pass   # Fail"
                  "\n\n  ignore errors   suites%9u%9u%9u"
                    "\n                  tests %9u%9u%9u"
                    "\n                  asserts%8u%9u%9u"
                  "\n\n  stop on error   suites%9u%9u%9u"
                    "\n                  tests %9u%9u%9u"
                    "\n                  asserts%8u%9u%9u\n\n",
                  14, 14, 3,
                  31, 10, 21,
                  89, 47, 42,
                  4, 4, 1,
                  12, 9, 3,
                  12, 9, 3);
}
