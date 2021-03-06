//
// Created by carwei02 on 6/1/2021.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Basic.h"
#include "ExampleTests.h"
#include "OpensslTests.h"

int test_suite_entry(int argc, char* argv[]) {
    CU_BasicRunMode mode = CU_BRM_VERBOSE;
    CU_ErrorAction error_action = CUEA_IGNORE;
    int i;

    setvbuf(stdout, NULL, _IONBF, 1);

    for (i=2 ; i<argc ; i++) {
        if (!strcmp("-i", argv[i])) {
            error_action = CUEA_IGNORE;
        }
        else if (!strcmp("-f", argv[i])) {
            error_action = CUEA_FAIL;
        }
        else if (!strcmp("-A", argv[i])) {
            error_action = CUEA_ABORT;
        }
        else if (!strcmp("-s", argv[i])) {
            mode = CU_BRM_SILENT;
        }
        else if (!strcmp("-n", argv[i])) {
            mode = CU_BRM_NORMAL;
        }
        else if (!strcmp("-v", argv[i])) {
            mode = CU_BRM_VERBOSE;
        }
        else if (!strcmp("-e", argv[i])) {
            print_example_results();
            return 1;
        }
        else {
            printf("\nUsage:  BasicTest [options]\n\n"
                   "Options:   -i   ignore framework errors [default].\n"
                   "           -f   fail on framework error.\n"
                   "           -A   abort on framework error.\n\n"
                   "           -s   silent mode - no output to screen.\n"
                   "           -n   normal mode - standard output to screen.\n"
                   "           -v   verbose mode - max output to screen [default].\n\n"
                   "           -e   print expected test results and exit.\n"
                   "           -h   print this message and exit.\n\n");
            return 1;
        }
    }

    if (CU_initialize_registry()) {
        printf("\nInitialization of Test Registry failed.");
    }
    else {
        //AddTests();
        //add_openssl_testsuite();
        CU_basic_set_mode(mode);
        CU_set_error_action(error_action);
        printf("\nTests completed with return value %d.\n", CU_basic_run_tests());
        //print_openssl_results();
        CU_cleanup_registry();
    }

    return 1;
}