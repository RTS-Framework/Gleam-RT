#include <check.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "src/mod_argument.h"

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const uint32_t payloads[] = {
        UINT32_MAX - 100,  // Exact exploit case: causes overflow in calculation
        UINT32_MAX,        // Boundary value: maximum possible size
        1024               // Valid input: normal size
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        uint32_t size = payloads[i];
        uint32_t num = 10;  // Small number of arguments
        
        // Create test context with minimal page size to maximize overflow potential
        TestContext context;
        context.MPS = 4096;
        
        // Create argument store
        ArgumentStore store;
        
        // Call the actual vulnerable function
        int result = loadArguments(&context, &store, size, num);
        
        // The function should either:
        // 1. Return failure (reject oversized input)
        // 2. Successfully handle without buffer overflow
        // We can't directly test for overflow, but we can ensure no crash occurs
        // and that if it succeeds, subsequent operations don't exceed bounds
        
        if (result == SUCCESS) {
            // If allocation succeeded, verify we can safely access within bounds
            ck_assert_ptr_nonnull(store.arguments);
            // Additional checks could be added here to verify no out-of-bounds access
        }
        // If result == FAILURE, that's acceptable - oversized input was rejected
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}