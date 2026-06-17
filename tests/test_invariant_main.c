#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Mock structures matching main.c */
#define FLASH_BUFFER_SIZE 4096

typedef struct {
    uint8_t *body_frag_start;
    uint32_t body_frag_len;
} http_response_t;

typedef struct {
    uint8_t flash_buffer[FLASH_BUFFER_SIZE];
    uint32_t flash_buffer_len;
} ota_context_t;

/* Forward declaration of the vulnerable function from main.c */
void process_ota_fragment(ota_context_t *ctx, http_response_t *rsp);

START_TEST(test_flash_buffer_overflow_protection)
{
    /* Invariant: memcpy into flash_buffer must never write beyond FLASH_BUFFER_SIZE,
       even when adversarial fragment sizes are provided */
    
    ota_context_t ctx;
    http_response_t rsp;
    uint8_t payload_data[5000];
    
    /* Test payloads: exploit case, boundary cases, valid input */
    struct {
        uint32_t initial_offset;
        uint32_t fragment_size;
        const char *description;
    } test_cases[] = {
        { 4090, 100, "Overflow: offset + size > FLASH_BUFFER_SIZE" },
        { 4095, 1, "Boundary: exact buffer end" },
        { 4096, 1, "Overflow: offset already at limit" },
        { 2048, 2048, "Valid: half buffer" },
        { 0, 100, "Valid: small fragment at start" }
    };
    
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    for (int i = 0; i < num_cases; i++) {
        memset(&ctx, 0, sizeof(ctx));
        memset(&rsp, 0, sizeof(rsp));
        memset(payload_data, 0xAA, sizeof(payload_data));
        
        ctx.flash_buffer_len = test_cases[i].initial_offset;
        rsp.body_frag_start = payload_data;
        rsp.body_frag_len = test_cases[i].fragment_size;
        
        /* Call the vulnerable function - it should handle bounds safely */
        process_ota_fragment(&ctx, &rsp);
        
        /* Security invariant: buffer_len must never exceed allocated size */
        ck_assert_msg(ctx.flash_buffer_len <= FLASH_BUFFER_SIZE,
                      "Buffer overflow detected at test case %d (%s): "
                      "buffer_len=%u exceeds FLASH_BUFFER_SIZE=%u",
                      i, test_cases[i].description, ctx.flash_buffer_len, FLASH_BUFFER_SIZE);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("OTA_Security");
    tc_core = tcase_create("BufferBounds");

    tcase_add_test(tc_core, test_flash_buffer_overflow_protection);
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