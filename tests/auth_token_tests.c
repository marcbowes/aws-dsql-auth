/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/auth/auth.h>
#include <aws/auth/credentials.h>
#include <aws/common/clock.h>
#include <aws/common/date_time.h>
#include <aws/common/error.h> /* for AWS_ERROR_INVALID_ARGUMENT */
#include <aws/dsql-auth/auth_token.h>
#include <string.h>

/* Mock time functions */
static struct aws_mutex system_clock_sync = AWS_MUTEX_INIT;
static uint64_t system_clock_time = 0;

int mock_aws_get_system_time(uint64_t *current_time) {
    aws_mutex_lock(&system_clock_sync);
    *current_time = system_clock_time;
    aws_mutex_unlock(&system_clock_sync);
    return AWS_OP_SUCCESS;
}

void mock_aws_set_system_time(uint64_t current_time) {
    aws_mutex_lock(&system_clock_sync);
    system_clock_time = current_time;
    aws_mutex_unlock(&system_clock_sync);
}

/* Test constants */
AWS_STATIC_STRING_FROM_LITERAL(s_access_key_id, "akid");
AWS_STATIC_STRING_FROM_LITERAL(s_secret_access_key, "secret");
AWS_STATIC_STRING_FROM_LITERAL(s_session_token, "token");
AWS_STATIC_STRING_FROM_LITERAL(s_hostname, "peccy.dsql.us-east-1.on.aws");
AWS_STATIC_STRING_FROM_LITERAL(s_region, "us-east-1");

/**
 * Helper function to create a static credentials provider
 */
static struct aws_credentials_provider *s_create_test_credentials_provider(struct aws_allocator *allocator) {
    struct aws_credentials_provider_static_options options = {
        .access_key_id = aws_byte_cursor_from_string(s_access_key_id),
        .secret_access_key = aws_byte_cursor_from_string(s_secret_access_key),
        .session_token = aws_byte_cursor_from_string(s_session_token)};

    return aws_credentials_provider_new_static(allocator, &options);
}

/**
 * Helper function to set up auth config
 */
static int s_setup_auth_config(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    struct aws_credentials_provider *credentials_provider,
    uint64_t expires_in) {

    ASSERT_SUCCESS(aws_dsql_auth_config_init(config));
    ASSERT_SUCCESS(aws_dsql_auth_config_set_hostname(config, aws_string_c_str(s_hostname)));
    config->region = s_region; /* Set region directly */
    aws_dsql_auth_config_set_expires_in(config, expires_in);
    aws_dsql_auth_config_set_credentials_provider(config, credentials_provider);

    /* Set the mock time functions */
    config->system_clock_fn = mock_aws_get_system_time;

    return AWS_OP_SUCCESS;
}

/**
 * Test that signing works for regular DbConnect action
 */
static int s_aws_dsql_auth_signing_works_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Initialize the AWS auth library */
    aws_auth_library_init(allocator);

    /* Set the mock time to August 27, 2024 at 00:00:00 UTC (1724716800 seconds since Unix epoch) */
    mock_aws_set_system_time(1724716800ULL * 1000000000ULL); /* Convert to nanoseconds */

    /* Create credentials provider */
    struct aws_credentials_provider *credentials_provider = s_create_test_credentials_provider(allocator);
    ASSERT_NOT_NULL(credentials_provider);

    /* Set up auth config */
    struct aws_dsql_auth_config config;
    ASSERT_SUCCESS(s_setup_auth_config(allocator, &config, credentials_provider, 450));

    /* Generate auth token */
    struct aws_dsql_auth_token token = {0}; /* Zero-initialize */
    ASSERT_SUCCESS(aws_dsql_auth_token_generate(&config, false, allocator, &token));

    /* Verify token */
    const char *token_str = aws_dsql_auth_token_get_str(&token);
    ASSERT_NOT_NULL(token_str);

    /* Check full token string */
    ASSERT_STR_EQUALS(
        "peccy.dsql.us-east-1.on.aws/"
        "?Action=DbConnect&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=akid%2F20240827%2Fus-east-1%2Fdsql%2Faws4_"
        "request&X-Amz-Date=20240827T000000Z&X-Amz-SignedHeaders=host&X-Amz-Expires=450&X-Amz-Security-Token=token&X-"
        "Amz-Signature=9fdb9de7ca6822832943d5a4e1b02411d302a2b8204bd7e8193aa4875fbd5a58",
        token_str);

    /* Clean up */
    aws_dsql_auth_token_clean_up(&token);
    aws_dsql_auth_config_clean_up(&config);
    aws_credentials_provider_release(credentials_provider);

    /* Clean up the AWS auth library */
    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

/**
 * Test that signing works for admin DbConnectAdmin action
 */
static int s_aws_dsql_auth_signing_works_admin_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Initialize the AWS auth library */
    aws_auth_library_init(allocator);

    /* Set the mock time to August 27, 2024 at 00:00:00 UTC (1724716800 seconds since Unix epoch) */
    mock_aws_set_system_time(1724716800ULL * 1000000000ULL); /* Convert to nanoseconds */

    /* Create credentials provider */
    struct aws_credentials_provider *credentials_provider = s_create_test_credentials_provider(allocator);
    ASSERT_NOT_NULL(credentials_provider);

    /* Set up auth config */
    struct aws_dsql_auth_config config;
    ASSERT_SUCCESS(s_setup_auth_config(allocator, &config, credentials_provider, 450));

    /* Generate admin auth token */
    struct aws_dsql_auth_token token = {0}; /* Zero-initialize */
    ASSERT_SUCCESS(aws_dsql_auth_token_generate(&config, true, allocator, &token));

    /* Verify token */
    const char *token_str = aws_dsql_auth_token_get_str(&token);
    ASSERT_NOT_NULL(token_str);

    /* Check full token string */
    ASSERT_STR_EQUALS(
        "peccy.dsql.us-east-1.on.aws/"
        "?Action=DbConnectAdmin&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=akid%2F20240827%2Fus-east-1%2Fdsql%"
        "2Faws4_request&X-Amz-Date=20240827T000000Z&X-Amz-SignedHeaders=host&X-Amz-Expires=450&X-Amz-Security-Token="
        "token&X-Amz-Signature=dd5373133b347f82a6e8a710e5fbd367f5e1d84824dc148b96d5f45089cb47f0",
        token_str);

    /* Clean up */
    aws_dsql_auth_token_clean_up(&token);
    aws_dsql_auth_config_clean_up(&config);
    aws_credentials_provider_release(credentials_provider);

    /* Clean up the AWS auth library */
    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

/**
 * Test that region auto-detection works from hostname using aws_dsql_auth_config_infer_region
 */
static int s_aws_dsql_auth_region_detection_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Initialize the AWS auth library */
    aws_auth_library_init(allocator);

    /* Set the mock time to August 27, 2024 at 00:00:00 UTC (1724716800 seconds since Unix epoch) */
    mock_aws_set_system_time(1724716800ULL * 1000000000ULL); /* Convert to nanoseconds */

    /* Create credentials provider */
    struct aws_credentials_provider *credentials_provider = s_create_test_credentials_provider(allocator);
    ASSERT_NOT_NULL(credentials_provider);

    /* Set up auth config but don't set region - we'll infer it from hostname */
    struct aws_dsql_auth_config config;
    ASSERT_SUCCESS(aws_dsql_auth_config_init(&config));

    /* Use a hostname with the expected format: <cluster-id>.dsql.<region>.on.aws */
    const char *test_hostname = "24abtvxzzxzrrfaxyduobmpfea.dsql.us-east-1.on.aws";
    ASSERT_SUCCESS(aws_dsql_auth_config_set_hostname(&config, test_hostname));

    /* Infer the region from the hostname */
    struct aws_string *region_str = NULL;
    ASSERT_SUCCESS(aws_dsql_auth_config_infer_region(allocator, &config, &region_str));

    /* Verify the region was correctly inferred */
    ASSERT_NOT_NULL(region_str);
    ASSERT_TRUE(aws_string_eq_c_str(region_str, "us-east-1"));
    
    /* Set the region in the config */
    config.region = region_str;
    
    aws_dsql_auth_config_set_expires_in(&config, 450);
    aws_dsql_auth_config_set_credentials_provider(&config, credentials_provider);

    /* Set the mock time functions */
    config.system_clock_fn = mock_aws_get_system_time;

    /* Generate auth token */
    struct aws_dsql_auth_token token = {0}; /* Zero-initialize */
    ASSERT_SUCCESS(aws_dsql_auth_token_generate(&config, false, allocator, &token));

    /* Verify token */
    const char *token_str = aws_dsql_auth_token_get_str(&token);
    ASSERT_NOT_NULL(token_str);

    /* Check that token contains the region (us-east-1) that was extracted from the hostname */
    /* We don't check the full token string since we only care that the region was properly extracted */
    ASSERT_TRUE(strstr(token_str, "us-east-1") != NULL);

    /* Clean up */
    aws_dsql_auth_token_clean_up(&token);
    aws_dsql_auth_config_clean_up(&config);
    aws_credentials_provider_release(credentials_provider);
    aws_string_destroy(region_str);

    /* Clean up the AWS auth library */
    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

/**
 * Test that region inference fails with invalid hostname format
 */
static int s_aws_dsql_auth_region_inference_invalid_hostname_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Initialize the AWS auth library */
    aws_auth_library_init(allocator);

    /* Set up auth config */
    struct aws_dsql_auth_config config;
    ASSERT_SUCCESS(aws_dsql_auth_config_init(&config));

    /* Test cases with invalid hostnames */
    const char *invalid_hostnames[] = {/* Too short cluster ID */
                                       "12345.dsql.us-east-1.on.aws",

                                       /* Wrong format - missing dsql */
                                       "24abtvxzzxzrrfaxyduobmpfea.wrong.us-east-1.on.aws",

                                       /* Wrong ending */
                                       "24abtvxzzxzrrfaxyduobmpfea.dsql.us-east-1.wrong",

                                       /* No region between dsql and on.aws */
                                       "24abtvxzzxzrrfaxyduobmpfea.dsql.on.aws"};

    for (size_t i = 0; i < sizeof(invalid_hostnames) / sizeof(invalid_hostnames[0]); i++) {
        /* Set up config with invalid hostname */
        ASSERT_SUCCESS(aws_dsql_auth_config_set_hostname(&config, invalid_hostnames[i]));

        /* Attempt to infer region - should fail because hostname format is invalid */
        struct aws_string *region_str = NULL;
        ASSERT_ERROR(AWS_ERROR_INVALID_ARGUMENT, aws_dsql_auth_config_infer_region(allocator, &config, &region_str));
    }

    /* Clean up */
    aws_dsql_auth_config_clean_up(&config);

    /* Clean up the AWS auth library */
    aws_auth_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_dsql_auth_signing_works_test, s_aws_dsql_auth_signing_works_test);
AWS_TEST_CASE(aws_dsql_auth_signing_works_admin_test, s_aws_dsql_auth_signing_works_admin_test);
AWS_TEST_CASE(aws_dsql_auth_region_detection_test, s_aws_dsql_auth_region_detection_test);
AWS_TEST_CASE(
    aws_dsql_auth_region_inference_invalid_hostname_test,
    s_aws_dsql_auth_region_inference_invalid_hostname_test);
