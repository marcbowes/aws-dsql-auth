include(AwsTestHarness)
enable_testing()

file(GLOB TEST_SRC "*.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(aws_dsql_auth_signing_works_test)
add_test_case(aws_dsql_auth_signing_works_admin_test)
add_test_case(aws_dsql_auth_region_detection_test)
add_test_case(aws_dsql_auth_region_inference_private_endpoint_test)
add_test_case(aws_dsql_auth_region_inference_invalid_hostname_test)

set(TEST_BINARY_NAME ${PROJECT_NAME}-tests)
generate_test_driver(${TEST_BINARY_NAME})
