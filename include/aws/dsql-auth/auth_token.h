/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AWS_DSQL_AUTH_AUTH_TOKEN_H
#define AWS_DSQL_AUTH_AUTH_TOKEN_H

#include <aws/common/allocator.h>
#include <aws/common/macros.h>
#include <aws/common/string.h>
#include <aws/dsql-auth/exports.h>
#include <aws/io/io.h>
#include <stdint.h>

AWS_EXTERN_C_BEGIN

/**
 * @defgroup aws-dsql-auth Aurora DSQL Authentication Token Generator
 * @{
 */

/**
 * Configuration for the DSQL auth token generator.
 */
struct aws_dsql_auth_config {
    /**
     * The AWS credentials provider to source credentials from.
     * If NULL, the default credential provider chain will be used.
     */
    struct aws_credentials_provider *credentials_provider;

    /**
     * The hostname of the database to connect to.
     * Required.
     */
    const char *hostname;

    /**
     * The region the database is located in.
     * Required.
     */
    struct aws_string *region;

    /**
     * The number of seconds the signed URL should be valid for.
     * Default is 900 seconds (15 minutes) if 0 is specified.
     */
    uint64_t expires_in;

    /**
     * For mocking, leave NULL otherwise
     */
    aws_io_clock_fn *system_clock_fn;
};

/**
 * An auth token usable as a password for a DSQL database.
 */
struct aws_dsql_auth_token {
    /**
     * The token string.
     */
    struct aws_string *token;
};

/**
 * Initialize a new auth token config with default values.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[out] config The config to initialize
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_init(struct aws_dsql_auth_config *config);

/**
 * Clean up resources associated with the auth token config.
 *
 * @param[in] config The config to clean up
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_config_clean_up(struct aws_dsql_auth_config *config);

/**
 * Set the hostname for the auth token config.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in,out] config The config to modify
 * @param[in] hostname The hostname to set
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_set_hostname(struct aws_dsql_auth_config *config, const char *hostname);

/**
 * Set the region for the auth token config.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in,out] config The config to modify
 * @param[in] region The region to set
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_set_region(struct aws_dsql_auth_config *config, struct aws_string *region);

/**
 * Try to infer the region from the hostname and set it in the config if successful.
 * The hostname must follow the format '<cluster-id>.dsql.<region>.on.aws', where cluster-id is always 26 characters.
 * If the hostname does not match this format, the region will not be set.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in] config The config
 * @param[out] out_region Output parameter to receive the inferred region
 *
 * @return AWS_OP_SUCCESS if the region was successfully inferred and set, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_infer_region(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    struct aws_string **out_region);

/**
 * Set the expiration time for the auth token config.
 *
 * @param[in,out] config The config to modify
 * @param[in] expires_in The expiration time in seconds
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_config_set_expires_in(struct aws_dsql_auth_config *config, uint64_t expires_in);

/**
 * Set the credentials provider for the auth token config.
 *
 * @param[in,out] config The config to modify
 * @param[in] credentials_provider The credentials provider to set
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_config_set_credentials_provider(
    struct aws_dsql_auth_config *config,
    struct aws_credentials_provider *credentials_provider);

/**
 * Generate an authentication token for Aurora DSQL.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in] config The configuration for the token generator
 * @param[in] is_admin Whether to generate an admin token (true) or regular token (false)
 * @param[out] token The generated token
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_token_generate(
    const struct aws_dsql_auth_config *config,
    bool is_admin,
    struct aws_allocator *allocator,
    struct aws_dsql_auth_token *token);

/**
 * Clean up resources associated with the auth token.
 *
 * @param[in] token The token to clean up
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_token_clean_up(struct aws_dsql_auth_token *token);

/**
 * Get the token string.
 *
 * @param[in] token The token
 *
 * @return The token string
 */
AWS_DSQL_AUTH_API const char *aws_dsql_auth_token_get_str(const struct aws_dsql_auth_token *token);

/**
 * @}
 */

AWS_EXTERN_C_END

#endif /* AWS_DSQL_AUTH_AUTH_TOKEN_H */
