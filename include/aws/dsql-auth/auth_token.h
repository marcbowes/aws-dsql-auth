/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AWS_DSQL_AUTH_TOKEN_H
#define AWS_DSQL_AUTH_TOKEN_H

#include <aws/common/common.h>
#include <aws/dsql-auth/exports.h>

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
     * The AWS credentials to sign requests with.
     * If NULL, the default credential provider chain will be used.
     */
    struct aws_credentials *credentials;

    /**
     * The hostname of the database to connect to.
     * Required.
     */
    const char *hostname;

    /**
     * The region the database is located in.
     * If NULL, the region will be inferred from the environment.
     */
    const char *region;

    /**
     * The number of seconds the signed URL should be valid for.
     * Default is 900 seconds (15 minutes) if 0 is specified.
     */
    uint64_t expires_in;
};

/**
 * An auth token usable as a password for a DSQL database.
 */
struct aws_dsql_auth_token {
    /**
     * The token string.
     */
    char *token;

    /**
     * The allocator used to create the token.
     */
    struct aws_allocator *allocator;
};

/**
 * Initialize a new auth token config with default values.
 * 
 * @param[in] allocator The allocator to use for memory allocation
 * @param[out] config The config to initialize
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_init(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config);

/**
 * Clean up resources associated with the auth token config.
 * 
 * @param[in] config The config to clean up
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_config_clean_up(
    struct aws_dsql_auth_config *config);

/**
 * Set the hostname for the auth token config.
 * 
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in,out] config The config to modify
 * @param[in] hostname The hostname to set
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_set_hostname(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    const char *hostname);

/**
 * Set the region for the auth token config.
 * 
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in,out] config The config to modify
 * @param[in] region The region to set
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
AWS_DSQL_AUTH_API int aws_dsql_auth_config_set_region(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    const char *region);

/**
 * Set the expiration time for the auth token config.
 * 
 * @param[in,out] config The config to modify
 * @param[in] expires_in The expiration time in seconds
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_config_set_expires_in(
    struct aws_dsql_auth_config *config,
    uint64_t expires_in);

/**
 * Set the credentials for the auth token config.
 * 
 * @param[in,out] config The config to modify
 * @param[in] credentials The credentials to set
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_config_set_credentials(
    struct aws_dsql_auth_config *config,
    struct aws_credentials *credentials);

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
    struct aws_allocator *allocator,
    const struct aws_dsql_auth_config *config,
    bool is_admin,
    struct aws_dsql_auth_token *token);

/**
 * Clean up resources associated with the auth token.
 * 
 * @param[in] token The token to clean up
 */
AWS_DSQL_AUTH_API void aws_dsql_auth_token_clean_up(
    struct aws_dsql_auth_token *token);

/**
 * Get the token string.
 * 
 * @param[in] token The token
 * 
 * @return The token string
 */
AWS_DSQL_AUTH_API const char *aws_dsql_auth_token_get_str(
    const struct aws_dsql_auth_token *token);

/**
 * @}
 */

AWS_EXTERN_C_END

#endif /* AWS_DSQL_AUTH_TOKEN_H */
