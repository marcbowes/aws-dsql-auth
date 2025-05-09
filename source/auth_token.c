/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <aws/auth/credentials.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_config.h>
#include <aws/auth/signing_result.h>
#include <aws/common/allocator.h> /* for aws_allocator, aws_mem_calloc/release */
#include <aws/common/byte_buf.h>  /* for aws_byte_cursor_from_c_str */
#include <aws/common/clock.h>     /* for aws_sys_clock_get_ticks function */
#include <aws/common/condition_variable.h>
#include <aws/common/date_time.h>
#include <aws/common/error.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/zero.h> /* for AWS_ZERO_STRUCT */
#include <aws/dsql-auth/auth_token.h>
#include <aws/http/request_response.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h> /* for strlen, strcmp, memcpy */

/* Hostname format: <cluster-id>.dsql.<region>.on.aws, where cluster-id is 26 chars */
#define DSQL_HOSTNAME_SUFFIX ".dsql."
#define DSQL_HOSTNAME_END ".on.aws"

enum { CLUSTER_ID_LENGTH = 26 };

#define ACTION_DB_CONNECT "DbConnect"
#define ACTION_DB_CONNECT_ADMIN "DbConnectAdmin"
#define SERVICE_NAME "dsql"

enum { DEFAULT_EXPIRES_IN = 900 };

int aws_dsql_auth_config_init(struct aws_dsql_auth_config *config) {
    AWS_ZERO_STRUCT(*config);
    config->expires_in = DEFAULT_EXPIRES_IN;

    return AWS_OP_SUCCESS;
}

void aws_dsql_auth_config_clean_up(struct aws_dsql_auth_config *config) {
    if (!config) {
        return;
    }

    if (config->credentials_provider) {
        aws_credentials_provider_release(config->credentials_provider);
    }

    AWS_ZERO_STRUCT(*config);
}

void aws_dsql_auth_config_set_hostname(struct aws_dsql_auth_config *config, const char *hostname) {
    config->hostname = hostname;
}

void aws_dsql_auth_config_set_region(struct aws_dsql_auth_config *config, struct aws_string *region) {
    config->region = region;
}

void aws_dsql_auth_config_set_expires_in(struct aws_dsql_auth_config *config, uint64_t expires_in) {
    config->expires_in = expires_in;
}

void aws_dsql_auth_config_set_credentials_provider(
    struct aws_dsql_auth_config *config,
    struct aws_credentials_provider *credentials_provider) {

    if (config->credentials_provider) {
        aws_credentials_provider_release(config->credentials_provider);
    }

    config->credentials_provider = credentials_provider;
    if (credentials_provider) {
        aws_credentials_provider_acquire(credentials_provider);
    }
}

/* Structure to hold signing state */
struct aws_signing_userdata {
    struct aws_allocator *allocator;

    struct aws_mutex mutex;
    struct aws_condition_variable condition_var;

    struct aws_http_message *request;

    int signing_result_code;
    bool is_signing_complete;
};

/* Callback for when signing is complete */
static void s_on_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {
    struct aws_signing_userdata *context = userdata;

    aws_mutex_lock(&context->mutex);

    /* Store the result in the userdata */
    aws_apply_signing_result_to_http_request(context->request, context->allocator, result);
    context->signing_result_code = error_code;
    context->is_signing_complete = true;

    aws_condition_variable_notify_one(&context->condition_var);
    aws_mutex_unlock(&context->mutex);
}

/* Helper function for condition variable predicate */
static bool s_is_signing_complete(void *userdata) {
    struct aws_signing_userdata *context = userdata;
    return context->is_signing_complete;
}

/* Structure to hold credentials callback state */
struct aws_credentials_callback_state {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_var;
    struct aws_credentials *credentials;
    int error_code;
    bool is_complete;
};

/**
 * Initialize a credentials callback state.
 *
 * @param[out] state The state to initialize
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
static int s_aws_credentials_callback_state_init(struct aws_credentials_callback_state *state) {
    AWS_ZERO_STRUCT(*state);

    if (aws_mutex_init(&state->mutex)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&state->condition_var)) {
        aws_mutex_clean_up(&state->mutex);
        return AWS_OP_ERR;
    }

    state->credentials = NULL;
    state->error_code = 0;
    state->is_complete = false;

    return AWS_OP_SUCCESS;
}

/**
 * Clean up resources associated with a credentials callback state.
 *
 * @param[in] state The state to clean up
 */
static void s_aws_credentials_callback_state_clean_up(struct aws_credentials_callback_state *state) {
    if (!state) {
        return;
    }

    if (state->credentials) {
        aws_credentials_release(state->credentials);
    }

    aws_condition_variable_clean_up(&state->condition_var);
    aws_mutex_clean_up(&state->mutex);
    
    AWS_ZERO_STRUCT(*state);
}

/* Callback for when credentials are retrieved */
static void s_on_get_credentials_complete(struct aws_credentials *credentials, int error_code, void *userdata) {
    struct aws_credentials_callback_state *state = (struct aws_credentials_callback_state *)userdata;
    aws_mutex_lock(&state->mutex);

    /* Store the result in the userdata */
    state->credentials = credentials;
    if (credentials) {
        aws_credentials_acquire(credentials);
    }
    state->error_code = error_code;
    state->is_complete = true;

    aws_condition_variable_notify_one(&state->condition_var);
    aws_mutex_unlock(&state->mutex);
}

/* Helper function for condition variable predicate */
static bool s_is_credentials_complete(void *userdata) {
    struct aws_credentials_callback_state *state = (struct aws_credentials_callback_state *)userdata;
    return state->is_complete;
}

/**
 * Extract the AWS region from a DSQL hostname.
 * Expected format: '<cluster-id>.dsql.<region>.on.aws'
 * Where cluster-id is always 26 characters.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in] hostname The hostname to extract the region from
 * @param[out] region_str Pointer to receive the newly allocated region string or NULL if format invalid
 *
 * @return AWS_OP_SUCCESS if the region was extracted successfully, AWS_OP_ERR otherwise
 */
static int s_extract_region_from_hostname(
    struct aws_allocator *allocator,
    const char *hostname,
    struct aws_string **region_str) {

    *region_str = NULL;

    if (!hostname) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    size_t hostname_len = strlen(hostname);

    /* Check if hostname is long enough to contain all required parts */
    /* Minimum length: 26 (cluster-id) + 6 (.dsql.) + 1 (min region length) + 7 (.on.aws) = 40 */
    if (hostname_len < 40) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT); /* Not enough characters for the expected format */
    }

    /* Ensure hostname has the right prefix: exactly 26 chars followed by ".dsql." */
    const char *dsql_suffix_pos = strstr(hostname, DSQL_HOSTNAME_SUFFIX);
    if (!dsql_suffix_pos || (dsql_suffix_pos - hostname) != CLUSTER_ID_LENGTH) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT); /* Cluster ID not exactly 26 chars or .dsql. not found */
    }

    /* Ensure hostname ends with ".on.aws" */
    const char *on_aws_suffix = hostname + hostname_len - strlen(DSQL_HOSTNAME_END);
    if (strcmp(on_aws_suffix, DSQL_HOSTNAME_END) != 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT); /* Doesn't end with .on.aws */
    }

    /* Extract the region between ".dsql." and ".on.aws" */
    const char *region_start = dsql_suffix_pos + strlen(DSQL_HOSTNAME_SUFFIX);
    const char *region_end = on_aws_suffix;

    size_t region_len = region_end - region_start;
    if (region_len <= 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT); /* No region found */
    }

    /* Allocate memory for the region string */
    char *region_buffer = aws_mem_calloc(allocator, 1, region_len + 1); /* +1 for null terminator */
    if (!region_buffer) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    /* Copy the region substring */
    memcpy(region_buffer, region_start, region_len);

    /* Create the aws_string from our buffer */
    *region_str = aws_string_new_from_c_str(allocator, region_buffer);

    /* Free the temporary buffer */
    aws_mem_release(allocator, region_buffer);

    if (!*region_str) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    return AWS_OP_SUCCESS;
}

/* Helper function to load credentials from a credentials provider */
static int s_load_credentials(
    struct aws_credentials_provider *credentials_provider,
    struct aws_credentials **out_credentials) {

    struct aws_credentials_callback_state creds_state;
    if (s_aws_credentials_callback_state_init(&creds_state) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    if (aws_credentials_provider_get_credentials(credentials_provider, s_on_get_credentials_complete, &creds_state)) {
        s_aws_credentials_callback_state_clean_up(&creds_state);
        return AWS_OP_ERR;
    }

    /* Wait for credentials to be retrieved */
    aws_mutex_lock(&creds_state.mutex);
    if (!creds_state.is_complete) {
        aws_condition_variable_wait_pred(
            &creds_state.condition_var, &creds_state.mutex, s_is_credentials_complete, &creds_state);
    }
    aws_mutex_unlock(&creds_state.mutex);

    /* Check if credentials were successfully retrieved */
    if (creds_state.error_code != AWS_ERROR_SUCCESS || !creds_state.credentials) {
        int error_code = creds_state.error_code ? creds_state.error_code : AWS_ERROR_INVALID_STATE;
        s_aws_credentials_callback_state_clean_up(&creds_state);
        return aws_raise_error(error_code);
    }

    *out_credentials = creds_state.credentials;
    creds_state.credentials = NULL; /* Transfer ownership to out_credentials */

    /* Clean up resources, but don't release the credentials as they're now owned by the caller */
    s_aws_credentials_callback_state_clean_up(&creds_state);

    return AWS_OP_SUCCESS;
}

/**
 * Helper to validate token configuration.
 * Initializes token if needed and validates config parameters.
 */
static int s_validate_token_config(const struct aws_dsql_auth_config *config) {
    if (!config->hostname) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Fail fast if credentials provider is not set */
    if (!config->credentials_provider) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Fail fast if region is not set */
    if (!config->region) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

/**
 * Helper to get the current time from the system or configuration.
 */
static int s_get_current_time(const struct aws_dsql_auth_config *config, uint64_t *out_time_ms) {
    uint64_t current_time_ns = 0;

    if (config->system_clock_fn) {
        if (config->system_clock_fn(&current_time_ns)) {
            return AWS_OP_ERR;
        }
    } else {
        if (aws_sys_clock_get_ticks(&current_time_ns)) {
            return AWS_OP_ERR;
        }
    }

    /* Convert from nanoseconds to milliseconds by dividing by 1,000,000 */
    *out_time_ms = current_time_ns / 1000000;
    return AWS_OP_SUCCESS;
}

/* Type definitions to avoid similar parameter types */
typedef const char *action_name_t;
typedef const char *hostname_t;

/**
 * Helper to create and configure an HTTP request for signing.
 *
 * @param allocator The allocator to use
 * @param api_action The action to include in the URL query parameter
 * @param host_name The hostname to set in the Host header
 * @param out_request Output parameter to receive the created HTTP request
 */
static int s_create_http_request(
    struct aws_allocator *allocator,
    action_name_t api_action, /* Using type definition to avoid similar parameter types */
    hostname_t host_name,     /* Using type definition to avoid similar parameter types */
    struct aws_http_message **out_request) {

    /* Create an HTTP request for signing */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    if (!request) {
        return AWS_OP_ERR;
    }

    /* Set the request method to GET */
    if (aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET"))) {
        aws_http_message_release(request);
        return AWS_OP_ERR;
    }

    /* Set the request path to the URL path and query string */
    char path_buffer[1024];
    snprintf(path_buffer, sizeof(path_buffer), "/?Action=%s", api_action);
    if (aws_http_message_set_request_path(request, aws_byte_cursor_from_c_str(path_buffer))) {
        aws_http_message_release(request);
        return AWS_OP_ERR;
    }

    /* Add Host header which is required for signing */
    struct aws_http_header host_header = {
        .name = aws_byte_cursor_from_c_str("Host"), .value = aws_byte_cursor_from_c_str(host_name)};

    if (aws_http_message_add_header(request, host_header)) {
        aws_http_message_release(request);
        return AWS_OP_ERR;
    }

    *out_request = request;
    return AWS_OP_SUCCESS;
}

/**
 * Initialize a signing userdata context.
 *
 * @param[in] allocator The allocator to use
 * @param[out] context The context to initialize
 * @param[in] request The HTTP request to associate with this context
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
static int s_aws_signing_userdata_init(
    struct aws_allocator *allocator,
    struct aws_signing_userdata *context,
    struct aws_http_message *request) {
    
    AWS_ZERO_STRUCT(*context);

    if (aws_mutex_init(&context->mutex)) {
        return AWS_OP_ERR;
    }

    if (aws_condition_variable_init(&context->condition_var)) {
        aws_mutex_clean_up(&context->mutex);
        return AWS_OP_ERR;
    }

    context->allocator = allocator;
    context->request = request;
    context->signing_result_code = 0;
    context->is_signing_complete = false;

    return AWS_OP_SUCCESS;
}

/**
 * Clean up resources associated with a signing userdata context.
 *
 * @param[in] context The context to clean up
 */
static void s_aws_signing_userdata_clean_up(struct aws_signing_userdata *context) {
    if (!context) {
        return;
    }

    aws_condition_variable_clean_up(&context->condition_var);
    aws_mutex_clean_up(&context->mutex);
    
    /* Note: We don't release the request here as that's managed by the caller */
    
    AWS_ZERO_STRUCT(*context);
}

/**
 * Helper to create a token string from a signed request.
 */
static int s_create_token_string(
    struct aws_allocator *allocator,
    const char *hostname,
    struct aws_http_message *request,
    struct aws_string **out_token_string) {

    /* Get the signed request path */
    struct aws_byte_cursor path_cursor;
    if (aws_http_message_get_request_path(request, &path_cursor) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    /* Create the complete token string: hostname + signed path */
    size_t hostname_len = strlen(hostname);
    size_t path_len = path_cursor.len;
    size_t total_len = hostname_len + path_len;

    /* Create a buffer for the token string */
    char *token_buffer = aws_mem_calloc(allocator, 1, total_len + 1); /* +1 for null terminator */
    if (!token_buffer) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    /* Copy hostname and path to form the complete token */
    memcpy(token_buffer, hostname, hostname_len);
    memcpy(token_buffer + hostname_len, path_cursor.ptr, path_len);

    /* Create the aws_string from our buffer */
    *out_token_string = aws_string_new_from_c_str(allocator, token_buffer);

    /* Free the temporary buffer as it was copied into the aws_string */
    aws_mem_release(allocator, token_buffer);

    if (!*out_token_string) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    return AWS_OP_SUCCESS;
}

/**
 * Helper to create a signable from the request and sign it with AWS SigV4.
 *
 * @param allocator The allocator to use
 * @param request The HTTP request to sign
 * @param credentials The credentials to use for signing
 * @param region The AWS region for signing
 * @param expiration_in_seconds The expiration time for the signed request
 * @param date_time The current date time for signing
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise
 */
static int s_sign_request(
    struct aws_allocator *allocator,
    struct aws_http_message *request,
    struct aws_credentials *credentials,
    struct aws_string *region,
    uint64_t expiration_in_seconds,
    struct aws_date_time date_time) {

    /* Create a signable from the request */
    struct aws_signable *signable = aws_signable_new_http_request(allocator, request);
    if (!signable) {
        return AWS_OP_ERR;
    }

    /* Set up the signing configuration */
    struct aws_signing_config_aws signing_config;
    AWS_ZERO_STRUCT(signing_config);
    signing_config.config_type = AWS_SIGNING_CONFIG_AWS;
    signing_config.algorithm = AWS_SIGNING_ALGORITHM_V4;
    signing_config.signature_type = AWS_ST_HTTP_REQUEST_QUERY_PARAMS;
    /* Ensure the region is correctly converted to a byte cursor */
    signing_config.region = aws_byte_cursor_from_string(region);
    signing_config.service = aws_byte_cursor_from_c_str(SERVICE_NAME);
    signing_config.flags.use_double_uri_encode = false;
    signing_config.flags.should_normalize_uri_path = true;
    signing_config.credentials = credentials;
    signing_config.expiration_in_seconds = expiration_in_seconds;
    signing_config.date = date_time;

    /* Set up the signing state */
    struct aws_signing_userdata context;
    int result = s_aws_signing_userdata_init(allocator, &context, request);
    if (result != AWS_OP_SUCCESS) {
        aws_signable_destroy(signable);
        return result;
    }

    /* Sign the request */
    if (aws_sign_request_aws(
            allocator, signable, (struct aws_signing_config_base *)&signing_config, s_on_signing_complete, &context)) {
        s_aws_signing_userdata_clean_up(&context);
        aws_signable_destroy(signable);
        return AWS_OP_ERR;
    }

    /* Wait for signing to complete */
    aws_mutex_lock(&context.mutex);
    if (!context.is_signing_complete) {
        aws_condition_variable_wait_pred(&context.condition_var, &context.mutex, s_is_signing_complete, &context);
    }
    aws_mutex_unlock(&context.mutex);

    /* Check if signing was successful */
    if (context.signing_result_code != AWS_ERROR_SUCCESS) {
        s_aws_signing_userdata_clean_up(&context);
        aws_signable_destroy(signable);
        return aws_raise_error(context.signing_result_code);
    }

    /* Clean up signing resources */
    s_aws_signing_userdata_clean_up(&context);
    aws_signable_destroy(signable);

    return AWS_OP_SUCCESS;
}

int aws_dsql_auth_token_generate(
    const struct aws_dsql_auth_config *config,
    bool is_admin,
    struct aws_allocator *allocator,
    struct aws_dsql_auth_token *token) {

    int result;

    /* Validate input parameters and initialize token if needed */
    result = s_validate_token_config(config);
    if (result != AWS_OP_SUCCESS) {
        return result;
    }

    const char *action = is_admin ? ACTION_DB_CONNECT_ADMIN : ACTION_DB_CONNECT;

    /* Get the current time */
    uint64_t current_time_ms;
    if (s_get_current_time(config, &current_time_ms) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    /* Initialize the date with the current time */
    struct aws_date_time date_time;
    aws_date_time_init_epoch_millis(&date_time, current_time_ms);

    /* Get credentials from the provider */
    struct aws_credentials *credentials = NULL;
    result = s_load_credentials(config->credentials_provider, &credentials);
    if (result != AWS_OP_SUCCESS) {
        return result;
    }

    /* Create an HTTP request for signing */
    struct aws_http_message *request = NULL;
    result = s_create_http_request(allocator, action, config->hostname, &request);
    if (result != AWS_OP_SUCCESS) {
        aws_credentials_release(credentials);
        return result;
    }

    /* Create a signable and sign the request */
    result = s_sign_request(allocator, request, credentials, config->region, config->expires_in, date_time);

    if (result != AWS_OP_SUCCESS) {
        aws_http_message_release(request);
        aws_credentials_release(credentials);
        return result;
    }

    /* Create the token string */
    struct aws_string *token_string = NULL;
    result = s_create_token_string(allocator, config->hostname, request, &token_string);

    /* Clean up resources we no longer need */
    aws_http_message_release(request);
    aws_credentials_release(credentials);

    if (result != AWS_OP_SUCCESS) {
        return result;
    }

    /* Clean up existing token if there is one */
    if (token->token != NULL) {
        aws_string_destroy(token->token);
    }

    token->token = token_string;

    return AWS_OP_SUCCESS;
}

void aws_dsql_auth_token_clean_up(struct aws_dsql_auth_token *token) {
    if (!token) {
        return;
    }

    if (token->token) {
        /* Destroy the aws_string which frees both the structure and its string data */
        aws_string_destroy(token->token);
        token->token = NULL;
    }

    AWS_ZERO_STRUCT(*token);
}

void aws_dsql_auth_module_clean_up(struct aws_allocator *allocator) {
    /* Nothing to clean up */
    (void)allocator;
}

const char *aws_dsql_auth_token_get_str(const struct aws_dsql_auth_token *token) {
    if (!token || !token->token) {
        return NULL;
    }

    return aws_string_c_str(token->token);
}

/**
 * Try to infer the region from the hostname and set it in the config if successful.
 * The hostname must follow the format '<cluster-id>.dsql.<region>.on.aws', where cluster-id is always 26 characters.
 * If the hostname does not match this format, the region will not be set.
 *
 * @param[in] allocator The allocator to use for memory allocation
 * @param[in] config The config
 * @param[out] out_region The inferred region
 *
 * @return AWS_OP_SUCCESS if the region was successfully inferred and set, AWS_OP_ERR otherwise
 */
int aws_dsql_auth_config_infer_region(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    struct aws_string **out_region) {

    if (!config || !config->hostname || !out_region) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Attempt to extract the region from the hostname */
    return s_extract_region_from_hostname(allocator, config->hostname, out_region);
}
