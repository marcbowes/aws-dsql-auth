/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <aws/dsql-auth/auth_token.h>
#include <aws/auth/credentials.h>
#include <aws/auth/signable.h>
#include <aws/auth/signing.h>
#include <aws/auth/signing_config.h>
#include <aws/common/string.h>
#include <aws/common/mutex.h>
#include <aws/common/condition_variable.h>
#include <aws/http/request_response.h>
#include <aws/io/uri.h>

/* Forward declarations for functions not in headers */
AWS_STATIC_IMPL struct aws_string *aws_string_new_format(struct aws_allocator *allocator, const char *fmt, ...);
AWS_STATIC_IMPL int aws_apply_signing_result_to_http_request(struct aws_http_message *request, struct aws_allocator *allocator, const struct aws_signing_result *result);
AWS_STATIC_IMPL void aws_signing_result_destroy(struct aws_signing_result *result);

#define ACTION_DB_CONNECT "DbConnect"
#define ACTION_DB_CONNECT_ADMIN "DbConnectAdmin"
#define SERVICE_NAME "dsql"
#define DEFAULT_EXPIRES_IN 900 /* 15 minutes */

int aws_dsql_auth_config_init(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config) {
    
    AWS_ZERO_STRUCT(*config);
    config->expires_in = DEFAULT_EXPIRES_IN;
    
    return AWS_OP_SUCCESS;
}

void aws_dsql_auth_config_clean_up(
    struct aws_dsql_auth_config *config) {
    
    if (config->credentials) {
        aws_credentials_release(config->credentials);
    }
    
    AWS_ZERO_STRUCT(*config);
}

int aws_dsql_auth_config_set_hostname(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    const char *hostname) {
    
    config->hostname = hostname;
    return AWS_OP_SUCCESS;
}

int aws_dsql_auth_config_set_region(
    struct aws_allocator *allocator,
    struct aws_dsql_auth_config *config,
    const char *region) {
    
    config->region = region;
    return AWS_OP_SUCCESS;
}

void aws_dsql_auth_config_set_expires_in(
    struct aws_dsql_auth_config *config,
    uint64_t expires_in) {
    
    config->expires_in = expires_in > 0 ? expires_in : DEFAULT_EXPIRES_IN;
}

void aws_dsql_auth_config_set_credentials(
    struct aws_dsql_auth_config *config,
    struct aws_credentials *credentials) {
    
    if (config->credentials) {
        aws_credentials_release(config->credentials);
    }
    
    config->credentials = credentials;
    if (credentials) {
        aws_credentials_acquire(credentials);
    }
}

/* Structure to hold signing state */
struct aws_signing_state {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_var;
    struct aws_signing_result *signing_result;
    int signing_result_code;
    bool is_signing_complete;
};

/* Callback for when signing is complete */
static void on_signing_complete(struct aws_signing_result *result, int error_code, void *userdata) {
    struct aws_signing_state *state = (struct aws_signing_state *)userdata;
    aws_mutex_lock(&state->mutex);
    
    /* Store the result in the userdata */
    state->signing_result = result;
    state->signing_result_code = error_code;
    state->is_signing_complete = true;
    
    aws_condition_variable_notify_one(&state->condition_var);
    aws_mutex_unlock(&state->mutex);
}

/* Helper function for condition variable predicate */
bool aws_is_signing_complete(void *userdata) {
    struct aws_signing_state *state = (struct aws_signing_state *)userdata;
    return state->is_signing_complete;
}

int aws_dsql_auth_token_generate(
    struct aws_allocator *allocator,
    const struct aws_dsql_auth_config *config,
    bool is_admin,
    struct aws_dsql_auth_token *token) {
    
    AWS_ZERO_STRUCT(*token);
    token->allocator = allocator;
    
    if (!config->hostname) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Create the URL for signing */
    const char *action = is_admin ? ACTION_DB_CONNECT_ADMIN : ACTION_DB_CONNECT;
    struct aws_string *url = aws_string_new_format(
        allocator,
        "https://%s/?Action=%s",
        config->hostname,
        action);
    
    if (!url) {
        return AWS_OP_ERR;
    }
    
    /* Create a signable HTTP request */
    struct aws_http_message *request = aws_http_message_new_request(allocator);
    if (!request) {
        aws_string_destroy(url);
        return AWS_OP_ERR;
    }
    
    if (aws_http_message_set_request_method(request, aws_byte_cursor_from_c_str("GET"))) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        return AWS_OP_ERR;
    }
    
    struct aws_byte_cursor url_cursor = aws_byte_cursor_from_string(url);
    if (aws_http_message_set_request_path(request, url_cursor)) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        return AWS_OP_ERR;
    }
    
    /* Create a signable from the HTTP request */
    struct aws_signable *signable = aws_signable_new_http_request(allocator, request);
    if (!signable) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        return AWS_OP_ERR;
    }
    
    /* Set up signing config */
    struct aws_signing_config_aws signing_config;
    AWS_ZERO_STRUCT(signing_config);
    
    signing_config.config_type = AWS_SIGNING_CONFIG_AWS;
    signing_config.algorithm = AWS_SIGNING_ALGORITHM_V4;
    signing_config.signature_type = AWS_ST_HTTP_REQUEST_QUERY_PARAMS;
    signing_config.region = aws_byte_cursor_from_c_str(config->region ? config->region : "us-east-1");
    signing_config.service = aws_byte_cursor_from_c_str(SERVICE_NAME);
    signing_config.flags.use_double_uri_encode = false;
    signing_config.flags.should_normalize_uri_path = true;
    signing_config.expiration_in_seconds = config->expires_in;
    
    /* Use provided credentials or default provider */
    signing_config.credentials = config->credentials;
    
    /* Sign the request */
    struct aws_signing_result *signing_result = NULL;
    
    /* Use the async signing API with a synchronous wait */
    struct aws_signing_state state;
    AWS_ZERO_STRUCT(state);
    
    if (aws_mutex_init(&state.mutex)) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        return AWS_OP_ERR;
    }
    
    if (aws_condition_variable_init(&state.condition_var)) {
        aws_mutex_clean_up(&state.mutex);
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        return AWS_OP_ERR;
    }
    
    /* Start the signing process */
    if (aws_sign_request_aws(
            allocator, 
            signable, 
            (struct aws_signing_config_base *)&signing_config, 
            on_signing_complete, 
            &state)) {
        aws_condition_variable_clean_up(&state.condition_var);
        aws_mutex_clean_up(&state.mutex);
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        return AWS_OP_ERR;
    }
    
    /* Wait for signing to complete */
    aws_mutex_lock(&state.mutex);
    while (!state.is_signing_complete) {
        aws_condition_variable_wait_pred(
            &state.condition_var, 
            &state.mutex, 
            aws_is_signing_complete, 
            &state);
    }
    aws_mutex_unlock(&state.mutex);
    
    aws_condition_variable_clean_up(&state.condition_var);
    aws_mutex_clean_up(&state.mutex);
    
    /* Get the signing result from the state */
    signing_result = state.signing_result;
    int signing_result_code = state.signing_result_code;
    
    /* Check if signing was successful */
    if (signing_result_code || !signing_result) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        return AWS_OP_ERR;
    }
    
    /* Apply the signing result to the request */
    if (aws_apply_signing_result_to_http_request(request, allocator, signing_result)) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        aws_signing_result_destroy(signing_result);
        return AWS_OP_ERR;
    }
    
    /* Extract the signed URL */
    struct aws_byte_cursor path_cursor;
    if (aws_http_message_get_request_path(request, &path_cursor)) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        aws_signing_result_destroy(signing_result);
        return AWS_OP_ERR;
    }
    
    /* Combine the host and query string to form the token */
    struct aws_string *token_str = aws_string_new_format(
        allocator,
        "%s%.*s",
        config->hostname,
        (int)path_cursor.len - 1, /* Remove the leading '/' */
        path_cursor.ptr + 1);
    
    if (!token_str) {
        aws_string_destroy(url);
        aws_http_message_release(request);
        aws_signable_destroy(signable);
        aws_signing_result_destroy(signing_result);
        return AWS_OP_ERR;
    }
    
    token->token = (char *)aws_string_c_str(token_str);
    
    /* Clean up */
    aws_string_destroy(url);
    aws_http_message_release(request);
    aws_signable_destroy(signable);
    aws_signing_result_destroy(signing_result);
    
    return AWS_OP_SUCCESS;
}

void aws_dsql_auth_token_clean_up(
    struct aws_dsql_auth_token *token) {
    
    if (token->token) {
        aws_mem_release(token->allocator, token->token);
    }
    
    AWS_ZERO_STRUCT(*token);
}

const char *aws_dsql_auth_token_get_str(
    const struct aws_dsql_auth_token *token) {
    
    return token->token;
}
