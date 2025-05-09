/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <aws/auth/auth.h>
#include <aws/auth/credentials.h>
#include <aws/common/allocator.h>
#include <aws/common/command_line_parser.h>
#include <aws/common/common.h>
#include <aws/common/error.h>
#include <aws/common/string.h>
#include <aws/dsql-auth/auth_token.h>
#include <aws/io/io.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/sdkutils/sdkutils.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct dsql_token_ctx {
    struct aws_allocator *allocator;
    const struct aws_string *hostname;
    const struct aws_string *region;
    uint64_t expires_in;
    bool admin;
};

static void s_usage(int exit_code) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  dsql-token --hostname HOSTNAME [--region REGION] [--expires-in SECONDS] [--admin]\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --hostname HOSTNAME        Required. The hostname of the Aurora DSQL database\n");
    fprintf(stderr, "  --region REGION            Optional. The AWS region. If not provided, will be auto-detected\n");
    fprintf(stderr, "  --expires-in SECONDS       Optional. The expiration time in seconds. Default is 900 (15 min)\n");
    fprintf(stderr, "  --admin                    Optional. Generate an admin token. Default is false\n");
    fprintf(stderr, "\n");
    exit(exit_code);
}

/* Define constants for command line arguments if they're not already defined */
#ifndef required_argument
#    define required_argument 1
#endif

#ifndef no_argument
#    define no_argument 0
#endif

static struct aws_cli_option s_long_options[] = {
    {"hostname", required_argument, NULL, 'h'},
    {"region", required_argument, NULL, 'r'},
    {"expires-in", required_argument, NULL, 'e'},
    {"admin", no_argument, NULL, 'a'},
    {"help", no_argument, NULL, '?'},
    {NULL, 0, NULL, 0},
};

static bool s_parse_args(int argc, char **argv, struct dsql_token_ctx *ctx) {
    ctx->admin = false;
    ctx->expires_in = 0; // Use default value

    int opt;
    int option_index = 0;

    while ((opt = aws_cli_getopt_long(argc, argv, "h:r:e:a?", s_long_options, &option_index)) != -1) {
        switch (opt) {
            case 0:
                /* getopt_long() set a variable, just keep going */
                break;

            case 'h':
                ctx->hostname = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                if (!ctx->hostname) {
                    return false;
                }
                break;

            case 'r':
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                if (!ctx->region) {
                    return false;
                }
                break;

            case 'e': {
                long long expires = strtoll(aws_cli_optarg, NULL, 10);
                if (expires < 0) {
                    fprintf(stderr, "Error: expires-in must be a positive number\n");
                    return false;
                }
                ctx->expires_in = (uint64_t)expires;
                break;
            }

            case 'a':
                ctx->admin = true;
                break;

            case '?':
                s_usage(0);
                break;

            default:
                s_usage(1);
                break;
        }
    }

    if (!ctx->hostname) {
        fprintf(stderr, "Error: --hostname is required\n");
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    struct aws_allocator *allocator = aws_default_allocator();
    struct dsql_token_ctx ctx = {.allocator = allocator};
    int result = AWS_OP_ERR; /* Initialize to error by default */
    struct aws_credentials_provider *credentials_provider = NULL;

    /* Initialize required AWS libraries */
    aws_common_library_init(allocator);
    aws_io_library_init(allocator);
    aws_auth_library_init(allocator);
    aws_sdkutils_library_init(allocator);

    /* Parse command line arguments */
    if (!s_parse_args(argc, argv, &ctx)) {
        s_usage(1);
    }

    /* Initialize DSQL auth config */
    struct aws_dsql_auth_config auth_config;
    aws_dsql_auth_config_init(allocator, &auth_config);

    /* Set hostname */
    aws_dsql_auth_config_set_hostname(allocator, &auth_config, aws_string_c_str(ctx.hostname));

    /* Set region if provided, otherwise try to infer from hostname */
    if (ctx.region) {
        aws_dsql_auth_config_set_region(allocator, &auth_config, aws_string_c_str(ctx.region));
    } else {
        /* Try to infer region from hostname */
        if (aws_dsql_auth_config_infer_region(allocator, &auth_config) != AWS_OP_SUCCESS) {
            fprintf(
                stderr,
                "Error: Failed to infer AWS region from hostname. Please provide region explicitly with --region.\n");
            result = AWS_OP_ERR;
            goto cleanup;
        }
    }

    /* Set expires_in if provided, otherwise default will be used */
    if (ctx.expires_in > 0) {
        aws_dsql_auth_config_set_expires_in(&auth_config, ctx.expires_in);
    }

    /* Create default credentials provider */
    struct aws_credentials_provider_chain_default_options credentials_provider_options = {0};

    credentials_provider = aws_credentials_provider_new_chain_default(allocator, &credentials_provider_options);

    if (!credentials_provider) {
        fprintf(stderr, "Error: Failed to create credentials provider\n");
        goto cleanup;
    }

    /* Set credentials provider */
    aws_dsql_auth_config_set_credentials_provider(&auth_config, credentials_provider);

    /* Generate the auth token */
    struct aws_dsql_auth_token auth_token;
    aws_dsql_auth_token_init(allocator, &auth_token);

    /* Generate the token */
    result = aws_dsql_auth_token_generate(allocator, &auth_config, ctx.admin, &auth_token);

    if (result != AWS_OP_SUCCESS) {
        fprintf(stderr, "Error: Failed to generate auth token: %s\n", aws_error_str(aws_last_error()));
        goto cleanup_token;
    }

    /* Print the token */
    printf("%s\n", aws_dsql_auth_token_get_str(&auth_token));

    /* Clean up */
cleanup_token:
    aws_dsql_auth_token_clean_up(&auth_token);

cleanup:
    if (credentials_provider) {
        aws_credentials_provider_release(credentials_provider);
    }
    aws_dsql_auth_config_clean_up(&auth_config);

    if (ctx.hostname) {
        aws_string_destroy((void *)ctx.hostname);
    }
    if (ctx.region) {
        aws_string_destroy((void *)ctx.region);
    }

    aws_sdkutils_library_clean_up();
    aws_auth_library_clean_up();
    aws_io_library_clean_up();
    aws_common_library_clean_up();

    return (result == AWS_OP_SUCCESS) ? 0 : 1;
}
