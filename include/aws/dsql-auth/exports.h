/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AWS_DSQL_AUTH_EXPORTS_H
#define AWS_DSQL_AUTH_EXPORTS_H

#include <aws/common/exports.h>

/**
 * AWS_DSQL_AUTH_API is used for public API declarations
 */
#if defined(AWS_DSQL_AUTH_USE_IMPORT_EXPORT) && defined(_WIN32)
#    ifdef AWS_DSQL_AUTH_EXPORTS
#        define AWS_DSQL_AUTH_API AWS_COMMON_EXPORT
#    else
#        define AWS_DSQL_AUTH_API AWS_COMMON_IMPORT
#    endif /* AWS_DSQL_AUTH_EXPORTS */
#else
#    define AWS_DSQL_AUTH_API
#endif /* defined(AWS_DSQL_AUTH_USE_IMPORT_EXPORT) && defined(_WIN32) */

#endif /* AWS_DSQL_AUTH_EXPORTS_H */
