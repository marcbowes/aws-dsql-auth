# Aurora DSQL Authentication Token Generator

This library provides functionality to generate authentication tokens for Aurora DSQL databases. It uses AWS Signature Version 4 to create signed URLs that can be used as passwords when connecting to Aurora DSQL databases.

## Features

- Generate regular and admin authentication tokens for Aurora DSQL
- Support for custom AWS credentials
- Configurable token expiration time
- Region-specific token generation

## Building

### Prerequisites

- CMake 3.10 or higher
- C compiler with C99 support
- Git (for cloning submodules)

### Build Steps

1. Clone the repository with submodules:
   ```bash
   git clone --recursive https://github.com/marcbowes/aws-dsql-auth.git
   cd aws-dsql-auth
   ```

2. If you didn't clone with `--recursive`, initialize the submodules:
   ```bash
   git submodule update --init --recursive
   ```

3. Build the library:
   ```bash
   ./build.sh
   ```

## Usage

```c
#include <aws/dsql-auth/auth_token.h>

int main() {
    struct aws_allocator *allocator = aws_default_allocator();
    
    // Initialize AWS libraries
    aws_common_library_init(allocator);
    aws_auth_library_init(allocator);
    
    // Set up the configuration
    struct aws_dsql_auth_config config;
    aws_dsql_auth_config_init(allocator, &config);
    aws_dsql_auth_config_set_hostname(allocator, &config, "mydb.dsql.us-east-1.on.aws");
    aws_dsql_auth_config_set_region(allocator, &config, "us-east-1");
    aws_dsql_auth_config_set_expires_in(&config, 900); // 15 minutes
    
    // Generate the token
    struct aws_dsql_auth_token token;
    if (aws_dsql_auth_token_generate(allocator, &config, false, &token) == AWS_OP_SUCCESS) {
        printf("Generated token: %s\n", aws_dsql_auth_token_get_str(&token));
        aws_dsql_auth_token_clean_up(&token);
    }
    
    // Clean up
    aws_dsql_auth_config_clean_up(&config);
    aws_auth_library_clean_up();
    aws_common_library_clean_up();
    
    return 0;
}
```

## License

This library is licensed under the Apache License, Version 2.0.
