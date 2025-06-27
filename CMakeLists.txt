cmake_minimum_required(VERSION 3.10)
project(aws-dsql-auth C)

# Option to control whether to use s2n and aws-lc
option(WITH_S2N_AWS_LC "Build with s2n-tls and aws-lc support" OFF)

if (NOT IN_SOURCE_BUILD)
    # this is required so we can use aws-c-common's CMake modules
    find_package(aws-c-common REQUIRED)
endif()

include(AwsCFlags)
include(AwsCheckHeaders)
include(AwsSharedLibSetup)
include(AwsSanitizers)
include(AwsFindPackage)
include(GNUInstallDirs)

# Find the installed AWS libraries
aws_use_package(aws-c-common)
aws_use_package(aws-c-cal)
aws_use_package(aws-c-io)
aws_use_package(aws-c-compression)
aws_use_package(aws-c-http)
aws_use_package(aws-c-sdkutils)
aws_use_package(aws-c-auth)

# Only find s2n if WITH_S2N_AWS_LC is enabled
if(WITH_S2N_AWS_LC)
    find_package(s2n REQUIRED)
endif()

# Include AWS common cmake modules
include(AwsCFlags)
include(AwsSharedLibSetup)
include(AwsSanitizers)

# Set up the library
file(GLOB AWS_DSQL_AUTH_HEADERS
    "include/aws/dsql-auth/*.h"
)

# Explicitly list source files instead of using GLOB to exclude dsql_token.c
set(AWS_DSQL_AUTH_SRC
    "source/auth_token.c"
)

add_library(${PROJECT_NAME} STATIC ${AWS_DSQL_AUTH_SRC})
aws_set_common_properties(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link against AWS libraries
set(AWS_DSQL_AUTH_LIBS
    AWS::aws-c-auth
    AWS::aws-c-common
    AWS::aws-c-cal
    AWS::aws-c-io
    AWS::aws-c-http
    AWS::aws-c-sdkutils
)

# Add s2n only if WITH_S2N_AWS_LC is enabled
if(WITH_S2N_AWS_LC)
    list(APPEND AWS_DSQL_AUTH_LIBS AWS::s2n)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC ${AWS_DSQL_AUTH_LIBS})

# Installation
install(
    TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY "include/aws"
    DESTINATION "include"
    FILES_MATCHING PATTERN "*.h"
)

# Export targets
install(
    EXPORT ${PROJECT_NAME}-targets
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}/cmake/"
    NAMESPACE AWS::
)

# Enable CTest
include(CTest)

# Add tests if testing is enabled
if (BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Create the dsql-token executable
add_executable(dsql-token source/dsql_token.c)

# Set compiler options for dsql-token
aws_set_common_properties(dsql-token)

# Link against the aws-dsql-auth library and other dependencies
target_link_libraries(dsql-token PRIVATE
    ${PROJECT_NAME}
    ${AWS_DSQL_AUTH_LIBS}
)

# Install the dsql-token executable
install(
    TARGETS dsql-token
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
