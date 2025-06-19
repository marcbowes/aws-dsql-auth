cmake_minimum_required(VERSION 3.10)
project(aws-dsql-auth C)

# Set the path to the AWS common cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_INSTALL_PREFIX}/lib/aws-c-common/cmake")

# Disable tests in dependencies
set(BUILD_TESTING OFF CACHE BOOL "Disable tests in dependencies" FORCE)

# Force static library builds for AWS dependencies
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries" FORCE)
set(SEARCH_LIBCRYPTO OFF)

# Re-enable tests for our project
set(BUILD_TESTING ON CACHE BOOL "Enable tests for our project" FORCE)

# Find the installed AWS libraries
find_package(aws-c-common REQUIRED)
find_package(aws-c-cal REQUIRED)
find_package(aws-c-io REQUIRED)
find_package(aws-c-compression REQUIRED)
find_package(aws-c-http REQUIRED)
find_package(aws-c-sdkutils REQUIRED)
find_package(aws-c-auth REQUIRED)
find_package(s2n REQUIRED)

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
target_link_libraries(${PROJECT_NAME} PUBLIC
    AWS::s2n
    AWS::aws-c-auth
    AWS::aws-c-common
    AWS::aws-c-cal
    AWS::aws-c-io
    AWS::aws-c-http
    AWS::aws-c-sdkutils
)

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
    AWS::s2n
    AWS::aws-c-auth
    AWS::aws-c-common
    AWS::aws-c-cal
    AWS::aws-c-io
    AWS::aws-c-http
    AWS::aws-c-sdkutils
)

# Install the dsql-token executable
install(
    TARGETS dsql-token
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
