cmake_minimum_required(VERSION 3.10)
project(aws-dsql-auth C)

# Set the path to the AWS common cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/aws-sdk/aws-c-common/cmake")

# Build AWS C libraries in the correct order
add_subdirectory(aws-sdk/aws-c-common)
add_subdirectory(aws-sdk/aws-c-cal)
add_subdirectory(aws-sdk/aws-c-io)
add_subdirectory(aws-sdk/aws-c-compression)
add_subdirectory(aws-sdk/aws-c-http)
add_subdirectory(aws-sdk/aws-c-sdkutils)
add_subdirectory(aws-sdk/aws-c-auth)

# Include AWS common cmake modules
include(AwsCFlags)
include(AwsSharedLibSetup)
include(AwsSanitizers)

# Set up the library
file(GLOB AWS_DSQL_AUTH_HEADERS
    "include/aws/dsql-auth/*.h"
)

file(GLOB AWS_DSQL_AUTH_SRC
    "source/*.c"
)

add_library(${PROJECT_NAME} ${AWS_DSQL_AUTH_SRC})
aws_set_common_properties(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link against AWS libraries
target_link_libraries(${PROJECT_NAME} PUBLIC
    aws-c-auth
    aws-c-common
    aws-c-cal
    aws-c-io
    aws-c-http
    aws-c-sdkutils
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

# Add tests
# add_subdirectory(tests)
