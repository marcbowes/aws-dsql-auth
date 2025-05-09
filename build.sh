#!/bin/bash
set -e

# Clean and recreate build directory
mkdir -p build
cd build

# Configure and build
cmake -DIN_SOURCE_BUILD=ON ..
make -j4

echo "Build completed successfully!"

# Run tests with CTest
echo "Running tests with CTest..."
# Only run tests for aws-dsql-auth
ctest --output-on-failure

echo "All tests passed successfully!"
