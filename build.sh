#!/bin/bash
set -e

# Create build directory
mkdir -p build
cd build

# Configure and build
cmake -DIN_SOURCE_BUILD=ON ..
make -j4

echo "Build completed successfully!"
