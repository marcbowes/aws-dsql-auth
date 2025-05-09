#!/bin/bash
set -e

# Check for arguments
if [ "$1" = "clean" ]; then
    echo "Cleaning build directory..."
    rm -rf build/*
    echo "Build directory cleaned."
    exit 0
elif [ "$1" = "tidy" ]; then
    echo "Running clang-format and clang-tidy on codebase (excluding aws-sdk/)..."
    
    # Check if clang-format and clang-tidy are available
    if ! command -v clang-format &> /dev/null; then
        echo "Error: clang-format not found. Please install clang-format."
        exit 1
    fi
    
    if ! command -v clang-tidy &> /dev/null; then
        echo "Error: clang-tidy not found. Please install clang-tidy."
        exit 1
    fi
    
    # Find all C/C++ source and header files excluding aws-sdk/ and build/
    FILES=$(find . -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" \) -not -path "./aws-sdk/*" -not -path "./build/*")
    
    # Run clang-format on found files
    echo "Running clang-format..."
    for FILE in $FILES; do
        echo "  Formatting $FILE"
        clang-format -i "$FILE"
    done
    
    # Check for compilation database
    if [ -f "build/compile_commands.json" ]; then
        echo "Found compilation database. Using it for clang-tidy..."
        
        # Run clang-tidy on found files using compilation database
        echo "Running clang-tidy..."
        for FILE in $FILES; do
            echo "  Checking $FILE"
            clang-tidy -p build "$FILE" --checks="-misc-header-include-cycle,-bugprone-easily-swappable-parameters"
        done
    else
        # Create build directory and generate compilation database
        echo "No compilation database found. Generating one..."
        mkdir -p build
        (cd build && cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..)
        
        if [ -f "build/compile_commands.json" ]; then
            # Run clang-tidy with compilation database
            echo "Running clang-tidy with generated compilation database..."
            for FILE in $FILES; do
                echo "  Checking $FILE"
                clang-tidy -p build "$FILE" --checks="-misc-header-include-cycle,-bugprone-easily-swappable-parameters"
            done
        else
            # Fallback without compilation database
            echo "Warning: Could not generate compilation database. Running clang-tidy with basic options..."
            for FILE in $FILES; do
                echo "  Checking $FILE"
                clang-tidy "$FILE" --checks="-misc-header-include-cycle,-bugprone-easily-swappable-parameters" -- -I./include
            done
        fi
    fi
    
    echo "Tidy operations completed."
    exit 0
fi

# Detect platform
PLATFORM="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
fi

# Create build directory if it doesn't exist
mkdir -p build

# Additional dependencies and setup based on platform
CMAKE_EXTRA_ARGS=""

if [ "$PLATFORM" = "linux" ]; then
    echo "Linux platform detected. Checking for AWS-LC..."
    
    # Check if AWS-LC exists
    if [ ! -d "aws-lc" ]; then
        echo "AWS-LC not found. Cloning from GitHub..."
        git clone https://github.com/awslabs/aws-lc.git
        
        echo "Building AWS-LC..."
        mkdir -p aws-lc/build
        (cd aws-lc/build && cmake -DCMAKE_INSTALL_PREFIX=$(pwd)/../../aws-lc-install -DBUILD_SHARED_LIBS=ON ..)
        (cd aws-lc/build && make -j4 install)
        
        echo "AWS-LC build completed."
    elif [ ! -d "aws-lc-install" ]; then
        echo "AWS-LC source exists but not installed. Building..."
        mkdir -p aws-lc/build
        (cd aws-lc/build && cmake -DCMAKE_INSTALL_PREFIX=$(pwd)/../../aws-lc-install -DBUILD_SHARED_LIBS=ON ..)
        (cd aws-lc/build && make -j4 install)
        
        echo "AWS-LC build completed."
    fi
    
    if [ -d "aws-lc-install" ]; then
        echo "Using locally built AWS-LC"
        CMAKE_EXTRA_ARGS="-DCMAKE_PREFIX_PATH=$(pwd)/aws-lc-install"
    fi
fi

echo "Configuring with CMake..."
cd build
cmake -DIN_SOURCE_BUILD=ON ${CMAKE_EXTRA_ARGS} ..

echo "Building..."
make -j4

echo "Build completed successfully!"

# Run tests with CTest
echo "Running tests with CTest..."
# Only run tests for aws-dsql-auth
ctest --output-on-failure

echo "All tests passed successfully!"
