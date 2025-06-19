#!/bin/bash
set -e

# Automatically compute make parallelism based on available CPU cores
if command -v nproc &> /dev/null; then
    # Linux
    MAKE_JOBS=$(nproc)
elif command -v sysctl &> /dev/null; then
    # macOS
    MAKE_JOBS=$(sysctl -n hw.ncpu)
else
    # Fallback
    MAKE_JOBS=4
fi

echo "Using ${MAKE_JOBS} parallel jobs for make"

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

# Set the installation prefix
INSTALL_PREFIX=$(pwd)/build/install
mkdir -p ${INSTALL_PREFIX}

echo "Building dependencies..."

# Build aws-lc
echo "Building aws-lc..."
mkdir -p aws-lc/build
(cd aws-lc/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

# Build s2n-tls with aws-lc
echo "Building s2n-tls..."
mkdir -p s2n-tls/build
(cd s2n-tls/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

# Build AWS C libraries in the correct order
echo "Building aws-c-common..."
mkdir -p aws-sdk/aws-c-common/build
(cd aws-sdk/aws-c-common/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

echo "Building aws-c-cal..."
mkdir -p aws-sdk/aws-c-cal/build
(cd aws-sdk/aws-c-cal/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

echo "Building aws-c-io..."
mkdir -p aws-sdk/aws-c-io/build
(cd aws-sdk/aws-c-io/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

echo "Building aws-c-compression..."
mkdir -p aws-sdk/aws-c-compression/build
(cd aws-sdk/aws-c-compression/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

echo "Building aws-c-http..."
mkdir -p aws-sdk/aws-c-http/build
(cd aws-sdk/aws-c-http/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

echo "Building aws-c-sdkutils..."
mkdir -p aws-sdk/aws-c-sdkutils/build
(cd aws-sdk/aws-c-sdkutils/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

echo "Building aws-c-auth..."
mkdir -p aws-sdk/aws-c-auth/build
(cd aws-sdk/aws-c-auth/build && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .. && make -j${MAKE_JOBS} && make install)

# Additional dependencies and setup based on platform
CMAKE_EXTRA_ARGS="-DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}"

echo "Configuring aws-dsql-auth with CMake..."
mkdir -p build/aws-dsql-auth
cd build/aws-dsql-auth
cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} ${CMAKE_EXTRA_ARGS} ../..

echo "Building aws-dsql-auth..."
make -j${MAKE_JOBS}

echo "Build completed successfully!"
