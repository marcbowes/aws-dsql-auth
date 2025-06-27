#!/bin/bash
set -euo pipefail

# Detect platform
OS=$(uname -s)
case "$OS" in
    Linux*)
        PLATFORM="linux"
        ;;
    Darwin*)
        PLATFORM="macos"
        ;;
    CYGWIN*|MINGW*|MSYS*)
        PLATFORM="windows"
        ;;
    *)
        echo "Error: Unsupported platform: $OS"
        exit 1
        ;;
esac

echo "Detected platform: $PLATFORM"

# Set WITH_S2N_AWS_LC variable (defaults to true on Linux)
if [[ "$PLATFORM" == "linux" ]]; then
    WITH_S2N_AWS_LC=${WITH_S2N_AWS_LC:-true}
else
    WITH_S2N_AWS_LC=${WITH_S2N_AWS_LC:-false}
fi

echo "WITH_S2N_AWS_LC: $WITH_S2N_AWS_LC"

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

echo "Detected $MAKE_JOBS CPU cores"

# Set CMAKE_BUILD_PARALLEL_LEVEL for parallel builds
export CMAKE_BUILD_PARALLEL_LEVEL=$MAKE_JOBS

# Create build directory if it doesn't exist
mkdir -p build

INSTALL_PREFIX=$(pwd)/build/install
BUILD_PRIVATE=$(pwd)/build/private
mkdir -p ${INSTALL_PREFIX} ${BUILD_PRIVATE}

echo "Building dependencies..."

# Only build aws-lc and s2n-tls if WITH_S2N_AWS_LC is true
if [[ "$WITH_S2N_AWS_LC" == "true" ]]; then
    echo "Building aws-lc..."
    cmake -S aws-lc -B ${BUILD_PRIVATE}/aws-lc/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}
    cmake --build ${BUILD_PRIVATE}/aws-lc/build --target install

    echo "Building s2n-tls..."
    cmake -S s2n-tls -B ${BUILD_PRIVATE}/s2n-tls/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
    cmake --build ${BUILD_PRIVATE}/s2n-tls/build --target install
else
    echo "Skipping aws-lc and s2n-tls build (WITH_S2N_AWS_LC=$WITH_S2N_AWS_LC)"
fi

echo "Building aws-c-common..."
cmake -S aws-sdk/aws-c-common -B ${BUILD_PRIVATE}/aws-c-common/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-common/build --target install

echo "Building aws-c-cal..."
cmake -S aws-sdk/aws-c-cal -B ${BUILD_PRIVATE}/aws-c-cal/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-cal/build --target install

echo "Building aws-c-io..."
cmake -S aws-sdk/aws-c-io -B ${BUILD_PRIVATE}/aws-c-io/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-io/build --target install

echo "Building aws-c-compression..."
cmake -S aws-sdk/aws-c-compression -B ${BUILD_PRIVATE}/aws-c-compression/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-compression/build --target install

echo "Building aws-c-http..."
cmake -S aws-sdk/aws-c-http -B ${BUILD_PRIVATE}/aws-c-http/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-http/build --target install

echo "Building aws-c-sdkutils..."
cmake -S aws-sdk/aws-c-sdkutils -B ${BUILD_PRIVATE}/aws-c-sdkutils/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-sdkutils/build --target install

echo "Building aws-c-auth..."
cmake -S aws-sdk/aws-c-auth -B ${BUILD_PRIVATE}/aws-c-auth/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX}
cmake --build ${BUILD_PRIVATE}/aws-c-auth/build --target install

# ---
#
#

echo "Building aws-dsql-auth"
cmake -S . -B ${BUILD_PRIVATE}/aws-dsql-auth/build -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} -DWITH_S2N_AWS_LC=${WITH_S2N_AWS_LC}
cmake --build ${BUILD_PRIVATE}/aws-dsql-auth/build --target install

echo "Build completed successfully!"
