#!/bin/bash
set -e


if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &>/dev/null; then
        echo "Ubuntu/Debian detected. Installing LLVM & Clang..."
        sudo apt-get update
        sudo apt-get install -y llvm-dev libclang-dev clang
    elif command -v pacman &>/dev/null; then
        echo "Arch Linux detected. Installing LLVM & Clang..."
        sudo pacman -Syu --noconfirm llvm clang
    elif command -v dnf &>/dev/null; then
        echo "Fedora detected. Installing LLVM & Clang..."
        sudo dnf install -y llvm-devel clang
    else
        echo "Unsupported Linux distribution. Please install LLVM & Clang manually"
        exit 1
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected. Installing LLVM & Clang via Homebrew..."
    if ! command -v brew &>/dev/null; then
        echo "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update
    brew install llvm
else
    echo "Unsupported OS : $OSTYPE"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "Cargo is not installed. Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env"
else
    echo "Cargo is installed. Updating Rust toolchain..."
    rustup update
fi

echo "Cleaning and building the project in release mode..."
# cargo clean
cargo build --release
echo "Build complete !"

OS=$(uname)
if [[ "$OS" == "MINGW"* ]] || [[ "$OS" == "MSYS"* ]] || [[ "$OS" == "CYGWIN"* ]]; then
    EXT_SUFFIX="dll"
elif [[ "$OS" == "Darwin" ]]; then
    EXT_SUFFIX="dylib"
else
    EXT_SUFFIX="so"
fi
echo "Detected OS : $OS , using extension : $EXT_SUFFIX"

EXT_FILE=$(find / -type f -iname "libtgcrypto.${EXT_SUFFIX}" 2>/dev/null | head -n 1)

if [ -z "$EXT_FILE" ]; then
    echo "Error : No extension file found in target/release"
    exit 1
fi
echo "Found extension file : $EXT_FILE"

EXT_DIR=$(php-config --extension-dir 2>/dev/null)
if [ -z "$EXT_DIR" ]; then
    echo "Error : Could not determine PHP extension directory via php-config"
    exit 1
fi
echo "PHP extension directory : $EXT_DIR"

OUTPUT_FILE="$EXT_DIR/tgcrypto.$EXT_SUFFIX"

cp "$EXT_FILE" "$OUTPUT_FILE" || { echo "Failed to copy extension file"; exit 1; }


PHP_INI=$(php --ini | awk -F': ' '/Loaded Configuration File/ {print $2}' | xargs)

if [ -z "$PHP_INI" ]; then
    echo "Error: Could not find php.ini file."
    exit 1
fi

if grep -q "^extension=tgcrypto.$EXT_SUFFIX" "$PHP_INI"; then
    echo "tgcrypto.$EXT_SUFFIX is already enabled in php.ini"
else
    echo "Adding extension=tgcrypto.$EXT_SUFFIX to php.ini"
    echo -e "\nextension=tgcrypto.$EXT_SUFFIX" >> "$PHP_INI"
    echo "tgcrypto.$EXT_SUFFIX has been added to php.ini"
fi


echo "Verifying PHP extension load..."
php -m | grep -i tgcrypto && echo "extension is loaded !" || echo "extension is not loaded. Check your configuration"

php -r "print('Version : '.TGCRYPTO_VERSION.PHP_EOL);"

echo "Installation successful !"
