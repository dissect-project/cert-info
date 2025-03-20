#!/bin/bash

# Colors
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
BOLD="\033[1m"
RESET="\033[0m"

# Function to print a header
print_header() {
    #echo -e "${BLUE}========================================${RESET}"
    echo ""
    echo -e "${BOLD}$1${RESET}"
    sleep $2  # Pause for readability
}

# Function for success messages
success_msg() {
    echo -e "${GREEN}✔ $1${RESET}"
    sleep 1  # Pause for readability
}

# Function for warning messages
warning_msg() {
    echo -e "${YELLOW}⚠ $1${RESET}"
    sleep 1  # Pause for readability
}

# Function for error messages
error_msg() {
    echo -e "${RED}✖ $1${RESET}"
    sleep 1  # Pause for readability
}

# Project Root and Source Directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSSL_REPO="https://github.com/testssl/testssl.sh.git"

# Print a banner
# clear
echo -e "${BOLD}${GREEN}"
echo "╔════════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                                ║"
echo "║    ██████╗███████╗██████╗ ████████╗           ██╗███╗   ██╗███████╗ ██████╗    ║"
echo "║   ██╔════╝██╔════╝██╔══██╗╚══██╔══╝           ██║████╗  ██║██╔════╝██╔═══██╗   ║"
echo "║   ██║     █████╗  ██████╔╝   ██║      ████╗   ██║██╔██╗ ██║█████╗  ██║   ██║   ║"
echo "║   ██║     ██╔══╝  ██╔══██╗   ██║      ╚═══╝   ██║██║╚██╗██║██╔══╝  ██║   ██║   ║"
echo "║   ╚██████╗███████╗██║  ██║   ██║              ██║██║ ╚████║██║     ╚██████╔╝   ║"
echo "║    ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝              ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝    ║"
echo "║                                                                                ║"
echo "╚════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
sleep 1  # Pause for readability

######### Verify wether the environment is ready #########
print_header "📂 Preparing the Environment" 2
# Ensure src/ directory exists
mkdir -p "$SRC_DIR"
success_msg "The src/ directory exists at $SRC_DIR"
##########################################################

### Clone the testssl.sh repository with a nice spinner ##
print_header "🔄 Looking for testssl.sh" 2
# Check if the repository already exists
if [ -d "$SRC_DIR/testssl" ]; then
    warning_msg "Repository already exists in $SRC_DIR. Skipping clone."
else
    echo "⏳ Cloning repository..."
    sleep 1  # Simulate loading time
    git clone "$TESTSSL_REPO" "$SRC_DIR/testssl" &> /dev/null
    if [ $? -eq 0 ]; then
        success_msg "Repository cloned successfully into $SRC_DIR/testssl"
    else
        error_msg "Failed to clone repository!"
        exit 1
    fi
fi
##########################################################

# Print a success message
print_header "🎉 Setup Complete!" 0.5
success_msg "Package is ready to use."
