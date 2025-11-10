#!/bin/bash

# usage: ./check_binary_hash.sh <image_file> [hash_type]
# hash_type: md5, sha1, sha256 (default), sha512

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# target binaries
BINARY_FILES=(
    "/usr/local/bin/tapp-cli"
    "/usr/local/bin/tapp_server"
)

# check parameters
if [ $# -eq 0 ]; then
    echo "usage: $0 <image_file> [hash_type]"
    echo "hash_type: md5, sha1, sha256 (default), sha512"
    echo "example: $0 my-image.qcow2 sha256"
    exit 1
fi

IMAGE="$1"
HASH_TYPE="${2:-sha256}" # default sha256

# check if the image file exists
if [ ! -f "$IMAGE" ]; then
    echo -e "${RED}error: image file '$IMAGE' not found${NC}"
    exit 1
fi

# check hash type
case "$HASH_TYPE" in
    md5|sha1|sha256|sha512)
        ;;
    *)
        echo -e "${RED}error: unsupported hash type '$HASH_TYPE'${NC}"
        echo "supported types: md5, sha1, sha256, sha512"
        exit 1
        ;;
esac

# set libguestfs backend
export LIBGUESTFS_BACKEND=direct

echo "======================================"
echo "  binary file hash check"
echo "  image: $IMAGE"
echo "  hash type: ${HASH_TYPE^^}"
echo "======================================"

# function: calculate file hash
calculate_hash() {
    local file_path="$1"
    local file_name=$(basename "$file_path")
    local file_dir=$(dirname "$file_path")
    
    echo -e "\n${BLUE}[file: $file_path]${NC}"
    
    # check if the file exists
    if ! virt-ls -a "$IMAGE" "$file_dir" 2>/dev/null | grep -q "^${file_name}$"; then
        echo -e "${RED}❌ file not found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ file exists${NC}"
    
    # calculate hash
    echo -e "\n${CYAN}${HASH_TYPE^^}:${NC}"
    local hash_value
    
    case "$HASH_TYPE" in
        md5)
            hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | md5sum | awk '{print $1}')
            ;;
        sha1)
            hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | sha1sum | awk '{print $1}')
            ;;
        sha256)
            hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | sha256sum | awk '{print $1}')
            ;;
        sha512)
            hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | sha512sum | awk '{print $1}')
            ;;
    esac
    
    if [ -n "$hash_value" ]; then
        echo -e "${GREEN}$hash_value${NC}"
    else
        echo -e "${RED}calculation failed${NC}"
        return 1
    fi
    
    return 0
}

# check all binary files
SUCCESS_COUNT=0
FAIL_COUNT=0

for binary in "${BINARY_FILES[@]}"; do
    if calculate_hash "$binary"; then
        ((SUCCESS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
done

# summary
echo -e "\n======================================"
echo -e "${BLUE}summary${NC}"
echo "======================================"
echo "number of files to check: ${#BINARY_FILES[@]}"
echo -e "success: ${GREEN}$SUCCESS_COUNT${NC}"
if [ $FAIL_COUNT -gt 0 ]; then
    echo -e "failed: ${RED}$FAIL_COUNT${NC}"
fi

# JSON format output
if [ "$3" = "--json" ]; then
    echo -e "\n${CYAN}JSON format:${NC}"
    echo "{"
    echo "  \"image\": \"$IMAGE\","
    echo "  \"hash_type\": \"$HASH_TYPE\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"binaries\": ["
    
    local first=1
    for binary in "${BINARY_FILES[@]}"; do
        if [ $first -eq 0 ]; then
            echo ","
        fi
        first=0
        
        local file_name=$(basename "$binary")
        local file_dir=$(dirname "$binary")
        
        echo "    {"
        echo "      \"path\": \"$binary\","
        
        if virt-ls -a "$IMAGE" "$file_dir" 2>/dev/null | grep -q "^${file_name}$"; then
            local hash_value
            case "$HASH_TYPE" in
                md5)
                    hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | md5sum | awk '{print $1}')
                    ;;
                sha1)
                    hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | sha1sum | awk '{print $1}')
                    ;;
                sha256)
                    hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | sha256sum | awk '{print $1}')
                    ;;
                sha512)
                    hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | sha512sum | awk '{print $1}')
                    ;;
            esac
            
            echo "      \"exists\": true,"
            echo "      \"$HASH_TYPE\": \"$hash_value\""
        else
            echo "      \"exists\": false"
        fi
        
        echo -n "    }"
    done
    
    echo ""
    echo "  ]"
    echo "}"
fi

echo ""

# exit code
if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
else
    exit 0
fi