# Virtual Machine Image Security Audit Guide

## Overview

This document provides methods and scripts for auditing virtual machine image files without booting them. The audit focuses on:
- SSH service status (security check)
- Binary file integrity verification
- General image inspection techniques

## Prerequisites

### Install libguestfs Tools

```bash
# Ubuntu/Debian
sudo apt-get install libguestfs-tools

# CentOS/RHEL
sudo yum install libguestfs-tools

# Set backend for better performance
export LIBGUESTFS_BACKEND=direct
```

## General Image Inspection Methods

### 1. List Files and Directories

```bash
# List directory contents
virt-ls -a image.qcow2 /path/to/directory

# List with details (permissions, size, etc.)
virt-ls -lR -a image.qcow2 /

# Find specific files
virt-ls -lR -a image.qcow2 / | grep "filename"
```

### 2. Read File Contents

```bash
# Display file content
virt-cat -a image.qcow2 /etc/ssh/sshd_config

# Extract file from image
virt-copy-out -a image.qcow2 /path/to/file /local/destination/
```

### 3. Execute Commands Inside Image

```bash
# Run command in image
virt-customize -a image.qcow2 --run-command 'command'

# Get image information
virt-inspector -a image.qcow2
```

### 4. Mount Image for Manual Inspection

```bash
# Mount image to local directory
guestmount -a image.qcow2 -i /mnt/image

# After inspection, unmount
guestunmount /mnt/image
```

### 5. Check Installed Packages

```bash
# List installed packages (Debian/Ubuntu)
virt-customize -a image.qcow2 --run-command 'dpkg -l'

# List installed packages (CentOS/RHEL)
virt-customize -a image.qcow2 --run-command 'rpm -qa'
```

## Audit Scripts

### Script 1: SSH Security Check

**Purpose**: Verify that SSH service is disabled in the image (secure state).

**Security Rule**: 
- ✅ **SECURE**: SSH not installed OR SSH installed but not enabled
- ❌ **INSECURE**: SSH installed and enabled (auto-start on boot)

**Script**: `check_ssh_security.sh`

```bash
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ $# -eq 0 ]; then
    echo "Usage: $0 <image_file>"
    exit 1
fi

IMAGE="$1"

if [ ! -f "$IMAGE" ]; then
    echo -e "${RED}Error: Image file '$IMAGE' not found${NC}"
    exit 1
fi

export LIBGUESTFS_BACKEND=direct

echo "======================================"
echo "  SSH Security Check"
echo "  Image: $IMAGE"
echo "======================================"

# Check if SSH is installed
echo -e "\n${BLUE}[1] Checking SSH installation${NC}"
if virt-ls -a "$IMAGE" /usr/sbin/ 2>/dev/null | grep -q "^sshd$"; then
    echo -e "${YELLOW}⚠️  SSH is installed${NC}"
    SSH_INSTALLED=1
else
    echo -e "${GREEN}✅ SSH is not installed${NC}"
    SSH_INSTALLED=0
fi

# Check if SSH is enabled (auto-start)
SSH_ENABLED=0
if [ $SSH_INSTALLED -eq 1 ]; then
    echo -e "\n${BLUE}[2] Checking SSH auto-start status${NC}"
    ENABLED_SERVICES=$(virt-ls -a "$IMAGE" /etc/systemd/system/multi-user.target.wants/ 2>/dev/null | grep ssh)
    if [ -n "$ENABLED_SERVICES" ]; then
        echo -e "${RED}❌ SSH is enabled (auto-start on boot)${NC}"
        echo "$ENABLED_SERVICES"
        SSH_ENABLED=1
    else
        echo -e "${GREEN}✅ SSH is not enabled (no auto-start)${NC}"
    fi
fi

# Summary
echo -e "\n======================================"
echo -e "${BLUE}SECURITY ASSESSMENT${NC}"
echo "======================================"

if [ $SSH_INSTALLED -eq 0 ]; then
    echo -e "${GREEN}✅ SECURE: SSH is not installed${NC}"
    exit 0
elif [ $SSH_ENABLED -eq 0 ]; then
    echo -e "${GREEN}✅ SECURE: SSH is installed but disabled${NC}"
    exit 0
else
    echo -e "${RED}❌ INSECURE: SSH is enabled (security risk)${NC}"
    echo -e "${RED}   Action required: Disable SSH service${NC}"
    exit 1
fi
```

### Script 2: Binary Hash Verification

**Purpose**: Verify the integrity of critical binary files by calculating their hash values.

**Script**: `check_binary_hash.sh`

```bash
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

BINARY_FILES=(
    "/usr/local/bin/tapp-cli"
    "/usr/local/bin/tapp-server"
)

if [ $# -eq 0 ]; then
    echo "Usage: $0 <image_file> [hash_type] [--json]"
    echo "Hash types: md5, sha1, sha256 (default), sha512"
    echo "Example: $0 my-image.qcow2 sha256"
    exit 1
fi

IMAGE="$1"
HASH_TYPE="${2:-sha256}"

if [ ! -f "$IMAGE" ]; then
    echo -e "${RED}Error: Image file '$IMAGE' not found${NC}"
    exit 1
fi

case "$HASH_TYPE" in
    md5|sha1|sha256|sha512) ;;
    *)
        echo -e "${RED}Error: Unsupported hash type '$HASH_TYPE'${NC}"
        exit 1
        ;;
esac

export LIBGUESTFS_BACKEND=direct

echo "======================================"
echo "  Binary Hash Verification"
echo "  Image: $IMAGE"
echo "  Hash Type: ${HASH_TYPE^^}"
echo "======================================"

calculate_hash() {
    local file_path="$1"
    local file_name=$(basename "$file_path")
    local file_dir=$(dirname "$file_path")
    
    echo -e "\n${BLUE}[File: $file_path]${NC}"
    
    if ! virt-ls -a "$IMAGE" "$file_dir" 2>/dev/null | grep -q "^${file_name}$"; then
        echo -e "${RED}❌ File not found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ File exists${NC}"
    echo -e "\n${CYAN}${HASH_TYPE^^}:${NC}"
    
    local hash_value
    case "$HASH_TYPE" in
        md5)    hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | md5sum | awk '{print $1}') ;;
        sha1)   hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | sha1sum | awk '{print $1}') ;;
        sha256) hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | sha256sum | awk '{print $1}') ;;
        sha512) hash_value=$(virt-cat -a "$IMAGE" "$file_path" 2>/dev/null | sha512sum | awk '{print $1}') ;;
    esac
    
    if [ -n "$hash_value" ]; then
        echo -e "${GREEN}$hash_value${NC}"
    else
        echo -e "${RED}Hash calculation failed${NC}"
        return 1
    fi
    
    return 0
}

SUCCESS_COUNT=0
FAIL_COUNT=0

for binary in "${BINARY_FILES[@]}"; do
    if calculate_hash "$binary"; then
        ((SUCCESS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
done

# Summary
echo -e "\n======================================"
echo -e "${BLUE}SUMMARY${NC}"
echo "======================================"
echo "Total files: ${#BINARY_FILES[@]}"
echo -e "Success: ${GREEN}$SUCCESS_COUNT${NC}"
[ $FAIL_COUNT -gt 0 ] && echo -e "Failed: ${RED}$FAIL_COUNT${NC}"

# JSON output
if [ "$3" = "--json" ]; then
    echo -e "\n${CYAN}JSON Output:${NC}"
    echo "{"
    echo "  \"image\": \"$IMAGE\","
    echo "  \"hash_type\": \"$HASH_TYPE\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"binaries\": ["
    
    local first=1
    for binary in "${BINARY_FILES[@]}"; do
        [ $first -eq 0 ] && echo ","
        first=0
        
        local file_name=$(basename "$binary")
        local file_dir=$(dirname "$binary")
        
        echo "    {"
        echo "      \"path\": \"$binary\","
        
        if virt-ls -a "$IMAGE" "$file_dir" 2>/dev/null | grep -q "^${file_name}$"; then
            local hash_value
            case "$HASH_TYPE" in
                md5)    hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | md5sum | awk '{print $1}') ;;
                sha1)   hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | sha1sum | awk '{print $1}') ;;
                sha256) hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | sha256sum | awk '{print $1}') ;;
                sha512) hash_value=$(virt-cat -a "$IMAGE" "$binary" 2>/dev/null | sha512sum | awk '{print $1}') ;;
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
exit $FAIL_COUNT
```

## Usage Examples

### SSH Security Check

```bash
# Make script executable
chmod +x check_ssh_security.sh

# Run the check
./check_ssh_security.sh myimage.qcow2

# Expected outputs:
# - Exit code 0: Secure (SSH not installed or disabled)
# - Exit code 1: Insecure (SSH enabled)
```

### Binary Hash Verification

```bash
# Make script executable
chmod +x check_binary_hash.sh

# Check with SHA256 (default)
./check_binary_hash.sh myimage.qcow2

# Check with different hash type
./check_binary_hash.sh myimage.qcow2 sha512

# Output JSON format
./check_binary_hash.sh myimage.qcow2 sha256 --json
```

### Complete Audit Workflow

```bash
#!/bin/bash

IMAGE="production-image.qcow2"

echo "Starting security audit for $IMAGE"
echo "=================================="

# 1. SSH Security Check
echo -e "\n[Step 1] SSH Security Check"
./check_ssh_security.sh "$IMAGE"
SSH_RESULT=$?

# 2. Binary Hash Check
echo -e "\n[Step 2] Binary Integrity Check"
./check_binary_hash.sh "$IMAGE" sha256
HASH_RESULT=$?

# 3. Manual inspection (optional)
echo -e "\n[Step 3] Additional Checks"
virt-inspector -a "$IMAGE" > "${IMAGE}.inspection.xml"

# Final result
echo -e "\n=================================="
echo "Audit Complete"
echo "SSH Security: $([ $SSH_RESULT -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "Binary Check: $([ $HASH_RESULT -eq 0 ] && echo 'PASS' || echo 'FAIL')"

exit $(($SSH_RESULT + $HASH_RESULT))
```

## Best Practices

1. **Always verify images before deployment** - Run audits on new images before using them in production
2. **Maintain hash baselines** - Store known-good hash values for comparison
3. **Automate audits** - Integrate these scripts into your CI/CD pipeline
4. **Regular re-audits** - Periodically re-check images to detect tampering
5. **Access control** - Limit who can modify base images
6. **Audit logging** - Keep records of all audit results with timestamps

## Troubleshooting

### Permission Issues
```bash
# Run with sudo if needed
sudo ./check_ssh_security.sh image.qcow2
```

### libguestfs Backend Error
```bash
# Try alternative backend
export LIBGUESTFS_BACKEND=libvirt
# or
export LIBGUESTFS_BACKEND=direct
```

### Slow Performance
```bash
# Use direct backend for better performance
export LIBGUESTFS_BACKEND=direct

# Pre-warm the cache
virt-inspector -a image.qcow2 > /dev/null
```

## Additional Resources

- [libguestfs Official Documentation](http://libguestfs.org/)
- [guestfs Tools Reference](http://libguestfs.org/guestfs.1.html)
- [Virtual Machine Security Best Practices](https://www.nist.gov/publications/guide-security-focused-configuration-management-information-systems)