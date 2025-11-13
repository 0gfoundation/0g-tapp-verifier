# Confidential Virtual Machine Image Security Audit Guide

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

**Purpose**: Verify the integrity of critical binary files by calculating their hash values and comparing them with GitHub release attestations.

**Verification Workflow**:
1. Calculate hashes from binaries in the VM image
2. Compare with official GitHub release hashes
3. Verify GitHub Sigstore attestations (optional but recommended)

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
    "/usr/local/bin/tapp_server"
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

## Verifying Against GitHub Release

### Manual Hash Verification Guide

After running the hash check script, you should manually compare the results with the official GitHub release to verify binary integrity.

### Step 1: Calculate Hashes from VM Image

```bash
# Run the hash check script
./check_binary_hash.sh myimage.qcow2 sha256

# Or calculate manually
virt-cat -a myimage.qcow2 /usr/local/bin/tapp-cli | sha256sum
virt-cat -a myimage.qcow2 /usr/local/bin/tapp_server | sha256sum
```

**Example output**:
```
[File: /usr/local/bin/tapp-cli]
✅ File exists

SHA256:
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2

[File: /usr/local/bin/tapp_server]
✅ File exists

SHA256:
f2e1d0c9b8a7z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1
```

### Step 2: Visit GitHub Release Page

1. Open your browser and navigate to the project's GitHub release page
2. **Example**: `https://github.com/0gfoundation/0g-tapp/releases/tag/v0.0.1`
3. Look for the **Assets** section at the bottom of the release

### Step 3: Find Official Checksums

In the GitHub release page, look for:
- **Checksums file**: Usually named `checksums.txt`, `SHA256SUMS`, or similar
- **Attestation badges**: Look for "Provenance" or signature indicators
- **Release notes**: May include hash values directly

**Click to download the checksums file or view it inline**

### Step 4: Compare Hashes Manually

```
Official checksums.txt (from GitHub):
────────────────────────────────────────────────────────────────
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2  tapp-cli
f2e1d0c9b8a7z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1  tapp_server

Your extracted hashes (from Step 1):
────────────────────────────────────────────────────────────────
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2  tapp-cli
f2e1d0c9b8a7z6y5x4w3v2u1t0s9r8q7p6o5n4m3l2k1j0i9h8g7f6e5d4c3b2a1  tapp_server

Result: ✅ MATCH - Binaries are authentic
```

### Verification Checklist

- [ ] Downloaded checksums from official GitHub release
- [ ] Verified you're on the correct repository (e.g., `0gfoundation/0g-tapp`)
- [ ] Checked the correct release tag/version
- [ ] All hash values match exactly (character by character)
- [ ] No warnings or errors during hash calculation

### What to Do If Hashes Don't Match

❌ **DO NOT USE THE IMAGE** if hashes don't match

Possible causes:
- Binary files were modified or tampered with
- Wrong version of binaries in the image
- Corrupted download or build process

Actions:
1. Verify you're comparing against the correct release version
2. Re-download the image from a trusted source
3. Contact the image provider for clarification
4. Rebuild the image from official source code

### Additional Verification (Optional)

For projects that support Sigstore attestations, GitHub may display:
- ✅ **"Provenance" badge** - Indicates cryptographically signed build
- 📋 **Build logs** - Link to the GitHub Actions workflow that built the binary
- 🔐 **Signature files** - `.sig` or `.pem` files for advanced verification

These provide additional confidence that binaries were built by the official repository and haven't been tampered with.

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

echo -e "\n=================================="
echo "Next Steps:"
echo "=================================="
echo "1. Copy the hash values above"
echo "2. Visit GitHub release page:"
echo "   https://github.com/0gfoundation/0g-tapp/releases/tag/v0.0.1"
echo "3. Download checksums file from Assets section"
echo "4. Manually compare hash values"
echo ""

# 3. Manual inspection (optional)
echo -e "[Step 3] Generating inspection report (optional)..."
virt-inspector -a "$IMAGE" > "${IMAGE}.inspection.xml"

# Final result
echo -e "\n=================================="
echo "Audit Summary"
echo "=================================="
echo "SSH Security:    $([ $SSH_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "Binary Check:    $([ $HASH_RESULT -eq 0 ] && echo '✅ PASS' || echo '❌ FAIL')"
echo "Manual Verify:   ⏳ PENDING (see instructions above)"
echo "=================================="

exit $(($SSH_RESULT + $HASH_RESULT))
```

## Best Practices

1. **Always verify images before deployment** - Run audits on new images before using them in production
2. **Verify against GitHub releases** - Manually compare hashes with official GitHub release checksums
3. **Document verification** - Record which release version you verified against and keep audit logs
4. **Access control** - Limit who can modify base images
5. **Regular re-audits** - Periodically re-check images to detect tampering
6. **Use specific versions** - Reference exact release tags (e.g., v0.0.1), not "latest"
7. **Automate where possible** - Integrate SSH and hash check scripts into your CI/CD pipeline
8. **Verify build provenance** - Check for Sigstore attestations or "Provenance" badges on GitHub releases

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
- [0G Foundation GitHub](https://github.com/0gfoundation)
- [Sigstore Project Overview](https://docs.sigstore.dev/)
- [Virtual Machine Security Best Practices](https://www.nist.gov/publications/guide-security-focused-configuration-management-information-systems)