#!/bin/bash

# SSH image check script
# usage: ./check_ssh_in_image.sh <image_file>

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# check parameters
if [ $# -eq 0 ]; then
    echo "usage: $0 <image_file>"
    echo "example: $0 my-image.qcow2"
    exit 1
fi

IMAGE="$1"

# check if the image file exists
if [ ! -f "$IMAGE" ]; then
    echo -e "${RED}error: image file '$IMAGE' not found${NC}"
    exit 1
fi

# set libguestfs backend
export LIBGUESTFS_BACKEND=direct

echo "======================================"
echo "  SSH status check report"
echo "  image: $IMAGE"
echo "======================================"

# 1. check if SSH is installed
echo -e "\n${BLUE}[1] check if SSH is installed${NC}"
if virt-ls -a "$IMAGE" /usr/sbin/ 2>/dev/null | grep -q "^sshd$"; then
    echo -e "${GREEN}✅ SSH is installed${NC}"
    SSH_INSTALLED=1
else
    echo -e "${RED}❌ SSH is not installed${NC}"
    SSH_INSTALLED=0
fi

# 2. check SSH service file
if [ $SSH_INSTALLED -eq 1 ]; then
    echo -e "\n${BLUE}[2] SSH service file${NC}"
    virt-ls -a "$IMAGE" /lib/systemd/system/ 2>/dev/null | grep ssh || echo "未找到 systemd 服务文件"
fi

# 3. check if SSH is enabled (auto-started on boot)
echo -e "\n${BLUE}[3] check if SSH is enabled (auto-started on boot)${NC}"
ENABLED_SERVICES=$(virt-ls -a "$IMAGE" /etc/systemd/system/multi-user.target.wants/ 2>/dev/null | grep ssh)
if [ -n "$ENABLED_SERVICES" ]; then
    echo -e "${GREEN}✅ SSH 已启用（开机自启动）${NC}"
    echo "$ENABLED_SERVICES"
    SSH_ENABLED=1
else
    echo -e "${RED}❌ SSH 未启用（开机不会自启动）${NC}"
    SSH_ENABLED=0
fi

# 4. check SSH key configuration
echo -e "\n${BLUE}[4] SSH key configuration${NC}"
SSHD_CONFIG=$(virt-cat -a "$IMAGE" /etc/ssh/sshd_config 2>/dev/null)
if [ -n "$SSHD_CONFIG" ]; then
    # port
    PORT=$(echo "$SSHD_CONFIG" | grep "^Port" | awk '{print $2}')
    if [ -n "$PORT" ]; then
        echo "  端口: $PORT"
    else
        echo "  端口: 22 (默认)"
    fi
    
    # Root login
    PERMIT_ROOT=$(echo "$SSHD_CONFIG" | grep "^PermitRootLogin" | awk '{print $2}')
    if [ -n "$PERMIT_ROOT" ]; then
        if [ "$PERMIT_ROOT" = "yes" ]; then
            echo -e "  Root login: ${YELLOW}$PERMIT_ROOT${NC}"
        else
            echo -e "  Root login: ${GREEN}$PERMIT_ROOT${NC}"
        fi
    else
        echo "  Root login: not explicitly configured (default may allow)"
    fi
    
    # password authentication
    PASSWORD_AUTH=$(echo "$SSHD_CONFIG" | grep "^PasswordAuthentication" | awk '{print $2}')
    if [ -n "$PASSWORD_AUTH" ]; then
        echo "  Password authentication: $PASSWORD_AUTH"
    else
        echo "  Password authentication: not explicitly configured (default may allow)"
    fi
    
    # public key authentication
    PUBKEY_AUTH=$(echo "$SSHD_CONFIG" | grep "^PubkeyAuthentication" | awk '{print $2}')
    if [ -n "$PUBKEY_AUTH" ]; then
        echo "  Public key authentication: $PUBKEY_AUTH"
    else
        echo "  Public key authentication: not explicitly configured (default may allow)"
    fi
else
    echo -e "${YELLOW}⚠️  cannot read SSH config file${NC}"
fi

# 5. check firewall rules
echo -e "\n${BLUE}[5] check firewall rules${NC}"
# check iptables
IPTABLES=$(virt-cat -a "$IMAGE" /etc/sysconfig/iptables 2>/dev/null | grep -i "22")
if [ -n "$IPTABLES" ]; then
    echo "  iptables rules:"
    echo "$IPTABLES" | sed 's/^/    /'
else
    # check ufw
    UFW=$(virt-cat -a "$IMAGE" /etc/ufw/user.rules 2>/dev/null | grep -i "22")
    if [ -n "$UFW" ]; then
        echo "  UFW rules:"
        echo "$UFW" | sed 's/^/    /'
    else
        echo "  no obvious firewall rules configured"
    fi
fi

# 6. summary
echo -e "\n======================================"
echo -e "${BLUE}summary${NC}"
echo "======================================"

if [ $SSH_INSTALLED -eq 0 ]; then
    echo -e "${RED}❌ SSH is not installed - SSH is disabled${NC}"
elif [ $SSH_ENABLED -eq 0 ]; then
    echo -e "${YELLOW}⚠️  SSH is installed but not enabled - SSH is disabled${NC}"
    echo -e "${YELLOW}   (can be manually started, but will not start automatically on boot)${NC}"
else
    echo -e "${GREEN}✅ SSH is installed and enabled - SSH is enabled${NC}"
    echo -e "${GREEN}   (will start automatically on boot)${NC}"
fi

echo ""

# exit code
if [ $SSH_INSTALLED -eq 0 ] || [ $SSH_ENABLED -eq 0 ]; then
    exit 1  # SSH is disabled
else
    exit 0  # SSH is enabled
fi