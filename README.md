# 0g-tapp-verifier

This repository provides tools and scripts for verifying TEE (Trusted Execution Environment) evidence and auditing CVM confidential images. It enables users to validate the integrity and authenticity of TEE instances running on Alibaba Cloud.

## Table of Contents

- [TEE Evidence Verification](#tee-evidence-verification)
- [TEE CVM Image Audit](#tee-cvm-image-audit)

---

## TEE Evidence Verification

This section guides you through the process of verifying TEE evidence.

### Prerequisites

- Access to Alibaba Cloud OSS
- Sufficient storage space (at least 20GB for the CVM image)
- Command-line tools: `ossutil`, `git`, `bash`

### Step 1: Download and Configure OSS

Download and configure `ossutil` following the official Alibaba Cloud documentation:

**Documentation:** https://www.alibabacloud.com/help/en/oss/developer-reference/install-ossutil?spm=5176.2020520104.0.0.22953a98t0kXoY

**Configuration Parameters:**
- **Region:** `cn-beijing`
- **Endpoint:** 
  - Internal: `oss-cn-beijing-internal.aliyuncs.com` (Recommended)
  - Public: `oss-cn-beijing.aliyuncs.com`
- **Access Credentials:** Generate your own `accessKeyID` and `accessKeySecret` (the bucket has public read access)

> **⚠️ Important Recommendation:** 
> It is strongly recommended to launch an ECS instance in the same region (cn-beijing) and use the internal endpoint (`oss-cn-beijing-internal.aliyuncs.com`). The CVM confidential image is approximately **18GB** in size, and using the internal endpoint will significantly reduce download time.

### Step 2: Download CVM Confidential Image

Create the input directory and download the confidential image:

```bash
mkdir -p ./verify/input
ossutil cp oss://confidential-disk/0g-tapp-confidential-gpu.qcow2 ./verify/input/0g-tapp-confidential-gpu.qcow2
```

This will download the `0g-tapp-confidential-gpu.qcow2` image file to your local `./verify/input/` directory.

### Step 3: Get TEE Evidence

Clone the repository and retrieve the evidence:

```bash
# Clone the repository
git clone https://github.com/0gfoundation/0g-tapp

# Navigate to the tapp directory
cd tapp

# Get evidence from the TEE instance
sh examples/get_evidence.sh 8.131.111.246
```

Save the output to `./verify/input/evidence.json`:

```bash
sh examples/get_evidence.sh 8.131.111.246 > ./verify/input/evidence.json
```

### Step 4: Execute Verification Script

Run the verification script:

```bash
sh ./verify/run.sh
```

The script will verify the TEE evidence against the confidential image and output the verification results.

---

## TEE CVM Image Audit

For detailed information on TEE CVM image audit procedures, please refer to:

**[TEE CVM Image Audit Documentation](./audit/AUDIT_GUIDE.md)**

---

## Troubleshooting

- **OSS Connection Issues:** Ensure your OSS credentials (accessKeyID and accessKeySecret) are correctly configured.
- **Large File Download:** If the download is slow or fails, verify your network connection and consider using the internal endpoint if you're on an Alibaba Cloud ECS instance.
- **Evidence Collection:** Ensure the IP address `8.131.111.246` is accessible and the TEE instance is running properly.

## Support

For issues or questions, please open an issue in the [0g-tapp repository](https://github.com/0gfoundation/0g-tapp).