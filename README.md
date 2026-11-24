# 0g-tapp-verifier

This repository provides tools and scripts for verifying TEE (Trusted Execution Environment) evidence and auditing CVM confidential images. It enables users to validate the integrity and authenticity of 0G tapp TEE instances.

## Table of Contents

- [tappscan — TappRegistry explorer and verifier](./scan/README.md) (`scan/`)
- [TDX boot-chain verifier with your own trustee](./tdx-boot-chain/README.md) (`tdx-boot-chain/`)
- [TEE CVM Image Audit](#tee-cvm-image-audit) (`audit/`)

---

## Verifying a node

- `tapp-cli verify-app` from [0g-tapp](https://github.com/0gfoundation/0g-tapp) checks an app's
  nodes end to end: quote, boot chain against the published reference values, on-chain
  registration and KMS keys.
- The hosted scans show the same verdicts for every registered app: mainnet
  `https://tappscan.0g.ai`, testnet `https://tappscan-testnet.34-122-75-6.sslip.io`
  ([`scan/`](./scan/README.md)).
- To trust neither: compute the reference values from the image yourself with 0g-tapp's
  `cvm/ci/gen-reference-values.sh` and evaluate the evidence on your own trustee
  ([`tdx-boot-chain/`](./tdx-boot-chain/README.md)).

---

## TEE CVM Image Audit

For detailed information on TEE CVM image audit procedures, please refer to:

**[TEE CVM Image Audit Documentation](./audit/AUDIT_GUIDE.md)**

---

## Support

For issues or questions, please open an issue in the [0g-tapp repository](https://github.com/0gfoundation/0g-tapp).
