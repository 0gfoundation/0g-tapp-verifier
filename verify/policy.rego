package policy

import rego.v1

# This policy validates multiple TEE platforms
# The policy is meant to capture the TCB requirements
# for confidential containers.

# This policy is used to generate an EAR Appraisal.
# Specifically it generates an AR4SI result.
# More informatino on AR4SI can be found at
# <https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/>

# For the `executables` trust claim, the value 33 stands for
# "Runtime memory includes executables, scripts, files, and/or
#  objects which are not recognized."
default executables := 33


# For the `configuration` trust claim the value 36 stands for
# "Elements of the configuration relevant to security are
#  unavailable to the Verifier."
default configuration := 36

# For the `filesystem` trust claim, the value 35 stands for
# "File system integrity cannot be verified or is compromised."
default file_system := 35

##### Common Helper Functions

### The following functions are for parsing UEFI event logs
### These functions are chosen when the related verifier is using `deps/eventlog`
### crate

# Parse grub algorithm and digest
parse_grub(uefi_event_logs) := grub if {
        some i, j
        uefi_event_logs[i].type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
        contains(uefi_event_logs[i].details.device_paths[j], "grub")
        grub := {
                "alg": uefi_event_logs[i].digests[0].alg,
                "value": uefi_event_logs[i].digests[0].digest,
        }
}

# Parse shim algorithm and digest
parse_shim(uefi_event_logs) := shim if {
        some i, j
        uefi_event_logs[i].type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
        contains(uefi_event_logs[i].details.device_paths[j], "shim")
        shim := {
                "alg": uefi_event_logs[i].digests[0].alg,
                "value": uefi_event_logs[i].digests[0].digest,
        }
}

# Parse kernel algorithm and digest
parse_kernel(uefi_event_logs) := kernel if {
        some i
        uefi_event_logs[i].type_name == "EV_IPL"
        contains(uefi_event_logs[i].details.string, "Kernel")
        kernel := {
                "alg": uefi_event_logs[i].digests[0].alg,
                "value": uefi_event_logs[i].digests[0].digest,
        }
}

# Parse initrd algorithm and digest
parse_initrd(uefi_event_logs) := initrd if {
        some i
        uefi_event_logs[i].type_name == "EV_IPL"
        contains(uefi_event_logs[i].details.string, "Initrd")
        initrd := {
                "alg": uefi_event_logs[i].digests[0].alg,
                "value": uefi_event_logs[i].digests[0].digest,
        }
}

# Generic function to validate measurements for any platform and algorithm
# that recorded via uefi eventlog format
validate_boot_measurements_uefi_event_log(uefi_event_logs) if {
        grub := parse_grub(uefi_event_logs)
        shim := parse_shim(uefi_event_logs)
        initrd := parse_initrd(uefi_event_logs)
        kernel := parse_kernel(uefi_event_logs)
        components := [
                {"name": "grub", "value": grub.value, "alg": grub.alg},
                {"name": "shim", "value": shim.value, "alg": shim.alg},
                {"name": "initrd", "value": initrd.value, "alg": initrd.alg},
                {"name": "kernel", "value": kernel.value, "alg": kernel.alg},
        ]
        every component in components {
                measurement_key := sprintf("measurement.%s.%s", [component.name, component.alg])
                component.value in data.reference[measurement_key]
        }
}

# Generic function to validate kernel cmdline for any platform and algorithm
validate_kernel_cmdline_uefi(uefi_event_logs) if {
        some prefix in ["grub_cmd linux", "kernel_cmdline", "grub_kernel_cmdline"]
        some i
        uefi_event_logs[i].type_name == "EV_IPL"
        startswith(uefi_event_logs[i].details.string, prefix)
        measurement_key := sprintf("measurement.kernel_cmdline.%s", [uefi_event_logs[i].digests[0].alg])
        uefi_event_logs[i].digests[0].digest in data.reference[measurement_key]
}

# Function to check the cryptpilot load config
validate_cryptpilot_config(uefi_event_logs) if {
        some i
        uefi_event_logs[i].type_name == "EV_EVENT_TAG"
        uefi_event_logs[i].details.unicode_name == "AAEL"
        uefi_event_logs[i].details.data.domain == "cryptpilot.alibabacloud.com"
        uefi_event_logs[i].details.data.operation == "load_config"
        uefi_event_logs[i].details.data.content in data.reference["AA.eventlog.cryptpilot.alibabacloud.com.load_config"]
}

# Function to check the cryptpilot fde rootfs integrity
validate_cryptpilot_fde(uefi_event_logs) if {
        some i
        uefi_event_logs[i].type_name == "EV_EVENT_TAG"
        uefi_event_logs[i].details.unicode_name == "AAEL"
        uefi_event_logs[i].details.data.domain == "cryptpilot.alibabacloud.com"
        uefi_event_logs[i].details.data.operation == "fde_rootfs_hash"
        uefi_event_logs[i].details.data.content in data.reference["AA.eventlog.cryptpilot.alibabacloud.com.fde_rootfs_hash"]
}

executables := 3 if {
        # Check the kernel, initrd, shim and grub measurements for any supported algorithm
        validate_boot_measurements_uefi_event_log(input.tdx.uefi_event_logs)
}

configuration := 2 if {
        # Check kernel command line parameters have the expected value for any supported algorithm
        validate_kernel_cmdline_uefi(input.tdx.uefi_event_logs)
        # Check cryptpilot config
        validate_cryptpilot_config(input.tdx.uefi_event_logs)
        validate_cryptpilot_fde(input.tdx.uefi_event_logs)
}

file_system := 1 if {
        # Check rootfs integrity
        validate_cryptpilot_fde(input.tdx.uefi_event_logs)
}