fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AS proto is shared with the self-hosted trustee stack (layer 1) rather
    // than duplicated — one copy per repo, not per component.
    let protos = [
        ("proto", "proto/tapp_service.proto"),
        ("../tdx-boot-chain", "../tdx-boot-chain/attestation.proto"),
    ];
    for (dir, file) in protos {
        println!("cargo:rerun-if-changed={file}");
        tonic_build::configure()
            .build_server(false)
            .compile_protos(&[file], &[dir])?;
    }
    Ok(())
}
