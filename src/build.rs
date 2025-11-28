fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    match target_os.as_str() {
        "windows" => configure_windows(),
        "linux" | "macos" => configure_unix(),
        _ => {
            println!("cargo:warning=Unsupported OS: {}", target_os);
        }
    }
}

fn configure_windows() {
    println!("cargo:warning=Configuring for Windows...");
    
    // Try environment variable first, then fall back to hardcoded path
    let lib_path = std::env::var("LIBPCAP_LIBDIR")
        .unwrap_or_else(|_| "C:/Users/nathan/npcap-sdk-1.15/Lib/x64".to_string());
    
    // Verify the path exists
    if !std::path::Path::new(&lib_path).exists() {
        panic!(
            "\n\n\
            ═══════════════════════════════════════════════════════════════\n\
            ERROR: Npcap SDK not found!\n\
            ═══════════════════════════════════════════════════════════════\n\
            \n\
            Looking for: {}\n\
            \n\
            Please ensure:\n\
            1. Npcap SDK is installed\n\
            2. Set LIBPCAP_LIBDIR environment variable, or\n\
            3. Update the hardcoded path in build.rs\n\
            \n\
            Download Npcap SDK from: https://npcap.com/#download\n\
            ═══════════════════════════════════════════════════════════════\n\
            ", lib_path
        );
    }
    
    println!("cargo:rustc-link-search=native={}", lib_path);
    println!("cargo:warning=✓ Npcap SDK found: {}", lib_path);
    
    // Explicitly link the required libraries
    println!("cargo:rustc-link-lib=dylib=wpcap");
    println!("cargo:rustc-link-lib=dylib=Packet");
}

fn configure_unix() {
    println!("cargo:warning=Configuring for Unix/Linux...");
    
    // On Linux/Unix, pkg-config handles libpcap automatically via the pcap crate
    // Just verify pkg-config can find it
    match std::process::Command::new("pkg-config")
        .args(&["--exists", "libpcap"])
        .status()
    {
        Ok(status) if status.success() => {
            println!("cargo:warning=✓ libpcap found via pkg-config");
            
            // Optionally print the version
            if let Ok(output) = std::process::Command::new("pkg-config")
                .args(&["--modversion", "libpcap"])
                .output()
            {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    println!("cargo:warning=  libpcap version: {}", version.trim());
                }
            }
        }
        Ok(_) => {
            println!("cargo:warning=⚠ libpcap not found via pkg-config");
            println!("cargo:warning=  Install with:");
            println!("cargo:warning=    Debian/Ubuntu: sudo apt-get install libpcap-dev");
            println!("cargo:warning=    Fedora/RHEL:   sudo dnf install libpcap-devel");
            println!("cargo:warning=    Arch:          sudo pacman -S libpcap");
        }
        Err(e) => {
            println!("cargo:warning=⚠ pkg-config not found: {}", e);
            println!("cargo:warning=  libpcap detection may fail");
        }
    }
    
    // Note about capabilities
    println!("cargo:warning=");
    println!("cargo:warning=Remember: After building, set capabilities with:");
    println!("cargo:warning=  sudo setcap cap_net_raw,cap_net_admin=eip target/release/<binary>");
    println!("cargo:warning=");
}