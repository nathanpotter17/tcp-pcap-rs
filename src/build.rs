fn main() {
    println!("cargo:warning=Build script is running!");
    println!("cargo:rustc-link-search=native=C:/Users/nathan/npcap-sdk-1.15/Lib/x64");
    println!("cargo:warning=Added lib path: C:/Users/nathan/npcap-sdk-1.15/Lib/x64");
}