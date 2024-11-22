pub mod types;

use std::env;
use types::Architecture;
fn main() {
    println!("Client démarré");
    println!("{:?}", get_architecture());
}

/// Returns the current architecture of the system.
///
/// This function uses the `env::consts::ARCH` constant to determine the
/// architecture of the system at compile time and maps it to the corresponding
/// `Architecture` enum variant.
///
/// # Returns
///
/// * `Architecture::X86` - if the architecture is x86 (32-bit).
/// * `Architecture::X86_64` - if the architecture is x86_64 (64-bit).
/// * `Architecture::ARM` - if the architecture is ARM.
/// * `Architecture::AARCH64` - if the architecture is AArch64.
/// * `Architecture::Unknown` - if the architecture is not recognized.
fn get_architecture() -> Architecture {
    let arch = env::consts::ARCH;
    match arch {
        "x86" => Architecture::X86,
        "x86_64" => Architecture::X86_64,
        "arm" => Architecture::ARM,
        "aarch64" => Architecture::AARCH64,
        _ => Architecture::Unknown,
    }
}
