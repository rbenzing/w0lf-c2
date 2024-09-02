use std::env;
use std::path::PathBuf;

fn main() {
    // Rerun the build script if `build.rs` changes
    println!("cargo:rerun-if-changed=build.rs");

    // Retrieve the VCPKG_ROOT environment variable or use a default path
    let vcpkg_root: String = env::var("VCPKG_ROOT").unwrap_or_else(|_| "C:/vcpkg".to_string());

    // Define the paths to the vcpkg library and include directories
    let lib_dir: PathBuf = PathBuf::from(&vcpkg_root).join("installed/x64-windows/lib");
    let include_dir: PathBuf = PathBuf::from(&vcpkg_root).join("installed/x64-windows/include");

    // Print library paths for Cargo
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:include={}", include_dir.display());

    // Specify which libraries to link against
    println!("cargo:rustc-link-lib=opencv_core4");
    println!("cargo:rustc-link-lib=opencv_highgui4");
    println!("cargo:rustc-link-lib=opencv_imgcodecs4");
    println!("cargo:rustc-link-lib=opencv_videoio4");
}