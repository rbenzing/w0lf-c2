## Description
This is an educational project to create a Rust client for W0lf C2.

## Windows x86_x64 Installation
- Visual Studio Code - Install (https://code.visualstudio.com/download)
- rust-analyzer - Install the VS Code extension.
- rust - install Rust (https://rustup.rs/)
- vcpkg - Install vcpkg package manager (https://github.com/microsoft/vcpkg)
 - `git clone https://github.com/Microsoft/vcpkg.git`
 - `cd .\vcpkg\`
 - `.\bootstrap-vcpkg.bat`
 - `.\vcpkg integrate install` (optional step to integrate with Visual Studio MSBuild)
- Install opencv and llvm
 - `.\vcpkg install llvm opencv4`

## Verify Installation
- compiler check - `rustc --version`
- update rust - `rustup update` (if necessary)

## Update Cargo.toml
- Change the path to the VS LLVM-CONFIG libraries.

## Build Project
- use cargo - `cargo build`