// swift-tools-version: 5.9
// Package.swift — SPM package for Accord iOS

import PackageDescription

let package = Package(
    name: "Accord",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        .library(name: "AccordCore", targets: ["AccordCore"]),
    ],
    targets: [
        // Swift wrapper around the Rust FFI
        .target(
            name: "AccordCore",
            dependencies: ["AccordCoreFFI"],
            path: "Accord",
            sources: ["AccordCore.swift"]
        ),
        // C module wrapping the Rust static library
        .systemLibrary(
            name: "AccordCoreFFI",
            path: "AccordCore"
        ),
    ]
)
