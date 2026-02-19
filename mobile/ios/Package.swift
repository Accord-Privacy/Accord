// swift-tools-version: 5.9
// Package.swift — SPM package for Accord iOS

import PackageDescription

let package = Package(
    name: "Accord",
    platforms: [
        .iOS(.v17),
    ],
    products: [
        .library(name: "AccordCore", targets: ["AccordCore"]),
        .library(name: "AccordApp", targets: ["AccordApp"]),
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
        // Full SwiftUI app (models, views, services)
        .target(
            name: "AccordApp",
            dependencies: ["AccordCore"],
            path: "Accord",
            exclude: ["AccordCore.swift"],
            sources: [
                "AccordApp.swift",
                "Models",
                "Views",
                "Services",
            ]
        ),
    ]
)
