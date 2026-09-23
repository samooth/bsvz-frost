const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bsvz_dep = b.dependency("bsvz", .{
        .target = target,
        .optimize = optimize,
    });
    const bsvz_mod = bsvz_dep.module("bsvz");

    // Module principal
    const frost_mod = b.addModule("bsvz-frost", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    frost_mod.addImport("bsvz", bsvz_mod);

    // Ejecutable de tests/demo
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("bsvz-frost", frost_mod);
    const exe = b.addExecutable(.{
        .name = "bsvz-frost-demo",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_demo = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the FROST demo");
    run_step.dependOn(&run_demo.step);

    // Tests
    const tests_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests_mod.addImport("bsvz-frost", frost_mod);
    tests_mod.addImport("bsvz", bsvz_mod);
    const tests = b.addTest(.{
        .root_module = tests_mod,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run FROST tests");
    test_step.dependOn(&run_tests.step);

    // Integration tests: naive threshold + Shamir against the real bsvz
    const naive_mod = b.createModule(.{
        .root_source_file = b.path("tests/naive_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    naive_mod.addImport("bsvz-frost", frost_mod);
    naive_mod.addImport("bsvz", bsvz_mod);
    const naive_tests = b.addTest(.{ .root_module = naive_mod });
    const run_naive_tests = b.addRunArtifact(naive_tests);
    test_step.dependOn(&run_naive_tests.step);

    const shamir_mod = b.createModule(.{
        .root_source_file = b.path("tests/shamir_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    shamir_mod.addImport("bsvz-frost", frost_mod);
    shamir_mod.addImport("bsvz", bsvz_mod);
    const shamir_tests = b.addTest(.{ .root_module = shamir_mod });
    const run_shamir_tests = b.addRunArtifact(shamir_tests);
    test_step.dependOn(&run_shamir_tests.step);

    // Interop test against official ZcashFoundation/frost-secp256k1 vectors
    const vector_mod = b.createModule(.{
        .root_source_file = b.path("tests/vector_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    vector_mod.addImport("bsvz-frost", frost_mod);
    const vector_tests = b.addTest(.{ .root_module = vector_mod });
    const run_vector_tests = b.addRunArtifact(vector_tests);
    test_step.dependOn(&run_vector_tests.step);

    // Negative / misuse-resistance tests
    const security_mod = b.createModule(.{
        .root_source_file = b.path("tests/security_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    security_mod.addImport("bsvz-frost", frost_mod);
    const security_tests = b.addTest(.{ .root_module = security_mod });
    const run_security_tests = b.addRunArtifact(security_tests);
    test_step.dependOn(&run_security_tests.step);

    // Distributed key generation tests
    const dkg_mod = b.createModule(.{
        .root_source_file = b.path("tests/dkg_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    dkg_mod.addImport("bsvz-frost", frost_mod);
    const dkg_tests = b.addTest(.{ .root_module = dkg_mod });
    const run_dkg_tests = b.addRunArtifact(dkg_tests);
    test_step.dependOn(&run_dkg_tests.step);

    // Interop test against official ZcashFoundation/frost-secp256k1 DKG vectors
    const dkg_vector_mod = b.createModule(.{
        .root_source_file = b.path("tests/dkg_vector_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    dkg_vector_mod.addImport("bsvz-frost", frost_mod);
    const dkg_vector_tests = b.addTest(.{ .root_module = dkg_vector_mod });
    const run_dkg_vector_tests = b.addRunArtifact(dkg_vector_tests);
    test_step.dependOn(&run_dkg_vector_tests.step);

    // Fuzz targets (smoke-run under `zig build test`; fuzzed via
    // `zig build --fuzz=NNN` or `zig build --fuzz`)
    // Skip in ReleaseFast/ReleaseSmall as libFuzzer expects different signature
    if (optimize != std.builtin.OptimizeMode.ReleaseFast and optimize != std.builtin.OptimizeMode.ReleaseSmall) {
        const fuzz_mod = b.createModule(.{
            .root_source_file = b.path("tests/fuzz_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        fuzz_mod.addImport("bsvz-frost", frost_mod);
        const fuzz_tests = b.addTest(.{ .root_module = fuzz_mod });
        const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
        test_step.dependOn(&run_fuzz_tests.step);
    }

    // ── WebAssembly module (wasm32-freestanding, browser + Node)
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm.zig"),
        .target = wasm_target,
        .optimize = optimize,
        .single_threaded = true,
        .link_libc = false,
    });
    wasm_mod.addImport("bsvz", bsvz_mod);
    wasm_mod.export_symbol_names = &[_][]const u8{
        "frost_version",
        "frost_seed",
        "frost_seed_buffer",
        "frost_random_bytes",
        "frost_alloc",
        "frost_dealloc",
        "frost_out_ptr",
        "frost_out_len",
        "frost_out_err",
        "frost_keygen",
        "frost_keypackage_from_share",
        "frost_round1_commit",
        "frost_round2_sign",
        "frost_aggregate",
        "frost_verify",
        "frost_reconstruct",
        "frost_dkg_part1",
        "frost_dkg_part2",
        "frost_dkg_part3",
    };
    const wasm_exe = b.addExecutable(.{
        .name = "bsvz-frost-wasm",
        .root_module = wasm_mod,
    });
    wasm_exe.entry = .disabled;
    wasm_exe.export_memory = true;
    const install_wasm = b.addInstallArtifact(wasm_exe, .{
        .dest_sub_path = "lib/bsvz-frost.wasm",
    });
    const wasm_step = b.step("wasm", "Build WebAssembly module into zig-out/bin/lib/bsvz-frost.wasm");
    wasm_step.dependOn(&install_wasm.step);
}
