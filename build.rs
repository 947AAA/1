use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cpp_root = manifest_dir.join("../Lite_version/src/patch_kernel_root");

    let asmjit_root = cpp_root.join("3rdparty/asmjit2-src/src");
    let capstone_include = cpp_root.join("3rdparty/capstone-5.0.7/include");
    let capstone_src = cpp_root.join("3rdparty/capstone-5.0.7/src");

    // bridge.cpp is at Cargo project root
    let bridge_cpp = manifest_dir.join("bridge.cpp");

    // ---- C++ project sources ----
    let project_srcs: Vec<String> = [
        "analyze/kallsyms_lookup_name.cpp",
        "analyze/kallsyms_lookup_name_4_6_0.cpp",
        "analyze/kallsyms_lookup_name_6_1_0.cpp",
        "analyze/kallsyms_lookup_name_6_1_42.cpp",
        "analyze/kallsyms_lookup_name_6_1_60.cpp",
        "analyze/kallsyms_lookup_name_6_4_0.cpp",
        "analyze/kallsyms_lookup_name_6_12_0.cpp",
        "analyze/init_cred_searcher.cpp",
        "analyze/kernel_symbol_parser.cpp",
        "analyze/kernel_version_parser.cpp",
        "analyze/symbol_analyze.cpp",
        "patch_current_avc_check.cpp",
        "patch_avc_denied.cpp",
        "patch_audit_log_start.cpp",
        "patch_base.cpp",
        "patch_do_execve.cpp",
        "patch_filldir64.cpp",
        "patch_kernel_root.cpp",
    ].iter().map(|f| cpp_root.join(f).to_string_lossy().to_string()).collect();

    // ---- AsmJit sources (full: ARM64 + Core, exclude x86 for smaller binary) ----
    let asmjit_srcs: Vec<PathBuf> = [
        "asmjit/arm/a64assembler.cpp",
        "asmjit/arm/a64builder.cpp",
        "asmjit/arm/a64compiler.cpp",
        "asmjit/arm/a64emithelper.cpp",
        "asmjit/arm/a64formatter.cpp",
        "asmjit/arm/a64func.cpp",
        "asmjit/arm/a64instapi.cpp",
        "asmjit/arm/a64instdb.cpp",
        "asmjit/arm/a64operand.cpp",
        "asmjit/arm/a64rapass.cpp",
        "asmjit/arm/armformatter.cpp",
        "asmjit/core/archtraits.cpp",
        "asmjit/core/assembler.cpp",
        "asmjit/core/builder.cpp",
        "asmjit/core/codeholder.cpp",
        "asmjit/core/codewriter.cpp",
        "asmjit/core/compiler.cpp",
        "asmjit/core/constpool.cpp",
        "asmjit/core/cpuinfo.cpp",
        "asmjit/core/emithelper.cpp",
        "asmjit/core/emitter.cpp",
        "asmjit/core/emitterutils.cpp",
        "asmjit/core/environment.cpp",
        "asmjit/core/errorhandler.cpp",
        "asmjit/core/formatter.cpp",
        "asmjit/core/func.cpp",
        "asmjit/core/funcargscontext.cpp",
        "asmjit/core/globals.cpp",
        "asmjit/core/inst.cpp",
        "asmjit/core/instdb.cpp",
        "asmjit/core/jitallocator.cpp",
        "asmjit/core/jitruntime.cpp",
        "asmjit/core/logger.cpp",
        "asmjit/core/operand.cpp",
        "asmjit/core/osutils.cpp",
        "asmjit/core/ralocal.cpp",
        "asmjit/core/rapass.cpp",
        "asmjit/core/rastack.cpp",
        "asmjit/core/string.cpp",
        "asmjit/core/support.cpp",
        "asmjit/core/target.cpp",
        "asmjit/core/type.cpp",
        "asmjit/core/virtmem.cpp",
        "asmjit/core/zone.cpp",
        "asmjit/core/zonehash.cpp",
        "asmjit/core/zonelist.cpp",
        "asmjit/core/zonestack.cpp",
        "asmjit/core/zonetree.cpp",
        "asmjit/core/zonevector.cpp",
    ].iter().map(|f| asmjit_root.join(f)).collect();

    // ---- Capstone sources (AArch64 only) ----
    let capstone_srcs: Vec<PathBuf> = [
        "arch/AArch64/AArch64BaseInfo.c",
        "arch/AArch64/AArch64Disassembler.c",
        "arch/AArch64/AArch64InstPrinter.c",
        "arch/AArch64/AArch64Mapping.c",
        "arch/AArch64/AArch64Module.c",
        "cs.c",
        "Mapping.c",
        "MCInst.c",
        "MCInstrDesc.c",
        "MCRegisterInfo.c",
        "SStream.c",
        "utils.c",
    ].iter().map(|f| capstone_src.join(f)).collect();

    // ---- Build C++ (bridge + project + asmjit) ----
    let mut cpp_build = cc::Build::new();
    cpp_build
        .cpp(true)
        .std("c++20")
        .flag("-fPIC")
        .include(&cpp_root)
        .include(&asmjit_root)
        .include(&capstone_include)
        .define("ASMJIT_STATIC", None)
        .define("NDEBUG", None)
        .define("CAPSTONE_HAS_ARM64", None)
        .define("CAPSTONE_USE_SYS_DYN_MEM", None);

    cpp_build.file(&bridge_cpp);
    for f in &project_srcs { cpp_build.file(f); }
    for f in &asmjit_srcs { cpp_build.file(f); }
    cpp_build.compile("patch_core");

    // ---- Build C (Capstone) ----
    // ---- Build C (Capstone) ----
    let mut c_build = cc::Build::new();
    c_build
        .std("c11")
        .flag("-fPIC")
        .include(&capstone_include)
        .include(&capstone_src)
        .define("CAPSTONE_HAS_ARM64", None)
        .define("CAPSTONE_USE_SYS_DYN_MEM", None);

    for f in &capstone_srcs { c_build.file(f); }
    c_build.compile("capstone_core");

    // Rerun if C++ sources change
    println!("cargo::rerun-if-changed=bridge.cpp");
    println!("cargo::rerun-if-changed=../Lite_version/src/patch_kernel_root");
}
