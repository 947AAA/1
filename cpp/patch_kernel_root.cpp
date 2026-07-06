#include <unistd.h>
#include "patch_kernel_root.h"
#include "analyze/base_func.h"
#include "analyze/symbol_analyze.h"
#include "patch_do_execve.h"
#include "patch_current_avc_check.h"
#include "patch_avc_denied.h"
#include "patch_audit_log_start.h"
#include "patch_filldir64.h"

#include "3rdparty/find_mrs_register.h"
#include "3rdparty/find_imm_register_offset.h"
#include "3rdparty/find_adrp_target.h"

struct PatchKernelOffset {
	size_t cred_offset = 0;
	size_t cred_uid_offset = 0;
	size_t seccomp_offset = 0;
	uint64_t huawei_kti_addr = 0;
};

struct PatchKernelResult {
	bool patched = false;
	size_t root_key_start = 0;
};


bool parser_cred_offset(const std::vector<char>& file_buf, const SymbolRegion &symbol, size_t& cred_offset) {
	using namespace a64_find_mrs_register;
	std::vector<track_reg_info>track_info;
	if (!find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, track_info)) return false;
	cred_offset = 0;
	for (auto& t : track_info) {
		if (t.load_offset > 0x400) { cred_offset = t.load_offset; break; }
	}
	return cred_offset > 0;
}

bool parse_cred_uid_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, size_t cred_offset, size_t& cred_uid_offset) {
	using namespace a64_find_imm_register_offset;
	cred_uid_offset = 0;
	KernelVersionParser kernel_ver(file_buf);
	size_t min_off = 8;
	if (kernel_ver.is_kernel_version_less("6.6.8")) min_off = 4;

	std::vector<int64_t> candidate_offsets;
	if (!find_imm_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, candidate_offsets)) return false;

	auto it = std::find(candidate_offsets.begin(), candidate_offsets.end(), cred_offset);
	if (it != candidate_offsets.end()) {
		for (++it; it != candidate_offsets.end(); ++it) {
			if (*it > 0x20 || *it < min_off) continue;
			cred_uid_offset = *it;
			break;
		}
	}
	return cred_uid_offset != 0;
}

bool parser_seccomp_offset(const std::vector<char>& file_buf, const SymbolRegion& symbol, size_t& seccomp_offset) {
	using namespace a64_find_mrs_register;
	std::vector<track_reg_info>track_info;
	if (!find_current_task_next_register_offset(file_buf, symbol.offset, symbol.offset + symbol.size, track_info)) return false;
	seccomp_offset = 0;
	for (auto& t : track_info) {
		if (t.load_offset > 0x400) { seccomp_offset = t.load_offset; break; }
	}
	return seccomp_offset > 0;
}

bool parser_huawei_kti_addr(const std::vector<char>& file_buf, const SymbolRegion& symbol, uint64_t& kti_addr) {
	using namespace a64_find_adrp_target;
	if (symbol.size == 0) return false;
	if (!find_adrp_target(file_buf, symbol.offset, symbol.offset + symbol.size, kti_addr)) return false;
	return kti_addr > 0;
}

void cfi_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	if (sym.__cfi_check.offset) PATCH_AND_CONSUME(sym.__cfi_check, patch_ret_cmd(file_buf, sym.__cfi_check.offset, vec_patch_bytes_data));
	patch_ret_cmd(file_buf, sym.__cfi_check_fail, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__cfi_slowpath_diag, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__cfi_slowpath, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail_abort, vec_patch_bytes_data);
	patch_ret_cmd(file_buf, sym.__ubsan_handle_cfi_check_fail, vec_patch_bytes_data);
	patch_ret_1_cmd(file_buf, sym.report_cfi_failure, vec_patch_bytes_data);
}

void huawei_bypass(const std::vector<char>& file_buf, KernelSymbolOffset &sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	patch_ret_0_cmd(file_buf, sym.hkip_check_uid_root, vec_patch_bytes_data);
	patch_ret_0_cmd(file_buf, sym.hkip_check_gid_root, vec_patch_bytes_data);
	patch_ret_0_cmd(file_buf, sym.hkip_check_xid_root, vec_patch_bytes_data);
}

PatchKernelResult patch_kernel_handler(const std::vector<char>& file_buf, const PatchKernelOffset& off, KernelSymbolOffset& sym, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	KernelVersionParser kernel_ver(file_buf);
	PatchBase patchBase(file_buf, off.cred_uid_offset, { .kti_addr = off.huawei_kti_addr });
	PatchDoExecve patchDoExecve(patchBase, sym);
	PatchCurrentAvcCheck patchCurrentAvcCheck(patchBase);
	PatchAvcDenied patchAvcDenied(patchBase, sym.avc_denied);
	PatchAuditLogStart patchAuditLogStart(patchBase, sym.audit_log_start);
	PatchFilldir64 patchFilldir64(patchBase, sym.filldir64);

	bool patched = true;
	PatchKernelResult r;
	if (kernel_ver.is_kernel_version_less("6.1.0")) {
		SymbolRegion next_empty_region = { 0x200, 0x300 };
		if (sym.__cfi_check.offset && sym.__cfi_check.size > next_empty_region.size) next_empty_region = sym.__cfi_check;
		auto start_b_location = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, 4);
		r.root_key_start = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, patchDoExecve.patch_do_execve(next_empty_region, off.cred_offset, off.seccomp_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, next_empty_region, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchFilldir64.patch_filldir64_core(next_empty_region, vec_patch_bytes_data));
		auto current_avc_check_bl_func = next_empty_region.offset;
		PATCH_AND_CONSUME(next_empty_region, patchCurrentAvcCheck.patch_current_avc_check_bl_func(next_empty_region, off.cred_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchAvcDenied.patch_avc_denied(next_empty_region, current_avc_check_bl_func, vec_patch_bytes_data));
		PATCH_AND_CONSUME(next_empty_region, patchAuditLogStart.patch_audit_log_start(next_empty_region, current_avc_check_bl_func, vec_patch_bytes_data));
		auto end_b_location = next_empty_region.offset;
		patchBase.patch_jump(start_b_location, end_b_location, vec_patch_bytes_data);
	} else if (sym.die.offset && sym.__drm_puts_coredump.offset && sym.__drm_printfn_coredump.offset) {
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patch_ret_cmd(file_buf, sym.__drm_printfn_coredump.offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_puts_coredump, patch_ret_cmd(file_buf, sym.__drm_puts_coredump.offset, vec_patch_bytes_data));
		r.root_key_start = sym.die.offset;
		PATCH_AND_CONSUME(sym.die, patchDoExecve.patch_do_execve(sym.die, off.cred_offset, off.seccomp_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_filldir64_root_key_guide(r.root_key_start, sym.die, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.die, patchFilldir64.patch_jump(sym.die.offset, sym.__drm_puts_coredump.offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_puts_coredump, patchFilldir64.patch_filldir64_core(sym.__drm_puts_coredump, vec_patch_bytes_data));
		auto current_avc_check_bl_func = sym.__drm_printfn_coredump.offset;
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchCurrentAvcCheck.patch_current_avc_check_bl_func(sym.__drm_printfn_coredump, off.cred_offset, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAvcDenied.patch_avc_denied(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
		PATCH_AND_CONSUME(sym.__drm_printfn_coredump, patchAuditLogStart.patch_audit_log_start(sym.__drm_printfn_coredump, current_avc_check_bl_func, vec_patch_bytes_data));
	} else {
		patched = false;
	}
	r.patched = patched;
	return r;
}

void write_all_patch(const char* file_path, std::vector<patch_bytes_data>& vec_patch_bytes_data) {
	for (auto& item : vec_patch_bytes_data) {
		std::shared_ptr<char> spData(new (std::nothrow) char[item.str_bytes.length() / 2], std::default_delete<char[]>());
		hex2bytes((uint8_t*)item.str_bytes.c_str(), (uint8_t*)spData.get());
		if (!write_file_bytes(file_path, item.write_addr, spData.get(), item.str_bytes.length() / 2)) {
			std::cout << "写入文件发生错误" << std::endl;
		}
	}
	if (vec_patch_bytes_data.size()) std::cout << "Done." << std::endl;
}


static int do_patch(const char* input_path, const char* output_path, const char* root_key) {
	std::vector<char> file_buf = read_file_buf(input_path);
	if (!file_buf.size()) {
		fprintf(stderr, "Fail to open file: %s\n", input_path);
		return -1;
	}

	SymbolAnalyze symbol_analyze(file_buf);
	if (!symbol_analyze.analyze_kernel_symbol()) {
		fprintf(stderr, "Failed to analyze kernel symbols\n");
		return -1;
	}
	KernelSymbolOffset sym = symbol_analyze.get_symbol_offset();

	PatchKernelOffset off;
	if (!parser_cred_offset(file_buf, sym.sys_getuid, off.cred_offset)) {
		fprintf(stderr, "Failed to parse cred offset\n");
		return -1;
	}
	if (!parse_cred_uid_offset(file_buf, sym.sys_getuid, off.cred_offset, off.cred_uid_offset)) {
		fprintf(stderr, "Failed to parse cred uid offset\n");
		return -1;
	}
	printf("cred uid offset: %zu\n", off.cred_uid_offset);

	if (!parser_seccomp_offset(file_buf, sym.prctl_get_seccomp, off.seccomp_offset)) {
		fprintf(stderr, "Failed to parse seccomp offset\n");
		return -1;
	}
	printf("cred offset: %zu\n", off.cred_offset);
	printf("seccomp offset: %zu\n", off.seccomp_offset);

	parser_huawei_kti_addr(file_buf, sym.kti_randomize_init, off.huawei_kti_addr);
	if (off.huawei_kti_addr) printf("kti addr: 0x%lx\n", (unsigned long)off.huawei_kti_addr);

	std::vector<struct patch_bytes_data> vec_patch_bytes_data;
	cfi_bypass(file_buf, sym, vec_patch_bytes_data);
	huawei_bypass(file_buf, sym, vec_patch_bytes_data);

	PatchKernelResult pr = patch_kernel_handler(file_buf, off, sym, vec_patch_bytes_data);
	if (!pr.patched) {
		fprintf(stderr, "Failed to find hook start addr\n");
		return -1;
	}

	std::string str_root_key;
	if (root_key && strlen(root_key) > 0) {
		str_root_key = root_key;
	} else {
		str_root_key = generate_random_str(ROOT_KEY_LEN);
	}
	std::string write_key = str_root_key;
	patch_data(file_buf, pr.root_key_start, (void*)write_key.c_str(), write_key.length() + 1, vec_patch_bytes_data);

	printf("# Root Key: %s\n\n", str_root_key.c_str());

	printf("# Writing patches to: %s\n", output_path);
	if (strcmp(input_path, output_path) != 0) {
		FILE* in = fopen(input_path, "rb");
		if (!in) { fprintf(stderr, "Failed to open input for copy\n"); return -1; }
		FILE* out = fopen(output_path, "wb");
		if (!out) { fclose(in); fprintf(stderr, "Failed to open output for copy\n"); return -1; }
		char buf[65536];
		size_t n;
		while ((n = fread(buf, 1, sizeof(buf), in)) > 0) fwrite(buf, 1, n, out);
		fclose(in); fclose(out);
	}
	write_all_patch(output_path, vec_patch_bytes_data);
	return 0;
}

extern "C" int patch_kernel_main_impl(const char* input_path, const char* output_path, const char* root_key) {
	return do_patch(input_path, output_path, root_key);
}
