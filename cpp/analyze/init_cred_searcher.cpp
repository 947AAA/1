#include "init_cred_searcher.h"
#include <vector>
#include <string_view>
#include <algorithm>
#include <cstring>
#include <cstring>
#include <cstring>

#define ATOMIC_INIT_4						4
#define SECUREBITS_DEFAULT			0

#define CAP_FULL_SET								0x1FFFFFFFFFULL
#define CAP_FULL_SET_3_16_0					0x3FFFFFFFFFULL
#define CAP_FULL_SET_HUAWEI_4_9_X		0x7FFFFFFFFFULL
#define CAP_FULL_SET_5_8_0						0xFFFFFFFFFFULL
#define CAP_FULL_SET_5_9_0						0x1FFFFFFFFFFULL

namespace {
#pragma pack(push, 1)
template <typename UsageT, typename SecurebitsT>
struct cred_model {
	UsageT atomic_usage = ATOMIC_INIT_4;
	cred_uid_info uid_info = { 0 };
	SecurebitsT securebits = SECUREBITS_DEFAULT;
};

struct cred_cap_info4 {
	uint64_t cap_inheritable; /* caps our children can inherit */
	uint64_t cap_permitted;	/* caps we're permitted */
	uint64_t cap_effective;	/* caps we can actually use */
	uint64_t cap_bset;	/* capability bounding set */
};

#pragma pack(pop)

template <typename T>
static void append_bytes(std::vector<uint8_t>& out, const T& obj) {
	const auto* p = reinterpret_cast<const uint8_t*>(&obj);
	out.insert(out.end(), p, p + sizeof(T));
}

template <typename HeadT, typename CapT>
static std::vector<uint8_t> build_pattern(const HeadT& head_obj, const CapT& cap_obj) {
	std::vector<uint8_t> buf;
	buf.reserve(sizeof(HeadT) + sizeof(CapT));
	append_bytes(buf, head_obj);
	append_bytes(buf, cap_obj);
	return buf;
}

template <typename HeadT, typename CapT>
void add_candidate(std::vector<InitCredResult>& out,
	const HeadT& head_obj,
	const CapT& cap_obj,
	int cap_cnt,
	uint64_t cap_ability_max) {
	InitCredResult s{};
	s.head = build_pattern(head_obj, cap_obj);
	s.atomic_usage_size = sizeof(decltype(head_obj.atomic_usage));
	s.securebits_size = sizeof(head_obj.securebits);
	s.cap_cnt = cap_cnt;
	s.cap_ability_max = cap_ability_max;
	out.push_back(std::move(s));
}
}

using cred_model_4usage_u_4securebits = cred_model<uint32_t, uint32_t>;
using cred_model_4usage_u_8securebits = cred_model<uint32_t, uint64_t>;
using cred_model_8usage_u_4securebits = cred_model<uint64_t, uint32_t>;
using cred_model_8usage_u_8securebits = cred_model<uint64_t, uint64_t>;

InitCredSearcher::InitCredSearcher(const std::vector<char>& file_buf, size_t cred_uid_offset) : m_file_buf(file_buf), m_cred_uid_offset(cred_uid_offset) {
}

InitCredSearcher::~InitCredSearcher() {}

bool InitCredSearcher::init() {
	std::vector<InitCredResult> search_candidate = m_cred_uid_offset == 4 ? build_atomic4usage_candidate() : build_atomic8usage_candidate();
	for (auto& item : search_candidate) {
		const auto& pat = item.head;
		if (pat.empty()) continue;
		for (size_t off = 0; off + pat.size() <= m_file_buf.size(); off += 4) {
			if (memcmp(m_file_buf.data() + off, pat.data(), pat.size()) == 0) {
				m_init_cred_result = item;
				std::cout << "init_cred offset:" << off << std::endl;
				return true;
			}
		}
	}
	std::cout << "[ERROR] init cred failed" << std::endl;
	return false;
}

InitCredResult InitCredSearcher::get_init_cred_result() { return m_init_cred_result; }

template <typename Head4T, typename Head8T>
std::vector<InitCredResult> InitCredSearcher::build_usage_candidates_impl() {
	Head4T head_u4;
	Head8T head_u8;
	std::vector<InitCredResult> out;
	uint64_t cap_max_arr[] = { CAP_FULL_SET_5_9_0, CAP_FULL_SET_5_8_0, CAP_FULL_SET_3_16_0, CAP_FULL_SET_HUAWEI_4_9_X, CAP_FULL_SET };
	int cap_cnt = get_cap_cnt();
	for (auto cap_max : cap_max_arr) {
		cred_cap_info4 cap4{};
		cap4.cap_permitted = cap_max;
		cap4.cap_effective = cap_max;
		cap4.cap_bset = cap_max;
		add_candidate(out, head_u4, cap4, cap_cnt, cap_max);
		add_candidate(out, head_u4, cap4, cap_cnt, cap_max);
		add_candidate(out, head_u8, cap4, cap_cnt, cap_max);
		add_candidate(out, head_u8, cap4, cap_cnt, cap_max);
	}
	return out;
}

std::vector<InitCredResult> InitCredSearcher::build_atomic4usage_candidate() {
	return build_usage_candidates_impl<
		cred_model_4usage_u_4securebits,
		cred_model_4usage_u_8securebits>();
}

std::vector<InitCredResult> InitCredSearcher::build_atomic8usage_candidate() {
	return build_usage_candidates_impl<
		cred_model_8usage_u_4securebits,
		cred_model_8usage_u_8securebits>();
}

int InitCredSearcher::get_cap_cnt() {
	static constexpr std::string_view key = "CapAmb:";
	auto it = std::search(m_file_buf.begin(), m_file_buf.end(), key.begin(), key.end());
	return it == m_file_buf.end() ? 4 : 5;
}