#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdint>
#include <cstdint>

struct cred_uid_info {
	uint32_t uid; /* real UID of the task */
	uint32_t gid; /* real GID of the task */
	uint32_t suid; /* saved UID of the task */
	uint32_t sgid; /* saved GID of the task */
	uint32_t euid; /* effective UID of the task */
	uint32_t egid; /* effective GID of the task */
	uint32_t fsuid; /* UID for VFS ops */
	uint32_t fsgid; /* GID for VFS ops */
};

struct InitCredResult {
	std::vector<uint8_t> head;
	size_t atomic_usage_size = 0;
	size_t securebits_size = 0;
	int cap_cnt = 0;
	uint64_t cap_ability_max = 0;
};

class InitCredSearcher {
public:
	InitCredSearcher(const std::vector<char>& file_buf, size_t cred_uid_offset);
	~InitCredSearcher();

public:
	bool init();
	InitCredResult get_init_cred_result();

private:
	template <typename Head4T, typename Head8T>
	std::vector<InitCredResult> build_usage_candidates_impl();

	std::vector<InitCredResult> build_atomic4usage_candidate();
	std::vector<InitCredResult> build_atomic8usage_candidate();

	int get_cap_cnt();

	const std::vector<char>& m_file_buf;
	size_t m_cred_uid_offset = 0;
	InitCredResult m_init_cred_result;
};