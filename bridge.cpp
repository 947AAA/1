#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" {

extern int patch_kernel_main_impl(const char* input_path, const char* output_path, const char* root_key);

int patch_kernel(const char* input_path, const char* output_path, const char* root_key) {
    if (!input_path || !output_path) {
        fprintf(stderr, "[ERROR] input_path and output_path are required\n");
        return -1;
    }
    fprintf(stdout, "Android SKRoot (Lite) ARM64 Linux Kernel Root Patcher V12\n\n");
    return patch_kernel_main_impl(input_path, output_path, root_key);
}

}
