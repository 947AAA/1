#!/bin/bash
set -e
S=SKRoot/Lite_version/src/patch_kernel_root

# 1) patch_kernel_root.h: fix IF_EXIT, remove <filesystem>
sed -i 's|printf("\[ERROR\] Patch empty addr!\\n"); system("pause"); exit(0)|fprintf(stderr, "[ERROR] Patch empty addr!\\n"); _exit(1)|g' $S/patch_kernel_root.h
sed -i '/<filesystem>/d' $S/patch_kernel_root.h

# 2) patch_base.cpp: prepend <unistd.h> for _exit()
{
    echo '#include <unistd.h>'
    cat $S/patch_base.cpp
} > /tmp/tmp.cpp && mv /tmp/tmp.cpp $S/patch_base.cpp

# 3) init_cred_searcher.h: add <cstdint> after <vector>
sed -i '/^#include <vector>/a\#include <cstdint>' $S/analyze/init_cred_searcher.h

# 4) init_cred_searcher.cpp: add <cstring> after <algorithm>
sed -i '/^#include <algorithm>/a\#include <cstring>' $S/analyze/init_cred_searcher.cpp

# 5) kernel_version_parser.cpp: add <cctype> after <cstring>
sed -i '/^#include <cstring>/a\#include <cctype>' $S/analyze/kernel_version_parser.cpp

echo "=== patches applied ==="
