// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

// Standalone fuzzer driver for platforms where libFuzzer cannot be linked
// (e.g., macOS with Homebrew LLVM where the fuzzer runtime has ABI mismatches).
// Reads each command-line argument as a file, feeds it to LLVMFuzzerTestOneInput.

#include <cstdint>
#include <cstdlib>
#include <print>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size);

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::println(stderr, "Usage: {} <input_file> [input_file ...]", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        FILE* f = fopen(argv[i], "rb");
        if (!f) {
            perror(argv[i]);
            continue;
        }
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        if (len < 0) {
            std::println(stderr, "{}: ftell failed", argv[i]);
            fclose(f);
            continue;
        }
        if (len > 10 * 1024 * 1024) {
            std::println(stderr, "{}: too large ({} bytes, max 10 MB)", argv[i], len);
            fclose(f);
            continue;
        }
        fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> buf(static_cast<size_t>(len));
        if (len > 0) {
            size_t n = fread(buf.data(), 1, static_cast<size_t>(len), f);
            buf.resize(n);
        }
        fclose(f);
        LLVMFuzzerTestOneInput(buf.data(), buf.size());
        std::println(stderr, "OK: {} ({} bytes)", argv[i], buf.size());
    }
    return 0;
}
