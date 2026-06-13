# Spider Inductions: Task 1 Security Audit
**Name:** Mayank Kumar
**Roll Number:** 114125062
**Target:** `xarinfo` Proprietary Archive Parser

---

## 1. Executive Summary
While conducting the security audit of the xarinfo binary, I utilized AFL++ with the afl-clang-lto compiler. I also enabled AddressSanitizer (AFL_USE_ASAN=1) so it would be easier to catch the exact error types and pinpoint the vulnerable line numbers. The campaign found a total of 23 crashes, which I narrowed down to 4 unique vulnerabilities. 

## 2. Methodology
* **Fuzzer:** AFL++
* **Compiler:** afl-clang-lto (I preferred this over gcc or afl-clang-fast because it prevents collision errors when compiling multiple files. It does this by first converting the whole codebase into an Intermediate Representation, where a unique ID can be assigned to every block of code to form the bitmap. This isn't possible when files are compiled one by one. Another benefit is that it extracts its own dictionary during compilation, which is used later to speed up fuzzing).
* **Seed Generation:** I created a file named seed.xar inside the in/ folder containing the magic bytes XAR!. This minimal valid header is later mutated during fuzzing to generate different seeds.
* **Triage:** I got a total of 23 crashes, but not all of them were unique, as different mutated files can ultimately trigger the exact same vulnerable endpoint. In order to narrow them down to the true unique crashes, I used the following shell script:
               ```for file in out/default/crashes/id*; do
                echo "Crash: $file"
                ./xarinfo "$file" 2>&1 | grep "SUMMARY: AddressSanitizer"
               done```
        **Script Breakdown:** The `for` loop picks one crash file at a time (starting with `id...`) and stores it in a variable. I used the `$` symbol to get the exact path and feed it to `xarinfo`. The `2>&1` command is crucial: output is usually printed in two streams (normal output, and error output, which is the red text). To combine them, `2>&1` transfers the error output into the standard output stream. I then used `grep` to filter out everything except the lines containing "SUMMARY: AddressSanitizer". 
  
  By doing this, I analyzed all 23 crashes and was able to narrow them down into 4 unique crashes in a fraction of the time.

*** ---

## 3. Vulnerability Findings

### Finding 1: Integer Overflow Bypassing Header Size Check

* **Component:** `parser.c` (Lines 59 & 60) calling `read_u32_le` in `utils.c` (Line 111).

* **Vulnerability:** The program checks if a file is large enough by using `if (archive->file_size < XAR_HEADER_SIZE + archive->header.metadata_size)`.. Adding `XAR_HEADER_SIZE` and `archive->header.metadata_size` can cause an integer overflow.

* **Exploitation:** I looked at the `xar_header` struct. Found that `metadata_size` is read from the 12th byte of the file. A fuzzer made this byte a huge number, like 4 billion. When adding 24 (the header size) to this number it overflows and becomes a small number, like 25. So a tiny 26-byte file passes the check.

* **Impact:** The program then tries to read data than the file has. It calls `read_u32_le` to read 4 bytes from the byte.. Since the file is only 26 bytes long it tries to access memory that is not allocated (byte 26 and, beyond). This causes a heap-buffer-overflow error.

* **Fix:** To fix the integer overflow, we can force the computer to use a much larger memory limit for the math by casting the values to 64 bit integers. I would change the check to if ((uint64_t)archive->file_size < (uint64_t)XAR_HEADER_SIZE + (uint64_t)archive->header.metadata_size). The addition can safely handle numbers up to 18 quintillion without rolling over, by temporarily putting these numbers into a huge 64-bit “box”, completely neutralising the bug.

### Finding 2: Missing Bounds Check Causing Stack Buffer Overflow

* **Component:** `parser.c` (Line 71) uses the `memcpy` function.

* **Vulnerability:** The program does not check if the `archive->metadata.creator_length` is too big for the destination buffer before it copies the memory.

* **Exploitation:** The `comment` section is safe because it checks its boundaries.. The `creator` section does not have an `if` statement to check the size. The fuzzer changed the `creator_length` value to a big number, 2.7 Gigabytes. The program does not check if this is bigger than `sizeof(archive->metadata.creator)` which is 64 bytes. So the program tells `memcpy` to write this amount of data.

* **Impact:** The `memcpy` function tries to write a lot of data into the 64-byte `creator` array. The `archive` object is made in `main.c`. It is on the stack. So when `memcpy` writes much data it goes past the arrays boundaries and damages important memory on the stack. This causes the program to crash because of a stack buffer overflow. The `archive` object and the `creator` section are important here. The `creator` section is too small. The `archive` object is in a bad place, on the stack. The `memcpy` function and the `creator` section are the problems. The `archive->metadata.creator_length` is not. This causes all the trouble.

* **Fix:** We just need to add the missing bounds check before invoking memcpy. I would wrap line 71 in a simple if statement like if (archive->metadata.creator_length < sizeof(archive->metadata.creator)) so it safely rejects the data if it is larger than the 64 byte box.

### Finding 3: Missing Source Bounds Check Causing Heap Out-of-Bounds Read

* **Component:** `parser.c` (Line 86) uses the `memcpy` function.

* **Vulnerability:** The program checks the size of the destination buffer. It does not check if the source pointer (`comment_ptr + copy_len`) is within the boundaries of the file data.

* **Exploitation:** The fuzzer used a short file only 57 bytes but said the `comment_length` was 127. The check on line 83 makes sure the copy operation does not go past the 128-byte `comment` array. However it does not check if this is okay with the `archive->file_size`. So the program tells `memcpy` to read 127 bytes from the source pointer without checking.

* **Impact:** When `memcpy` tries to read 127 bytes from a file buffer that's only 57 bytes long it reads past the end of the file data. This makes the program read memory that it should not. AddressSanitizer stops the program because it is doing something it should not which is a heap-buffer-overflow, when `memcpy` tries to read past the end of the `parser.c` file data, in the `parser.c` component.

* **Fix:** The destination check works, but we also need to protect the source. I would add a second `if` statement before the copy operation to ensure that the amount of data we are trying to read (`comment_ptr + copy_len`) does not exceed the actual physical `archive->file_size`.


### Finding 4: Unvalidated Array Index Causing Segmentation Fault

* **Component:** `parser.c` (Lines 181 and 182).

* **Vulnerability:** The program uses data from a file to calculate an array index, which's the `meta_index`. The program does not check if this index is valid before it tries to access memory.

* **Exploitation:** The program calculates `meta_index` by adding two values: `archive->header.chunk_area_offset` and `chunk->metadata_ref`. These values come from the file. An attacker can control them. On line 181 the program adds these values together to get `meta_index`. If this index is very large it is still used by the program.

The program does not check if `meta_index` is less than `archive->file_size`. This means the program trusts the calculation and uses the index without checking if it is safe.

* **Impact:** On line 182 the program tries to read one byte from `archive->file_data` using the `meta_index`. If `meta_index` is very large the program tries to access memory that's not part of the file buffer. This causes a problem because the program is trying to access memory that it is not allowed to access.

This results in a Segmentation Fault, which's a fatal error that stops the program immediately. The `meta_index` is the problem here. The program uses the `meta_index` to access memory. It does not check if the `meta_index` is valid. This is the issue, with the `meta_index` and it causes the Segmentation Fault.

* **Fix:** We cannot blindly trust the index computed on the data in the mutated file. I would put a  check in there just before line 182 like if (meta_index >= archive->file_size) return -1; Just to make sure we never try to read memory outside the safe bounds of the file.
