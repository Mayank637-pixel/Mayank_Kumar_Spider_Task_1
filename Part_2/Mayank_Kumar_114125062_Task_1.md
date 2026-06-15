# Part 2 – AFL++ Harness Repair and Vulnerability Discovery

## Objective

The goal of this task was to analyze the provided AFL++ harness.

We need to identify why AFL++ was making progress.

The next step is to repair the harness.

Then we will use the repaired harness to discover vulnerabilities in the target license validation library.

## Understanding the Original Harness

The provided harness was very small.

It only performed an operations:

* Read the input file.

* Initialize the license system.

* Pass the input directly to `validate_license()`.

The original harness did not do any preprocessing or repair of mutated inputs.

It just called the target function.

As a result many AFL++ mutations were rejected by validation checks.

They never reached parser logic.

## Understanding the License Format

Before repairing the harness I looked at how the license file's structured.

The file contains:

* A **CRC32 checksum** (4 bytes)

* A **Version** (2 bytes)

* **Flags** (2 bytes)

After the header the file has TLV chunks.

A TLV chunk consists of:

* **Type**. Identifies the chunk

* **Length**. Size of the data

* **Value**. Actual chunk data

Examples of types include:

* `OWNER`

* `LEVEL`

* `EXPIRY`

* `FEATURES`

* `HWID`

* `SIGNATURE`

* `OVERRIDE`

The parser reads each chunk. Calls a corresponding processing function.

## Problem 1 – CRC Validation Gate

During fuzzing AFL++ continuously mutates input files.

Whenever a mutation changes the file contents the stored CRC32 checksum becomes invalid.

The application verifies the CRC before processing the remaining data.

So the execution flow looked like this:

* Mutated Input → CRC Check Failure → Input Rejected → Poor Coverage

Many mutated inputs never reached parsing logic.

### CRC Repair

To solve this issue I modified the harness.

It now automatically recalculates the CRC32 checksum before calling the target.

The repaired harness computes a CRC32 value.

It writes this value back into the four bytes.

Here is an example fix:

* `uint32_t crc = calculate_crc32(buf. 4 Len. 4);`

* `Write_uint32_be(buf crc);`

This allowed AFL++ mutations to pass the CRC validation stage.

## Problem 2 – Signature Validation Gate

After repairing the CRC I observed that many inputs were still being rejected.

This happened during signature verification.

The license format contains a `SIGNATURE` chunk.

It is verified near the end of validation.

Mutated inputs often failed this verification stage.

They were rejected before reaching parser logic.

### Signature Repair

To improve reachability I analyzed the signature handling code.

I extended the harness to:

* Locate the `SIGNATURE` chunk.

* Recalculate the signature value.

* Replace the existing signature with the value.

* Recalculate CRC32 after all modifications.

This prevented mutated inputs from being rejected.

It increased parser reachability.

## Additional Harness Improvements

The original harness initialized the license system.

However it never cleaned it up.

The repaired harness adds cleanup.

This ensures resources are released correctly between executions:

* `init_license_system();`

* `validate_license(buf ;`

* `cleanup_license_system();`

This makes the harness much more stable.

It is suitable for fuzzing sessions.

## Build Configuration Investigation

While debugging the fuzzing environment I reviewed the Makefile.

The original Makefile used a compiler:

* `CC_FUZZ = gcc`

AFL++ requires compiler instrumentation.

This is necessary for coverage-guided fuzzing.

I investigated AFL++ compiler wrappers:

* `CC_FUZZ = afl-clang-lto`

I also reviewed the optimization settings.

The original configuration used `-O1`.

During debugging and crash analysis I experimented with optimization levels.

This made AddressSanitizer reports easier to reproduce and analyze.

## Reachability Verification

After repairing the harness I added debug output.

This helped me observe parser execution:

* `printf("[+] Chunk type=%u len=%u\n" type, len);`

This confirmed that AFL++ was successfully reaching parsing functions.

The output showed traversal of multiple chunk handlers.

These included `OWNER` `LEVEL` `EXPIRY` `FEATURES` `HWID` `SIGNATURE` and `OVERRIDE` processing paths.

## Vulnerability Analysis

While reviewing the parser implementation I identified code:

* ` int process_override(...) {`

* `char override_buffer[64];`

* `memcpy(override_buffer, data, len); }`

The destination buffer is fixed at exactly 64 bytes.

However `len` is derived from attacker-controlled input.

No bounds check is performed before copying.

This strongly indicated a stack-buffer-overflow vulnerability.

## Seed Investigation

The original seed file contained:

* `OWNER`

* `LEVEL`

* `EXPIRY`

* `FEATURES`

* `HWID`

* `SIGNATURE`

However it did not contain an `OVERRIDE` chunk.

Since the vulnerable code existed inside `process_override()` I manually studied the TLV structure.

I constructed an input containing an `OVERRIDE` chunk.

The `OVERRIDE` chunk was created with a payload length than the destination buffer size.

This was used to verify whether the suspected vulnerability was actually reachable.

## AFL++ Results

After repairing the harness AFL++ was executed against the target application.

The repaired harness significantly improved reachability.

It allowed AFL++ to explore parser paths.

Multiple crashes were discovered.

Crash analysis showed that all discovered crashes originated from:

* `process_override()`

* `license.c:216`

## AddressSanitizer Report

AddressSanitizer reported the fault:

* `ERROR: AddressSanitizer: stack-buffer-overflow`

* `WRITE of size 310`

* `process_override()`

* `license.c:216`

This definitively confirmed that memory outside the stack buffer was being overwritten.

## Root Cause

The vulnerable code performs a raw memory copy:

* `char override_buffer[64];`

* `memcpy(override_buffer, data, len);`

When `len > 64` the copy operation blindly writes beyond the bounds of `override_buffer`.

This results in a stack-buffer-overflow detected by AddressSanitizer.

## Impact

An attacker can provide an `OVERRIDE` chunk.

Its payload length can exceed the size of the destination buffer.

Because no bounds checking is performed memory outside the stack buffer can be overwritten.

This causes memory corruption and program crashes.

## The original harness was unable to support fuzzing.

Validation gates rejected AFL++ mutations before they reached deeper parsing logic.

To improve fuzzing effectiveness:

* CRC32 repair was implemented.

* Signature verification handling was repaired.

* Proper memory cleanup was added.

* Build configuration and instrumentation were investigated.

* Parser reachability was verified.

Using the repaired harness and AFL++ multiple crashes were discovered.

Crash analysis identified a *stack-buffer-overflow** vulnerability, in `process_override()`.

It was caused by a memcpy` into a fixed-size 64-byte stack buffer.

The vulnerability was successfully. Confirmed using AddressSanitizer.
