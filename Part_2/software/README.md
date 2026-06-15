# Part 2 — Fix the Fuzzer

Someone wrote an AFL++ harness for a license file parser. It compiles. AFL++ launches.
Nothing gets found.

Your job: figure out why it's broken and fix it. When it's working, AFL++ will
find a crash in `license.c`.

---

## The target

`license.c` parses a binary license format. Read the source — understanding the
format is part of the challenge.

---

## Setup

```bash
# Install AFL++ if needed
sudo apt-get install afl++

# Generate seed corpus
python3 gen_corpus.py

# Build
make

# System tuning AFL++ will ask for
echo core | sudo tee /proc/sys/kernel/core_pattern

# Run
afl-fuzz -i corpus/ -o findings/ -- ./fuzzer @@
```

Crashes land in `findings/default/crashes/`.

---

## Files

| File            | Purpose                        |
|-----------------|--------------------------------|
| `license.c/h`   | Target — do not modify         |
| `afl_harness.c` | Harness — fix this             |
| `Makefile`      | Build — fix this               |
| `test_license.c`| Unit tests, useful for reference |
| `gen_corpus.py` | Generates `corpus/seed01.bin`  |
