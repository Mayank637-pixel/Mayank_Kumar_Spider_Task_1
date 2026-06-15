# Part 1 — Find the Bugs

`xarinfo` is a command-line tool that parses a proprietary binary archive format
and prints a summary of its contents. It has memory safety bugs.

Your job: find them.

How you approach this — what tools you choose, how you set up your harness, how
you reason about the format — is what gets evaluated, not just the final crash/vuln

---

## Build

```bash
# Standard build
make

# Recommended: build with sanitizers enabled
make asan

# Run the bundled test suite to see what valid inputs look like
make test
```

## Usage

```bash
./xarinfo <file.xar>
./xarinfo --debug <file.xar>
```

## The format

Files start with the magic bytes `XAR!`. Beyond that, read the source.

---

## Files

| File        | Description              |
|-------------|--------------------------|
| `parser.c`  | Parser — this is the target |
| `parser.h`  | Structs and constants    |
| `main.c`    | Entry point              |
| `utils.c/h` | I/O and logging helpers  |