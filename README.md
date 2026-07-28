# libpectra

A C library for parsing and analyzing Portable Executable (PE/COFF) binary files.

## Features

- Full PE32 and PE32+ (64-bit) format support
- 14-phase parsing pipeline: DOS → COFF → Optional → Sections → Strings → Symbols → Imports → Exports → Relocations → Debug → Resources → Validation → Cache → Resolution
- Import table parsing with ILT/IAT thunk resolution
- Export table parsing with forwarder detection
- Base relocation table parsing and target computation
- Debug directory with CodeView/PDB path extraction
- Recursive resource directory tree parsing
- COFF symbol table and string table support
- PE checksum computation and verification
- Cross-table validation with issue reporting
- Section entropy and anomaly analysis

## Building

```bash
make            # Build library, tools, and tests
make test       # Run test suite
make asan       # Build with AddressSanitizer
make fuzz       # Build fuzzer harnesses (requires libFuzzer)
make loc        # Count lines of code
```

## Usage

```c
#include "pectra.h"

// Parse a PE file
pe_ctx_t *ctx = pe_open(file_data, file_size);
if (!ctx) {
    // Handle error
}

// Query parsed data
const pe_coff_header_t *coff = pe_get_coff_header(ctx);
printf("Machine: %s\n", pe_get_machine_name(coff->machine));
printf("Sections: %u\n", pe_get_section_count(ctx));

// Iterate imports
uint32_t desc_count = pe_get_import_descriptor_count(ctx);
for (uint32_t d = 0; d < desc_count; d++) {
    printf("DLL: %s\n", pe_get_import_dll_name(ctx, d));
}

// Clean up
pe_close(ctx);
```

## API Overview

### Core Lifecycle
- `pe_open()` — Parse a PE binary (runs full pipeline)
- `pe_close()` — Release all resources
- `pe_get_error()` / `pe_get_error_message()` — Error reporting

### Header Access
- `pe_get_dos_header()` — DOS MZ header
- `pe_get_coff_header()` — COFF file header
- `pe_get_optional_header()` — Optional header (PE32/PE32+)

### Section Queries
- `pe_get_section_count()` / `pe_get_section()` / `pe_get_section_name()`
- `pe_find_section_by_name()` / `pe_find_section_by_rva()`
- `pe_rva_to_offset()` / `pe_rva_to_ptr()`

### Import/Export Queries
- `pe_get_import_descriptor_count()` / `pe_get_import_thunk()`
- `pe_get_export_count()` / `pe_find_export_by_name()`

### Formatting
- `pe_format_characteristics()` / `pe_format_section_flags()`
- `pe_format_timestamp()` / `pe_format_guid()`

### Image Properties
- `pe_is_dll()` / `pe_is_64bit()` / `pe_has_aslr()` / `pe_has_dep()`

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for details on the 14-phase parsing pipeline and internal data flow.

## License

MIT License. See [LICENSE](LICENSE).
