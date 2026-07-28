# libpectra Architecture

## Parsing Pipeline

libpectra processes PE/COFF binaries through a 14-phase pipeline. Each phase is implemented in its own source file and builds on the results of previous phases.

### Phase 1: DOS Header (`dos.c`)
Validates the MZ signature and extracts `e_lfanew` (offset to PE signature). Detects Rich headers in the DOS stub.

### Phase 2: COFF Header (`coff.c`)
Verifies the PE signature ("PE\0\0") and parses the 20-byte COFF file header: machine type, section count, timestamp, symbol table location, optional header size, and characteristics.

### Phase 3: Optional Header (`optional.c`)
Parses the PE32 or PE32+ optional header based on the magic field. Extracts image base, section/file alignment, entry point, and the 16-entry data directory array.

### Phase 4: Section Table (`sections.c`)
Parses section headers (40 bytes each) and loads section data into allocated buffers. Resolves long section names from string table references (`/offset` format).

### Phase 5: String Table (`strings.c`)
Parses the COFF string table located after the symbol table. Builds an index of string entry pointers for fast offset-based lookup.

### Phase 6: Symbol Table (`symbols.c`)
Parses COFF symbol entries (18 bytes each), resolving names from inline 8-byte fields or string table offsets. Handles auxiliary symbol entries.

### Phase 7: Import Table (`imports.c`)
Parses import descriptors and import lookup table (ILT) entries. Resolves hint/name table entries to function name pointers within section data buffers.

### Phase 8: Export Table (`exports.c`)
Parses the export directory, export address table, name pointer table, and ordinal table. Detects forwarder entries (function RVAs within the export directory range).

### Phase 9: Relocation Table (`relocs.c`)
Parses base relocation blocks and entries. Computes target pointers into section data buffers for each relocation entry.

### Phase 10: Debug Directory (`debug.c`)
Parses debug directory entries (28 bytes each). Extracts CodeView data including GUID and PDB path for type-2 entries. Maps entries to containing sections.

### Phase 11: Resource Tree (`resources.c`)
Recursively parses the resource directory tree (Type → Name → Language). Resolves Unicode name strings and data entry RVAs. Flattens the tree into a linear array.

### Phase 12: Validation (`validate.c`)
Performs non-destructive cross-table consistency checks. Invalid optional
records may be disabled or cleared, while shared section and string-table
storage remains stable for parsed references.

### Phase 13: Cache Construction (`cache.c`)
Builds derived lookup caches from the validated parsed structures. Cache
entries retain stable indices and mirror selected pointers; resolution
refreshes mirrored pointers from the canonical records before use.

### Phase 14: Resolution (`resolve.c`)
Uses cache indices and canonical parsed structures to perform cross-reference
analysis, verify names, refresh relocation targets, map debug information, and
resolve symbol and resource references.

## Data Flow

```
Input bytes → DOS → COFF → Optional → Sections → Strings → Symbols
                                         ↓
               Imports → Exports → Relocs → Debug → Resources
                                         ↓
                              Validate → Cache → Resolve
                                         ↓
                                    Query API
```

## Key Design Decisions

1. **Single-pass parsing**: The input buffer is read through the pipeline, while
   section data is copied into owned buffers for parser use.

2. **Validate before caching**: Cross-table checks complete before derived caches
   are built, so cache contents reflect the final canonical records.

3. **Index-based resolution**: Cache entries retain record indices. Pointer fields
   are refreshed from the owning table before dereference and are never treated
   as independent ownership.

4. **Non-fatal errors**: Most malformed optional structures are reported as
   warnings or validation issues so partial analysis can continue safely.

## File Map

| File | Phase | LOC | Description |
|------|-------|-----|-------------|
| pectra.h | — | ~700 | Public API types and declarations |
| internal.h | — | ~250 | Internal declarations and macros |
| context.c | — | ~330 | Context lifecycle and error reporting |
| reader.c | — | ~290 | Binary data reader utilities |
| dos.c | 1 | ~195 | DOS header parsing |
| coff.c | 2 | ~200 | COFF header parsing |
| optional.c | 3 | ~390 | Optional header parsing |
| sections.c | 4 | ~380 | Section table and data loading |
| strings.c | 5 | ~215 | String table parsing |
| symbols.c | 6 | ~300 | Symbol table parsing |
| imports.c | 7 | ~420 | Import table parsing |
| exports.c | 8 | ~400 | Export table parsing |
| relocs.c | 9 | ~275 | Relocation table parsing |
| debug.c | 10 | ~340 | Debug directory parsing |
| resources.c | 11 | ~425 | Resource tree parsing |
| cache.c | 12 | ~390 | Cache construction |
| validate.c | 13 | ~590 | Cross-table validation |
| resolve.c | 14 | ~440 | Cross-reference resolution |
| checksum.c | — | ~145 | PE checksum computation |
| format.c | — | ~280 | Formatting utilities |
| query.c | — | ~400 | Public query API |
| analysis.c | — | ~540 | Entropy and anomaly analysis |
