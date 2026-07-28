/*
 * internal.h — Internal declarations for libpectra
 *
 * Private function prototypes and utility macros shared across
 * compilation units. Not part of the public API.
 */

#ifndef PECTRA_INTERNAL_H
#define PECTRA_INTERNAL_H

#include "pectra.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ----------------------------------------------------------------
 * Internal utility macros
 * ---------------------------------------------------------------- */

#define PE_UNUSED(x) ((void)(x))

#define PE_MAX(a, b) ((a) > (b) ? (a) : (b))
#define PE_MIN(a, b) ((a) < (b) ? (a) : (b))

#define PE_ALIGN_UP(val, align) \
    (((val) + (align) - 1) & ~((align) - 1))

#define PE_ARRAY_GROW(arr, count, cap, type)                          \
    do {                                                               \
        if ((count) >= (cap)) {                                        \
            uint32_t _newcap = (cap) == 0 ? 16 : (cap) * 2;           \
            type *_tmp = (type *)realloc((arr), _newcap * sizeof(type)); \
            if (!_tmp) { return PE_ERR_ALLOC; }                        \
            (arr) = _tmp;                                              \
            (cap) = _newcap;                                           \
        }                                                              \
    } while (0)

#define PE_ARRAY_GROW_VOID(arr, count, cap, type)                     \
    do {                                                               \
        if ((count) >= (cap)) {                                        \
            uint32_t _newcap = (cap) == 0 ? 16 : (cap) * 2;           \
            type *_tmp = (type *)realloc((arr), _newcap * sizeof(type)); \
            if (!_tmp) { return; }                                     \
            (arr) = _tmp;                                              \
            (cap) = _newcap;                                           \
        }                                                              \
    } while (0)

/* Safe offset checking */
#define PE_CHECK_OFFSET(ctx, off, needed) \
    ((off) <= (ctx)->size && (needed) <= (ctx)->size - (off))

/* Byte reading helpers — no bounds checking, caller must verify first */
#define PE_READ_U8(ptr)  (*(const uint8_t  *)(ptr))
#define PE_READ_U16(ptr) ((uint16_t)((uint16_t)(ptr)[0] | \
                          ((uint16_t)(ptr)[1] << 8)))
#define PE_READ_U32(ptr) ((uint32_t)((uint32_t)(ptr)[0] | \
                          ((uint32_t)(ptr)[1] << 8) | \
                          ((uint32_t)(ptr)[2] << 16) | \
                          ((uint32_t)(ptr)[3] << 24)))
#define PE_READ_U64(ptr) ((uint64_t)PE_READ_U32(ptr) | \
                          ((uint64_t)PE_READ_U32((ptr) + 4) << 32))

/* Internal allocation limits to prevent excessive memory usage */
#define PE_MAX_SECTIONS     256
#define PE_MAX_SYMBOLS      0x100000
#define PE_MAX_IMPORTS      4096
#define PE_MAX_THUNKS       65536
#define PE_MAX_EXPORTS      65536
#define PE_MAX_RELOC_BLOCKS 8192
#define PE_MAX_RELOC_ENTRIES 65536
#define PE_MAX_DEBUG_ENTRIES 256
#define PE_MAX_RESOURCE_DEPTH 8
#define PE_MAX_RESOURCE_NODES 65536
#define PE_MAX_STRING_TABLE  0x400000
#define PE_MAX_EXCEPTION_ENTRIES 16384
#define PE_MAX_UNWIND_CODES    256
#define PE_MAX_ISSUES        1024

/* Validation thresholds */
#define PE_VALIDATE_EXPORT_OVERLAP_THRESHOLD    64
#define PE_VALIDATE_IMPORT_DUP_THRESHOLD        3
#define PE_VALIDATE_DEBUG_TIMESTAMP_DRIFT       86400
#define PE_VALIDATE_SYMBOL_MISMATCH_THRESHOLD   16
#define PE_VALIDATE_SECTION_ALIGN_TOLERANCE     0
#define PE_VALIDATE_RESOURCE_BOUNDS_THRESHOLD   8

/* ----------------------------------------------------------------
 * Context management (context.c)
 * ---------------------------------------------------------------- */
pe_ctx_t  *pe_ctx_alloc(void);
void       pe_ctx_free(pe_ctx_t *ctx);
void       pe_ctx_set_error(pe_ctx_t *ctx, pe_error_t err, const char *fmt, ...);
void       pe_ctx_add_warning(pe_ctx_t *ctx, const char *fmt, ...);
void       pe_ctx_add_issue(pe_ctx_t *ctx, int severity, uint32_t section,
                            const char *fmt, ...);

/* ----------------------------------------------------------------
 * Reader utilities (reader.c)
 * ---------------------------------------------------------------- */
typedef struct {
    const uint8_t *base;
    size_t         total_size;
    size_t         offset;
} pe_reader_t;

void       pe_reader_init(pe_reader_t *r, const uint8_t *data, size_t size);
int        pe_reader_seek(pe_reader_t *r, size_t offset);
int        pe_reader_skip(pe_reader_t *r, size_t count);
size_t     pe_reader_tell(const pe_reader_t *r);
size_t     pe_reader_remaining(const pe_reader_t *r);
int        pe_reader_can_read(const pe_reader_t *r, size_t count);
int        pe_reader_read_u8(pe_reader_t *r, uint8_t *out);
int        pe_reader_read_u16(pe_reader_t *r, uint16_t *out);
int        pe_reader_read_u32(pe_reader_t *r, uint32_t *out);
int        pe_reader_read_u64(pe_reader_t *r, uint64_t *out);
int        pe_reader_read_bytes(pe_reader_t *r, void *buf, size_t count);
const uint8_t *pe_reader_peek(const pe_reader_t *r, size_t count);
int        pe_reader_read_cstring(pe_reader_t *r, char *buf, size_t bufsz,
                                   size_t *out_len);
int        pe_reader_read_fixed_string(pe_reader_t *r, char *buf, size_t len);
uint8_t   *pe_reader_copy_range(pe_reader_t *r, size_t offset, size_t length);

/* ----------------------------------------------------------------
 * Parsing phase functions
 * ---------------------------------------------------------------- */

/* Phase 1: DOS header (dos.c) */
pe_error_t pe_parse_dos_header(pe_ctx_t *ctx);

/* Phase 2: COFF header (coff.c) */
pe_error_t pe_parse_coff_header(pe_ctx_t *ctx);
pe_error_t pe_parse_pe_signature(pe_ctx_t *ctx, uint32_t offset);

/* Phase 3: Optional header (optional.c) */
pe_error_t pe_parse_optional_header(pe_ctx_t *ctx, uint32_t offset);
pe_error_t pe_parse_data_directories(pe_ctx_t *ctx, pe_reader_t *r);
pe_error_t pe_parse_pe32_fields(pe_ctx_t *ctx, pe_reader_t *r);
pe_error_t pe_parse_pe32plus_fields(pe_ctx_t *ctx, pe_reader_t *r);

/* Phase 4: Section table (sections.c) */
pe_error_t pe_parse_section_table(pe_ctx_t *ctx, uint32_t offset);
pe_error_t pe_load_section_data(pe_ctx_t *ctx);
pe_error_t pe_resolve_section_names(pe_ctx_t *ctx);
void       pe_free_section_data(pe_section_t *section);
void       pe_free_section_table(pe_section_table_t *table);
pe_error_t pe_reload_section_data(pe_ctx_t *ctx, uint32_t section_index);
uint32_t   pe_find_section_index_by_rva(const pe_ctx_t *ctx, uint32_t rva);
uint8_t   *pe_section_rva_to_ptr(const pe_ctx_t *ctx, uint32_t section_index,
                                  uint32_t rva, size_t min_size);

/* Phase 5: String table (strings.c) */
pe_error_t pe_parse_string_table(pe_ctx_t *ctx);
void       pe_free_string_table(pe_string_table_t *st);
pe_error_t pe_rebuild_string_table(pe_ctx_t *ctx);
const char *pe_string_table_lookup(const pe_string_table_t *st, uint32_t offset);

/* Phase 6: Symbol table (symbols.c) */
pe_error_t pe_parse_symbol_table(pe_ctx_t *ctx);
void       pe_free_symbol_table(pe_symbol_table_t *st);
pe_error_t pe_resolve_symbol_names(pe_ctx_t *ctx);

/* Phase 7: Import table (imports.c) */
pe_error_t pe_parse_import_table(pe_ctx_t *ctx);
char      *pe_resolve_hint_name(pe_ctx_t *ctx, uint32_t rva, uint16_t *hint_out);
pe_error_t pe_parse_import_descriptor(pe_ctx_t *ctx, pe_reader_t *r,
                                       pe_import_descriptor_t *desc);
pe_error_t pe_parse_import_thunks(pe_ctx_t *ctx, pe_import_descriptor_t *desc,
                                   int is_pe32plus);
void       pe_free_import_table(pe_import_table_t *it);
void       pe_free_import_descriptor(pe_import_descriptor_t *desc);

/* Phase 8: Export table (exports.c) */
pe_error_t pe_parse_export_table(pe_ctx_t *ctx);
pe_error_t pe_parse_export_entries(pe_ctx_t *ctx, pe_reader_t *r,
                                    uint32_t func_rva, uint32_t name_rva,
                                    uint32_t ordinal_rva);
pe_error_t pe_resolve_export_forwarders(pe_ctx_t *ctx, uint32_t export_dir_rva,
                                         uint32_t export_dir_size);
void       pe_free_export_table(pe_export_table_t *et);

/* Phase 9: Relocation table (relocs.c) */
pe_error_t pe_parse_reloc_table(pe_ctx_t *ctx);
pe_error_t pe_parse_reloc_block(pe_ctx_t *ctx, pe_reader_t *r,
                                 pe_reloc_block_t *block);
pe_error_t pe_compute_reloc_targets(pe_ctx_t *ctx);
void       pe_free_reloc_table(pe_reloc_table_t *rt);

/* Phase 10: Debug directory (debug.c) */
pe_error_t pe_parse_debug_table(pe_ctx_t *ctx);
pe_error_t pe_parse_codeview_info(pe_ctx_t *ctx, pe_debug_entry_t *entry);
pe_error_t pe_map_debug_to_sections(pe_ctx_t *ctx);
void       pe_free_debug_table(pe_debug_table_t *dt);
void       pe_free_debug_entry(pe_debug_entry_t *entry);

/* Phase 11: Resource tree (resources.c) */
pe_error_t pe_parse_resource_tree(pe_ctx_t *ctx);
pe_error_t pe_parse_resource_directory(pe_ctx_t *ctx, pe_reader_t *r,
                                        pe_resource_node_t *parent,
                                        uint32_t base_offset, uint32_t depth);
pe_error_t pe_flatten_resource_tree(pe_ctx_t *ctx, pe_resource_node_t *node);
void       pe_free_resource_tree(pe_resource_tree_t *rt);
void       pe_free_resource_node(pe_resource_node_t *node);

/* Phase 7b: Delay import directory (delay_import.c) */
pe_error_t pe_parse_delay_import_table(pe_ctx_t *ctx);
void       pe_free_delay_import_table(pe_delay_import_table_t *dt);

/* Phase 11b: Exception directory (exception.c) */
pe_error_t pe_parse_exception_table(pe_ctx_t *ctx);
void       pe_free_exception_table(pe_exception_table_t *et);

/* Phase 12: Cache construction (cache.c) */
pe_error_t pe_build_cache(pe_ctx_t *ctx);
pe_error_t pe_build_import_cache(pe_ctx_t *ctx);
pe_error_t pe_build_export_cache(pe_ctx_t *ctx);
pe_error_t pe_build_reloc_cache(pe_ctx_t *ctx);
pe_error_t pe_build_debug_cache(pe_ctx_t *ctx);
pe_error_t pe_build_symbol_cache(pe_ctx_t *ctx);
pe_error_t pe_build_resource_cache(pe_ctx_t *ctx);
pe_error_t pe_build_section_name_cache(pe_ctx_t *ctx);
void       pe_free_cache(pe_cache_t *cache);

/* Phase 13: Validation (validate.c) */
pe_error_t pe_validate(pe_ctx_t *ctx);
pe_error_t pe_validate_section_alignment(pe_ctx_t *ctx);
pe_error_t pe_validate_import_consistency(pe_ctx_t *ctx);
pe_error_t pe_validate_export_ranges(pe_ctx_t *ctx);
pe_error_t pe_validate_reloc_targets(pe_ctx_t *ctx);
pe_error_t pe_validate_debug_entries(pe_ctx_t *ctx);
pe_error_t pe_validate_symbol_table(pe_ctx_t *ctx);
pe_error_t pe_validate_resource_bounds(pe_ctx_t *ctx);
pe_error_t pe_validate_string_table_refs(pe_ctx_t *ctx);

/* Phase 14: Cross-reference resolution (resolve.c) */
pe_error_t pe_resolve(pe_ctx_t *ctx);
pe_error_t pe_resolve_import_names(pe_ctx_t *ctx);
pe_error_t pe_resolve_export_names(pe_ctx_t *ctx);
pe_error_t pe_resolve_relocations(pe_ctx_t *ctx);
pe_error_t pe_resolve_debug_info(pe_ctx_t *ctx);
pe_error_t pe_resolve_symbol_refs(pe_ctx_t *ctx);
pe_error_t pe_resolve_resource_names(pe_ctx_t *ctx);
pe_error_t pe_resolve_cross_references(pe_ctx_t *ctx);

/* Checksum (checksum.c) */
pe_error_t pe_validate_pe_checksum(pe_ctx_t *ctx);

/* Formatting (format.c) */
/* (public API declared in pectra.h) */

/* Query (query.c) */
/* (public API declared in pectra.h) */

/* Analysis (analysis.c) */
void pe_comprehensive_analysis(const pe_ctx_t *ctx);

#endif /* PECTRA_INTERNAL_H */
