/*
 * delay_import.c — Delay Import Directory Parsing
 *
 * Parses the delay-load import directory (data directory index 13)
 * which describes DLLs that are loaded on demand rather than at
 * process startup. Each delay import descriptor contains:
 *   - Attributes
 *   - DLL name RVA
 *   - Module handle address
 *   - Import Address Table RVA
 *   - Import Name Table RVA
 *   - Bound Import Address Table RVA
 *   - Unload Import Address Table RVA
 *   - Timestamp
 *
 * The delay import name table follows the same format as the
 * regular import lookup table (ILT), with by-ordinal and
 * by-name import entries.
 *
 * Reference: Microsoft PE/COFF Specification §5.8
 */

#include "internal.h"

/*
 * Parse a single delay import descriptor.
 * Each descriptor is 32 bytes with 8 fields of 4 bytes each.
 */
static pe_error_t pe_parse_delay_descriptor(pe_ctx_t *ctx, pe_reader_t *r,
                                              pe_delay_import_desc_t *desc)
{
    PE_UNUSED(ctx);
    memset(desc, 0, sizeof(*desc));

    if (!pe_reader_read_u32(r, &desc->attributes)) return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->name_rva))   return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->module_handle_rva)) return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->iat_rva))     return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->int_rva))     return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->bound_iat_rva)) return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->unload_iat_rva)) return PE_ERR_TRUNCATED;
    if (!pe_reader_read_u32(r, &desc->timestamp))   return PE_ERR_TRUNCATED;

    return PE_OK;
}

/*
 * Determine if a delay import descriptor uses RVA-based addressing
 * (modern format) or VA-based addressing (legacy format).
 * Attribute bit 0 controls this: 1 = RVA, 0 = VA.
 */
static int pe_delay_uses_rva(const pe_delay_import_desc_t *desc)
{
    return (desc->attributes & 1) != 0;
}

/*
 * Convert a delay import address to an RVA, accounting for the
 * RVA vs VA distinction based on the descriptor attributes.
 */
static uint32_t pe_delay_to_rva(const pe_ctx_t *ctx,
                                  const pe_delay_import_desc_t *desc,
                                  uint32_t addr)
{
    if (addr == 0) return 0;
    if (pe_delay_uses_rva(desc)) {
        return addr;
    }
    if ((uint64_t)addr >= ctx->optional.image_base) {
        return (uint32_t)((uint64_t)addr - ctx->optional.image_base);
    }
    return addr;
}

/*
 * Resolve the DLL name from the delay import descriptor.
 */
static char *pe_delay_resolve_dll_name(pe_ctx_t *ctx,
                                         const pe_delay_import_desc_t *desc)
{
    uint32_t name_rva = pe_delay_to_rva(ctx, desc, desc->name_rva);
    if (name_rva == 0) return NULL;

    const uint8_t *ptr = pe_rva_to_ptr(ctx, name_rva, 1);
    if (!ptr) return NULL;

    size_t max_len = ctx->size - (size_t)(ptr - ctx->data);
    if (max_len > 256) max_len = 256;

    size_t len = 0;
    while (len < max_len && ptr[len] != '\0') len++;

    char *name = (char *)malloc(len + 1);
    if (!name) return NULL;
    memcpy(name, ptr, len);
    name[len] = '\0';
    return name;
}

/*
 * Parse the delay import name table (INT) for a descriptor.
 * This follows the same format as the regular import lookup table.
 */
static pe_error_t pe_parse_delay_thunks(pe_ctx_t *ctx,
                                          pe_delay_import_desc_t *desc)
{
    uint32_t int_rva = pe_delay_to_rva(ctx, desc, desc->int_rva);
    if (int_rva == 0) return PE_OK;

    uint32_t int_offset = pe_rva_to_offset(ctx, int_rva);
    if (int_offset == 0) return PE_OK;

    int is_pe32plus = ctx->optional.is_pe32plus;
    uint32_t max_thunks = PE_MAX_THUNKS;

    desc->thunks = (pe_delay_thunk_t *)calloc(16, sizeof(pe_delay_thunk_t));
    if (!desc->thunks) return PE_ERR_ALLOC;
    desc->thunks_capacity = 16;

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, int_offset)) return PE_ERR_TRUNCATED;

    while (desc->num_thunks < max_thunks) {
        uint64_t thunk_val;
        if (is_pe32plus) {
            if (!pe_reader_read_u64(&r, &thunk_val)) break;
        } else {
            uint32_t val32;
            if (!pe_reader_read_u32(&r, &val32)) break;
            thunk_val = val32;
        }

        if (thunk_val == 0) break;

        PE_ARRAY_GROW(desc->thunks, desc->num_thunks,
                       desc->thunks_capacity, pe_delay_thunk_t);

        pe_delay_thunk_t *thunk = &desc->thunks[desc->num_thunks];
        memset(thunk, 0, sizeof(*thunk));

        uint64_t ordinal_flag = is_pe32plus ? 0x8000000000000000ULL
                                             : 0x80000000ULL;
        if (thunk_val & ordinal_flag) {
            thunk->is_ordinal = 1;
            thunk->ordinal = (uint16_t)(thunk_val & 0xFFFF);
        } else {
            uint32_t hint_name_rva = (uint32_t)(thunk_val &
                (is_pe32plus ? 0x7FFFFFFFULL : 0x7FFFFFFFUL));
            hint_name_rva = pe_delay_to_rva(ctx, desc, hint_name_rva);

            thunk->name = pe_resolve_hint_name(ctx, hint_name_rva,
                                                 &thunk->hint);
        }

        desc->num_thunks++;
    }

    return PE_OK;
}

/*
 * Validate delay import descriptor fields.
 */
static void pe_validate_delay_descriptor(pe_ctx_t *ctx,
                                           const pe_delay_import_desc_t *desc,
                                           uint32_t index)
{
    if (desc->name_rva == 0) {
        pe_ctx_add_issue(ctx, 1, 0,
            "delay import %u: null DLL name RVA", index);
    }

    if (desc->int_rva == 0 && desc->iat_rva == 0) {
        pe_ctx_add_issue(ctx, 1, 0,
            "delay import %u: both INT and IAT are null", index);
    }

    if (desc->dll_name) {
        size_t name_len = strlen(desc->dll_name);
        if (name_len > 128) {
            pe_ctx_add_issue(ctx, 1, 0,
                "delay import %u: DLL name unusually long (%zu chars)",
                index, name_len);
        }

        int has_extension = 0;
        for (size_t i = 0; i < name_len; i++) {
            if (desc->dll_name[i] == '.') has_extension = 1;
        }
        if (!has_extension) {
            pe_ctx_add_issue(ctx, 1, 0,
                "delay import %u: DLL name '%s' has no file extension",
                index, desc->dll_name);
        }
    }

    if (desc->timestamp != 0 && ctx->coff.timestamp != 0) {
        if (desc->timestamp > ctx->coff.timestamp + 86400 * 365 * 5) {
            pe_ctx_add_issue(ctx, 1, 0,
                "delay import %u: timestamp far in the future", index);
        }
    }
}

/*
 * Cross-reference delay imports with regular imports.
 * Identifies DLLs that appear in both the regular and delay
 * import tables, which may indicate an unusual build.
 */
static void pe_cross_ref_delay_imports(pe_ctx_t *ctx)
{
    pe_delay_import_table_t *dt = &ctx->delay_imports;
    pe_import_table_t *it = &ctx->imports;

    if (dt->count == 0 || it->count == 0) return;

    for (uint32_t d = 0; d < dt->count; d++) {
        if (!dt->descriptors[d].dll_name) continue;

        for (uint32_t i = 0; i < it->count; i++) {
            if (!it->descriptors[i].dll_name) continue;

            if (strcmp(dt->descriptors[d].dll_name,
                       it->descriptors[i].dll_name) == 0) {
                pe_ctx_add_issue(ctx, 1, 0,
                    "delay import '%s' also appears in regular imports",
                    dt->descriptors[d].dll_name);
            }
        }
    }
}

/*
 * Map delay import data to containing sections.
 */
static void pe_map_delay_imports_to_sections(pe_ctx_t *ctx)
{
    pe_delay_import_table_t *dt = &ctx->delay_imports;

    for (uint32_t d = 0; d < dt->count; d++) {
        pe_delay_import_desc_t *desc = &dt->descriptors[d];

        uint32_t name_rva = pe_delay_to_rva(ctx, desc, desc->name_rva);
        if (name_rva != 0) {
            desc->name_section = pe_find_section_index_by_rva(ctx, name_rva);
        }

        uint32_t iat_rva = pe_delay_to_rva(ctx, desc, desc->iat_rva);
        if (iat_rva != 0) {
            desc->iat_section = pe_find_section_index_by_rva(ctx, iat_rva);
        }
    }
}

/*
 * Parse the complete delay import directory.
 */
pe_error_t pe_parse_delay_import_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) return PE_ERR_NULLARG;

    pe_data_dir_t *delay_dir = &ctx->optional.data_dirs[PE_DIR_DELAY_IMPORT];
    if (delay_dir->rva == 0 || delay_dir->size == 0) return PE_OK;

    uint32_t dir_offset = pe_rva_to_offset(ctx, delay_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_add_warning(ctx,
            "delay import directory RVA 0x%X does not resolve",
            delay_dir->rva);
        return PE_OK;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) return PE_ERR_TRUNCATED;

    pe_delay_import_table_t *dt = &ctx->delay_imports;
    uint32_t max_descs = delay_dir->size / 32;
    if (max_descs > PE_MAX_IMPORTS) max_descs = PE_MAX_IMPORTS;

    dt->descriptors = (pe_delay_import_desc_t *)calloc(
        max_descs > 0 ? max_descs : 1, sizeof(pe_delay_import_desc_t));
    if (!dt->descriptors) return PE_ERR_ALLOC;
    dt->capacity = max_descs > 0 ? max_descs : 1;

    while (dt->count < max_descs) {
        if (pe_reader_remaining(&r) < 32) break;

        pe_delay_import_desc_t *desc = &dt->descriptors[dt->count];
        pe_error_t err = pe_parse_delay_descriptor(ctx, &r, desc);
        if (err != PE_OK) break;

        if (desc->attributes == 0 && desc->name_rva == 0 &&
            desc->iat_rva == 0 && desc->int_rva == 0) {
            break;
        }

        desc->dll_name = pe_delay_resolve_dll_name(ctx, desc);
        desc->name_section = UINT32_MAX;
        desc->iat_section = UINT32_MAX;

        err = pe_parse_delay_thunks(ctx, desc);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx,
                "delay import %u: thunk parse incomplete", dt->count);
        }

        pe_validate_delay_descriptor(ctx, desc, dt->count);
        dt->count++;
    }

    pe_cross_ref_delay_imports(ctx);
    pe_map_delay_imports_to_sections(ctx);

    return PE_OK;
}

/* Free delay import thunks */
static void pe_free_delay_thunks(pe_delay_import_desc_t *desc)
{
    if (!desc || !desc->thunks) return;
    free(desc->thunks);
    desc->thunks = NULL;
    desc->num_thunks = 0;
    desc->thunks_capacity = 0;
}

/* Free the delay import table */
void pe_free_delay_import_table(pe_delay_import_table_t *dt)
{
    if (!dt || !dt->descriptors) return;
    for (uint32_t i = 0; i < dt->count; i++) {
        free(dt->descriptors[i].dll_name);
        pe_free_delay_thunks(&dt->descriptors[i]);
    }
    free(dt->descriptors);
    dt->descriptors = NULL;
    dt->count = 0;
    dt->capacity = 0;
}

/* Public API: delay import descriptor count */
uint32_t pe_get_delay_import_count(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return ctx->delay_imports.count;
}

/* Public API: get delay import descriptor */
const pe_delay_import_desc_t *pe_get_delay_import(const pe_ctx_t *ctx,
                                                     uint32_t index)
{
    if (!ctx || index >= ctx->delay_imports.count) return NULL;
    return &ctx->delay_imports.descriptors[index];
}

/* Public API: get delay import DLL name */
const char *pe_get_delay_import_dll_name(const pe_ctx_t *ctx, uint32_t index)
{
    const pe_delay_import_desc_t *desc = pe_get_delay_import(ctx, index);
    if (!desc) return NULL;
    return desc->dll_name;
}

/* Public API: get delay import thunk count */
uint32_t pe_get_delay_thunk_count(const pe_ctx_t *ctx, uint32_t desc_index)
{
    const pe_delay_import_desc_t *desc = pe_get_delay_import(ctx, desc_index);
    if (!desc) return 0;
    return desc->num_thunks;
}

/* Public API: get delay import thunk */
const pe_delay_thunk_t *pe_get_delay_thunk(const pe_ctx_t *ctx,
                                              uint32_t desc_index,
                                              uint32_t thunk_index)
{
    const pe_delay_import_desc_t *desc = pe_get_delay_import(ctx, desc_index);
    if (!desc || thunk_index >= desc->num_thunks) return NULL;
    return &desc->thunks[thunk_index];
}
