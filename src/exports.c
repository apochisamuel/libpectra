/*
 * exports.c — Export Table Parsing (Phase 8)
 *
 * Parses the export directory table which lists functions exported
 * by the PE binary. Includes the export address table (EAT),
 * export name pointer table, and export ordinal table.
 *
 * Functions can be exported by name, by ordinal, or forwarded to
 * another DLL. Forwarder strings are detected when a function RVA
 * falls within the export directory data range.
 *
 * Reference: Microsoft PE/COFF Specification §6.3
 */

#include "internal.h"

/*
 * Read a null-terminated string at a given RVA, returning a pointer
 * into the section data buffer (not an allocated copy).
 */
static char *pe_export_read_name_ptr(pe_ctx_t *ctx, uint32_t rva)
{
    uint32_t sec_idx = pe_find_section_index_by_rva(ctx, rva);
    if (sec_idx == UINT32_MAX) {
        return NULL;
    }

    uint8_t *ptr = pe_section_rva_to_ptr(ctx, sec_idx, rva, 1);
    if (!ptr) {
        return NULL;
    }

    /* Verify null termination within section bounds */
    pe_section_t *sec = &ctx->sections.entries[sec_idx];
    uint32_t delta = rva - sec->virtual_address;
    size_t remaining = sec->data_size - delta;
    size_t len = 0;
    while (len < remaining && ptr[len] != '\0') {
        len++;
    }

    if (len >= remaining) {
        return NULL;
    }

    return (char *)ptr;
}

/*
 * Read a forwarder string at a given RVA.
 * Returns an allocated copy of the string (because forwarders
 * may be selectively freed during validation).
 */
static char *pe_export_read_forwarder(pe_ctx_t *ctx, uint32_t rva)
{
    const uint8_t *ptr = pe_rva_to_ptr(ctx, rva, 1);
    if (!ptr) {
        return NULL;
    }

    size_t max_len = ctx->size - (size_t)(ptr - ctx->data);
    if (max_len > 512) {
        max_len = 512;
    }

    size_t len = 0;
    while (len < max_len && ptr[len] != '\0') {
        len++;
    }

    char *str = (char *)malloc(len + 1);
    if (!str) {
        return NULL;
    }
    memcpy(str, ptr, len);
    str[len] = '\0';
    return str;
}

/*
 * Parse the export address table, name pointer table, and ordinal table.
 */
pe_error_t pe_parse_export_entries(pe_ctx_t *ctx, pe_reader_t *r,
                                    uint32_t func_rva, uint32_t name_rva,
                                    uint32_t ordinal_rva)
{
    pe_export_table_t *et = &ctx->exports;
    uint32_t num_funcs = et->num_functions;
    uint32_t num_names = et->num_names;
    PE_UNUSED(r);

    if (num_funcs == 0) {
        return PE_OK;
    }

    if (num_funcs > PE_MAX_EXPORTS) {
        num_funcs = PE_MAX_EXPORTS;
        et->num_functions = num_funcs;
    }

    et->entries = (pe_export_entry_t *)calloc(num_funcs, sizeof(pe_export_entry_t));
    if (!et->entries) {
        return PE_ERR_ALLOC;
    }
    et->entries_capacity = num_funcs;

    /* Read function RVAs from the export address table */
    uint32_t eat_offset = pe_rva_to_offset(ctx, func_rva);
    if (eat_offset == 0) {
        return PE_ERR_INVALID_EXPORT;
    }

    for (uint32_t i = 0; i < num_funcs; i++) {
        if (!PE_CHECK_OFFSET(ctx, eat_offset + i * 4, 4)) {
            break;
        }
        et->entries[i].function_rva = PE_READ_U32(ctx->data + eat_offset + i * 4);
        et->entries[i].ordinal = (uint16_t)(et->ordinal_base + i);
        et->entries[i].has_name = 0;
        et->entries[i].name = NULL;
        et->entries[i].forwarder = NULL;
        et->entries[i].is_forwarder = 0;
    }

    /* Read name pointers and ordinals */
    if (num_names > 0 && name_rva != 0 && ordinal_rva != 0) {
        uint32_t npt_offset = pe_rva_to_offset(ctx, name_rva);
        uint32_t ot_offset = pe_rva_to_offset(ctx, ordinal_rva);

        if (npt_offset == 0 || ot_offset == 0) {
            pe_ctx_add_warning(ctx,
                "export name/ordinal tables do not resolve");
        } else {
            uint32_t name_count = num_names;
            if (name_count > num_funcs) {
                name_count = num_funcs;
            }

            for (uint32_t i = 0; i < name_count; i++) {
                if (!PE_CHECK_OFFSET(ctx, npt_offset + i * 4, 4)) {
                    break;
                }
                if (!PE_CHECK_OFFSET(ctx, ot_offset + i * 2, 2)) {
                    break;
                }

                uint32_t name_entry_rva = PE_READ_U32(
                    ctx->data + npt_offset + i * 4);
                uint16_t ordinal_index = PE_READ_U16(
                    ctx->data + ot_offset + i * 2);

                if (ordinal_index < num_funcs) {
                    pe_export_entry_t *entry = &et->entries[ordinal_index];
                    entry->has_name = 1;
                    entry->name_ordinal = (uint16_t)i;

                    /* Name pointer goes into section data buffer */
                    entry->name = pe_export_read_name_ptr(ctx, name_entry_rva);
                    if (!entry->name) {
                        pe_ctx_add_warning(ctx,
                            "export %u: name RVA 0x%X does not resolve",
                            i, name_entry_rva);
                    }
                }
            }
        }
    }

    return PE_OK;
}

/*
 * Detect and resolve forwarder strings.
 * A function RVA that falls within the export directory data range
 * is a forwarder — the RVA points to a "DLL.Function" string.
 */
pe_error_t pe_resolve_export_forwarders(pe_ctx_t *ctx, uint32_t export_dir_rva,
                                         uint32_t export_dir_size)
{
    pe_export_table_t *et = &ctx->exports;

    uint32_t dir_start = export_dir_rva;
    uint32_t dir_end = export_dir_rva + export_dir_size;

    for (uint32_t i = 0; i < et->num_functions; i++) {
        pe_export_entry_t *entry = &et->entries[i];

        if (entry->function_rva == 0) {
            continue;
        }

        /* Check if the function RVA falls within the export directory */
        if (entry->function_rva >= dir_start &&
            entry->function_rva < dir_end) {
            entry->is_forwarder = 1;
            entry->forwarder = pe_export_read_forwarder(ctx,
                                                         entry->function_rva);
            if (!entry->forwarder) {
                pe_ctx_add_warning(ctx,
                    "export %u: forwarder RVA 0x%X does not resolve",
                    i, entry->function_rva);
            }
        }
    }

    return PE_OK;
}

/*
 * Parse the complete export table from the export directory RVA.
 */
pe_error_t pe_parse_export_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    pe_data_dir_t *export_dir = &ctx->optional.data_dirs[PE_DIR_EXPORT];
    if (export_dir->rva == 0 || export_dir->size == 0) {
        return PE_OK;
    }

    uint32_t dir_offset = pe_rva_to_offset(ctx, export_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_EXPORT,
                         "export directory RVA 0x%X does not resolve",
                         export_dir->rva);
        return PE_ERR_INVALID_EXPORT;
    }

    if (!PE_CHECK_OFFSET(ctx, dir_offset, 40)) {
        return PE_ERR_TRUNCATED;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_export_table_t *et = &ctx->exports;

    if (!pe_reader_read_u32(&r, &et->characteristics)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &et->timestamp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(&r, &et->major_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(&r, &et->minor_version)) {
        return PE_ERR_TRUNCATED;
    }

    uint32_t name_rva;
    if (!pe_reader_read_u32(&r, &name_rva)) {
        return PE_ERR_TRUNCATED;
    }

    if (name_rva != 0) {
        et->dll_name = pe_export_read_name_ptr(ctx, name_rva);
    }

    if (!pe_reader_read_u32(&r, &et->ordinal_base)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &et->num_functions)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &et->num_names)) {
        return PE_ERR_TRUNCATED;
    }

    uint32_t func_rva, npt_rva, ot_rva;
    if (!pe_reader_read_u32(&r, &func_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &npt_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &ot_rva)) {
        return PE_ERR_TRUNCATED;
    }

    /* Validate counts */
    if (et->num_names > et->num_functions) {
        pe_ctx_add_warning(ctx,
            "export name count %u exceeds function count %u",
            et->num_names, et->num_functions);
        et->num_names = et->num_functions;
    }

    /* Parse entries */
    pe_error_t err = pe_parse_export_entries(ctx, &r, func_rva, npt_rva, ot_rva);
    if (err != PE_OK) {
        return err;
    }

    /* Detect forwarders */
    err = pe_resolve_export_forwarders(ctx, export_dir->rva, export_dir->size);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "forwarder resolution incomplete");
    }

    return PE_OK;
}

/* Free export table */
void pe_free_export_table(pe_export_table_t *et)
{
    if (!et || !et->entries) {
        return;
    }

    for (uint32_t i = 0; i < et->num_functions; i++) {
        /* Export names point into section data — do not free them.
         * Forwarder strings are allocated copies — free them. */
        free(et->entries[i].forwarder);
        et->entries[i].forwarder = NULL;
    }

    /* dll_name points into section data — do not free */
    et->dll_name = NULL;

    free(et->entries);
    et->entries = NULL;
    et->num_functions = 0;
    et->num_names = 0;
    et->entries_capacity = 0;
}

/* Public API: export count */
uint32_t pe_get_export_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->exports.num_functions;
}

/* Public API: get export entry */
const pe_export_entry_t *pe_get_export(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->exports.num_functions) {
        return NULL;
    }
    return &ctx->exports.entries[index];
}

/* Public API: find export by name */
const pe_export_entry_t *pe_find_export_by_name(const pe_ctx_t *ctx,
                                                  const char *name)
{
    if (!ctx || !name) {
        return NULL;
    }

    for (uint32_t i = 0; i < ctx->exports.num_functions; i++) {
        const pe_export_entry_t *entry = &ctx->exports.entries[i];
        if (entry->has_name && entry->name &&
            strcmp(entry->name, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

/* Public API: find export by ordinal */
const pe_export_entry_t *pe_find_export_by_ordinal(const pe_ctx_t *ctx,
                                                     uint16_t ordinal)
{
    if (!ctx) {
        return NULL;
    }

    for (uint32_t i = 0; i < ctx->exports.num_functions; i++) {
        if (ctx->exports.entries[i].ordinal == ordinal) {
            return &ctx->exports.entries[i];
        }
    }

    return NULL;
}

/* Public API: get export DLL name */
const char *pe_get_export_dll_name(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return ctx->exports.dll_name;
}
