/*
 * debug.c — Debug Directory Parsing (Phase 10)
 *
 * Parses the debug directory which contains entries describing
 * debug information embedded in or associated with the PE image.
 * Supports CodeView (type 2) entries which reference PDB files.
 *
 * Debug entries are mapped to their containing sections to enable
 * cross-reference resolution between debug data and section content.
 *
 * Reference: Microsoft PE/COFF Specification §6.1
 */

#include "internal.h"

/* Return the debug type name */
const char *pe_get_debug_type_name(uint32_t type)
{
    switch (type) {
    case PE_DEBUG_TYPE_UNKNOWN:   return "UNKNOWN";
    case PE_DEBUG_TYPE_COFF:      return "COFF";
    case PE_DEBUG_TYPE_CODEVIEW:  return "CODEVIEW";
    case PE_DEBUG_TYPE_FPO:       return "FPO";
    case PE_DEBUG_TYPE_MISC:      return "MISC";
    case PE_DEBUG_TYPE_BORLAND:   return "BORLAND";
    case PE_DEBUG_TYPE_REPRO:     return "REPRO";
    case PE_DEBUG_TYPE_POGO:      return "POGO";
    default:                      return "OTHER";
    }
}

/*
 * Parse a CodeView debug info structure.
 * The CodeView data starts with a 4-byte signature ("RSDS" = 0x53445352)
 * followed by a 16-byte GUID, 4-byte age, and null-terminated PDB path.
 */
pe_error_t pe_parse_codeview_info(pe_ctx_t *ctx, pe_debug_entry_t *entry)
{
    if (entry->raw_data_offset == 0 || entry->data_size < 24) {
        return PE_OK;
    }

    if (!PE_CHECK_OFFSET(ctx, entry->raw_data_offset, entry->data_size)) {
        pe_ctx_add_warning(ctx,
            "CodeView data at offset 0x%X truncated", entry->raw_data_offset);
        return PE_ERR_TRUNCATED;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, entry->raw_data_offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_codeview_info_t *cv = (pe_codeview_info_t *)calloc(1,
                                                           sizeof(pe_codeview_info_t));
    if (!cv) {
        return PE_ERR_ALLOC;
    }

    if (!pe_reader_read_u32(&r, &cv->cv_signature)) {
        free(cv);
        return PE_ERR_TRUNCATED;
    }

    /* RSDS signature check */
    if (cv->cv_signature != 0x53445352) {
        pe_ctx_add_warning(ctx,
            "CodeView signature 0x%08X (expected RSDS 0x53445352)",
            cv->cv_signature);
        /* Continue anyway — some tools use different signatures */
    }

    if (!pe_reader_read_bytes(&r, cv->guid, 16)) {
        free(cv);
        return PE_ERR_TRUNCATED;
    }

    if (!pe_reader_read_u32(&r, &cv->age)) {
        free(cv);
        return PE_ERR_TRUNCATED;
    }

    /* PDB path: null-terminated string following the fixed fields */
    size_t path_max = entry->data_size - 24;
    if (path_max > 0 && path_max <= 512) {
        cv->pdb_path = (char *)malloc(path_max + 1);
        if (cv->pdb_path) {
            size_t path_len;
            if (!pe_reader_read_cstring(&r, cv->pdb_path,
                                         path_max + 1, &path_len)) {
                cv->pdb_path[0] = '\0';
            }
        }
    }

    entry->codeview = cv;
    return PE_OK;
}

/*
 * Parse a single debug directory entry (28 bytes).
 */
static pe_error_t pe_parse_debug_entry(pe_ctx_t *ctx, pe_reader_t *r,
                                        pe_debug_entry_t *entry)
{
    PE_UNUSED(ctx);
    memset(entry, 0, sizeof(*entry));

    if (!pe_reader_read_u32(r, &entry->characteristics)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &entry->timestamp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &entry->major_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &entry->minor_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &entry->type)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &entry->data_size)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &entry->address_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &entry->raw_data_offset)) {
        return PE_ERR_TRUNCATED;
    }

    entry->codeview = NULL;
    entry->section_index = -1;

    return PE_OK;
}

/*
 * Map debug entries to their containing sections.
 */
pe_error_t pe_map_debug_to_sections(pe_ctx_t *ctx)
{
    pe_debug_table_t *dt = &ctx->debug;

    for (uint32_t i = 0; i < dt->count; i++) {
        pe_debug_entry_t *entry = &dt->entries[i];

        if (entry->address_rva == 0) {
            continue;
        }

        uint32_t sec_idx = pe_find_section_index_by_rva(ctx, entry->address_rva);
        if (sec_idx != UINT32_MAX) {
            entry->section_index = (int)sec_idx;
        } else {
            pe_ctx_add_warning(ctx,
                "debug entry %u: RVA 0x%X has no containing section",
                i, entry->address_rva);
        }
    }

    return PE_OK;
}

/*
 * Validate debug entry fields.
 */
static void pe_validate_debug_entry(pe_ctx_t *ctx, const pe_debug_entry_t *entry,
                                     uint32_t index)
{
    if (entry->raw_data_offset != 0 &&
        entry->raw_data_offset >= ctx->size) {
        pe_ctx_add_warning(ctx,
            "debug entry %u: raw data offset 0x%X beyond file",
            index, entry->raw_data_offset);
    }

    if (entry->data_size > 0 && entry->raw_data_offset != 0) {
        uint32_t end = entry->raw_data_offset + entry->data_size;
        if (end < entry->raw_data_offset || end > ctx->size) {
            pe_ctx_add_warning(ctx,
                "debug entry %u: data extends beyond file", index);
        }
    }

    /* Check timestamp consistency with COFF header */
    if (entry->timestamp != 0 && ctx->coff.timestamp != 0) {
        int64_t drift = (int64_t)entry->timestamp - (int64_t)ctx->coff.timestamp;
        if (drift < 0) {
            drift = -drift;
        }
        if ((uint64_t)drift > PE_VALIDATE_DEBUG_TIMESTAMP_DRIFT) {
            pe_ctx_add_issue(ctx, 1, 0,
                "debug entry %u: timestamp drift %lld from COFF header",
                index, (long long)drift);
        }
    }
}

/*
 * Parse the complete debug directory.
 */
pe_error_t pe_parse_debug_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    pe_data_dir_t *debug_dir = &ctx->optional.data_dirs[PE_DIR_DEBUG];
    if (debug_dir->rva == 0 || debug_dir->size == 0) {
        return PE_OK;
    }

    uint32_t dir_offset = pe_rva_to_offset(ctx, debug_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_DEBUG,
                         "debug directory RVA 0x%X does not resolve",
                         debug_dir->rva);
        return PE_ERR_INVALID_DEBUG;
    }

    /* Each debug directory entry is 28 bytes */
    uint32_t num_entries = debug_dir->size / 28;
    if (num_entries > PE_MAX_DEBUG_ENTRIES) {
        num_entries = PE_MAX_DEBUG_ENTRIES;
    }

    if (!PE_CHECK_OFFSET(ctx, dir_offset, num_entries * 28)) {
        pe_ctx_add_warning(ctx, "debug directory truncated");
        uint32_t available = (uint32_t)((ctx->size - dir_offset) / 28);
        num_entries = available;
    }

    if (num_entries == 0) {
        return PE_OK;
    }

    pe_debug_table_t *dt = &ctx->debug;
    dt->entries = (pe_debug_entry_t *)calloc(num_entries,
                                              sizeof(pe_debug_entry_t));
    if (!dt->entries) {
        return PE_ERR_ALLOC;
    }
    dt->capacity = num_entries;

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) {
        return PE_ERR_TRUNCATED;
    }

    for (uint32_t i = 0; i < num_entries; i++) {
        pe_debug_entry_t *entry = &dt->entries[dt->count];
        pe_error_t err = pe_parse_debug_entry(ctx, &r, entry);
        if (err != PE_OK) {
            break;
        }

        pe_validate_debug_entry(ctx, entry, i);

        /* Parse CodeView data for type 2 entries */
        if (entry->type == PE_DEBUG_TYPE_CODEVIEW) {
            err = pe_parse_codeview_info(ctx, entry);
            if (err != PE_OK) {
                pe_ctx_add_warning(ctx,
                    "debug entry %u: CodeView parse incomplete", i);
            }
        }

        dt->count++;
    }

    /* Map debug entries to sections */
    pe_map_debug_to_sections(ctx);

    return PE_OK;
}

/* Free a single debug entry */
void pe_free_debug_entry(pe_debug_entry_t *entry)
{
    if (!entry) {
        return;
    }
    if (entry->codeview) {
        free(entry->codeview->pdb_path);
        free(entry->codeview);
        entry->codeview = NULL;
    }
}

/* Free the debug table */
void pe_free_debug_table(pe_debug_table_t *dt)
{
    if (!dt || !dt->entries) {
        return;
    }

    for (uint32_t i = 0; i < dt->count; i++) {
        pe_free_debug_entry(&dt->entries[i]);
    }

    free(dt->entries);
    dt->entries = NULL;
    dt->count = 0;
    dt->capacity = 0;
}

/* Public API: debug entry count */
uint32_t pe_get_debug_entry_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->debug.count;
}

/* Public API: get debug entry */
const pe_debug_entry_t *pe_get_debug_entry(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->debug.count) {
        return NULL;
    }
    return &ctx->debug.entries[index];
}

/* Public API: get PDB path for a debug entry */
const char *pe_get_pdb_path(const pe_ctx_t *ctx, uint32_t index)
{
    const pe_debug_entry_t *entry = pe_get_debug_entry(ctx, index);
    if (!entry || !entry->codeview) {
        return NULL;
    }
    return entry->codeview->pdb_path;
}
