/*
 * sections.c — Section Table Parsing (Phase 4)
 *
 * Parses the section table entries that follow the optional header.
 * Each entry describes a section's name, virtual address, raw data
 * location, and characteristics. Section data is loaded into
 * allocated buffers for use by subsequent parsing phases.
 *
 * Long section names (> 8 characters) use the COFF string table
 * format: the name field contains "/offset" where offset is a
 * decimal offset into the string table.
 *
 * Reference: Microsoft PE/COFF Specification §4
 */

#include "internal.h"

/*
 * Parse a single section header entry (40 bytes each).
 */
static pe_error_t pe_parse_section_entry(pe_ctx_t *ctx, pe_reader_t *r,
                                          pe_section_t *sec)
{
    PE_UNUSED(ctx);
    memset(sec, 0, sizeof(*sec));

    if (!pe_reader_read_fixed_string(r, sec->short_name, 8)) {
        return PE_ERR_TRUNCATED;
    }

    if (!pe_reader_read_u32(r, &sec->virtual_size)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &sec->virtual_address)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &sec->raw_data_size)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &sec->raw_data_offset)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &sec->reloc_offset)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &sec->linenum_offset)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &sec->num_relocs)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &sec->num_linenums)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &sec->characteristics)) {
        return PE_ERR_TRUNCATED;
    }

    sec->data = NULL;
    sec->data_size = 0;
    sec->data_owned = 0;
    sec->resolved_name = NULL;

    return PE_OK;
}

/*
 * Validate section header fields for consistency.
 */
static void pe_validate_section_entry(pe_ctx_t *ctx, const pe_section_t *sec,
                                       uint32_t index)
{
    if (sec->raw_data_size > 0 && sec->raw_data_offset == 0) {
        pe_ctx_add_warning(ctx,
            "section %u '%s': has raw data size but zero offset",
            index, sec->short_name);
    }

    if (sec->raw_data_offset > 0 && sec->raw_data_offset >= ctx->size) {
        pe_ctx_add_warning(ctx,
            "section %u '%s': raw data offset 0x%X beyond file",
            index, sec->short_name, sec->raw_data_offset);
    }

    if ((uint64_t)sec->raw_data_offset + sec->raw_data_size > ctx->size) {
        pe_ctx_add_warning(ctx,
            "section %u '%s': raw data extends beyond file",
            index, sec->short_name);
    }

    if (sec->virtual_address == 0 && index > 0) {
        pe_ctx_add_warning(ctx,
            "section %u '%s': zero virtual address",
            index, sec->short_name);
    }

    /* Check alignment against file alignment */
    uint32_t fa = ctx->optional.file_alignment;
    if (fa > 0 && sec->raw_data_offset > 0 &&
        (sec->raw_data_offset % fa) != 0) {
        pe_ctx_add_issue(ctx, 1, index,
            "section %u '%s': raw data offset 0x%X not aligned to %u",
            index, sec->short_name, sec->raw_data_offset, fa);
    }
}

/*
 * Parse the section table at the given file offset.
 * Section count is read from the COFF header.
 */
pe_error_t pe_parse_section_table(pe_ctx_t *ctx, uint32_t offset)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    uint32_t count = ctx->coff.num_sections;
    if (count == 0) {
        return PE_OK;
    }

    uint32_t table_size = count * 40;
    if (!PE_CHECK_OFFSET(ctx, offset, table_size)) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED,
                         "section table truncated at offset 0x%X", offset);
        return PE_ERR_TRUNCATED;
    }

    pe_section_table_t *st = &ctx->sections;
    st->entries = (pe_section_t *)calloc(count, sizeof(pe_section_t));
    if (!st->entries) {
        return PE_ERR_ALLOC;
    }
    st->count = count;
    st->capacity = count;

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, offset)) {
        return PE_ERR_TRUNCATED;
    }

    for (uint32_t i = 0; i < count; i++) {
        pe_error_t err = pe_parse_section_entry(ctx, &r, &st->entries[i]);
        if (err != PE_OK) {
            pe_ctx_set_error(ctx, err,
                             "failed to parse section header %u", i);
            return err;
        }
        pe_validate_section_entry(ctx, &st->entries[i], i);
    }

    return PE_OK;
}

/*
 * Load raw data for each section into allocated buffers.
 * Section data is copied from the file so it can be modified
 * during relocation application.
 */
pe_error_t pe_load_section_data(pe_ctx_t *ctx)
{
    pe_section_table_t *st = &ctx->sections;

    for (uint32_t i = 0; i < st->count; i++) {
        pe_section_t *sec = &st->entries[i];

        if (sec->raw_data_size == 0 || sec->raw_data_offset == 0) {
            sec->data = NULL;
            sec->data_size = 0;
            continue;
        }

        uint32_t end_offset = sec->raw_data_offset + sec->raw_data_size;
        if (end_offset < sec->raw_data_offset) {
            pe_ctx_add_warning(ctx,
                "section %u: raw data size overflow", i);
            continue;
        }

        uint32_t available = sec->raw_data_size;
        if (sec->raw_data_offset >= ctx->size) {
            available = 0;
        } else if ((uint64_t)end_offset > ctx->size) {
            available = (uint32_t)(ctx->size - sec->raw_data_offset);
        }

        if (available == 0) {
            sec->data = NULL;
            sec->data_size = 0;
            continue;
        }

        sec->data = (uint8_t *)malloc(available);
        if (!sec->data) {
            pe_ctx_set_error(ctx, PE_ERR_ALLOC,
                             "failed to allocate %u bytes for section %u",
                             available, i);
            return PE_ERR_ALLOC;
        }

        memcpy(sec->data, ctx->data + sec->raw_data_offset, available);
        sec->data_size = available;
        sec->data_owned = 1;
    }

    return PE_OK;
}

/*
 * Resolve long section names from the COFF string table.
 * Names starting with '/' followed by a decimal offset are
 * references into the string table.
 */
pe_error_t pe_resolve_section_names(pe_ctx_t *ctx)
{
    pe_section_table_t *st = &ctx->sections;

    for (uint32_t i = 0; i < st->count; i++) {
        pe_section_t *sec = &st->entries[i];

        if (sec->short_name[0] != '/') {
            /* Short name, store pointer to embedded name */
            sec->resolved_name = sec->short_name;
            continue;
        }

        /* Parse string table offset from "/digits" */
        uint32_t str_offset = 0;
        int valid = 1;
        for (int j = 1; j < 8 && sec->short_name[j] != '\0'; j++) {
            char ch = sec->short_name[j];
            if (ch < '0' || ch > '9') {
                valid = 0;
                break;
            }
            str_offset = str_offset * 10 + (uint32_t)(ch - '0');
        }

        if (!valid) {
            sec->resolved_name = sec->short_name;
            pe_ctx_add_warning(ctx,
                "section %u: invalid string table reference '%s'",
                i, sec->short_name);
            continue;
        }

        /* Look up in string table. Pointer into string table data. */
        const char *name = pe_string_table_lookup(&ctx->strings, str_offset);
        if (name) {
            sec->resolved_name = (char *)name;
        } else {
            sec->resolved_name = sec->short_name;
            pe_ctx_add_warning(ctx,
                "section %u: string table offset %u out of range",
                i, str_offset);
        }
    }

    return PE_OK;
}

/*
 * Reload section data from the original file buffer.
 * Used during validation when section data needs to be refreshed
 * after detecting inconsistencies.
 */
pe_error_t pe_reload_section_data(pe_ctx_t *ctx, uint32_t section_index)
{
    if (section_index >= ctx->sections.count) {
        return PE_ERR_INVALID_SECTION;
    }

    pe_section_t *sec = &ctx->sections.entries[section_index];

    /* Release current data buffer */
    if (sec->data && sec->data_owned) {
        free(sec->data);
        sec->data = NULL;
        sec->data_size = 0;
    }

    if (sec->raw_data_size == 0 || sec->raw_data_offset == 0) {
        return PE_OK;
    }

    if (sec->raw_data_offset >= ctx->size) {
        return PE_OK;
    }

    uint32_t available = sec->raw_data_size;
    uint64_t end = (uint64_t)sec->raw_data_offset + sec->raw_data_size;
    if (end > ctx->size) {
        available = (uint32_t)(ctx->size - sec->raw_data_offset);
    }

    sec->data = (uint8_t *)malloc(available);
    if (!sec->data) {
        return PE_ERR_ALLOC;
    }

    memcpy(sec->data, ctx->data + sec->raw_data_offset, available);
    sec->data_size = available;
    sec->data_owned = 1;

    return PE_OK;
}

/* Free a single section's data buffer */
void pe_free_section_data(pe_section_t *section)
{
    if (!section) {
        return;
    }
    if (section->data && section->data_owned) {
        free(section->data);
    }
    section->data = NULL;
    section->data_size = 0;
    section->data_owned = 0;
}

/* Free the entire section table */
void pe_free_section_table(pe_section_table_t *table)
{
    if (!table || !table->entries) {
        return;
    }

    for (uint32_t i = 0; i < table->count; i++) {
        pe_free_section_data(&table->entries[i]);
    }

    free(table->entries);
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}

/*
 * Find a section by name (case-sensitive).
 */
const pe_section_t *pe_find_section_by_name(const pe_ctx_t *ctx, const char *name)
{
    if (!ctx || !name) {
        return NULL;
    }

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        const char *sname = sec->resolved_name ? sec->resolved_name
                                                : sec->short_name;
        if (strcmp(sname, name) == 0) {
            return sec;
        }
    }

    return NULL;
}

/*
 * Find a section that contains the given RVA.
 */
const pe_section_t *pe_find_section_by_rva(const pe_ctx_t *ctx, uint32_t rva)
{
    if (!ctx) {
        return NULL;
    }

    uint32_t index = pe_find_section_index_by_rva(ctx, rva);
    if (index == UINT32_MAX) {
        return NULL;
    }
    return &ctx->sections.entries[index];
}
