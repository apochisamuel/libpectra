/*
 * strings.c — COFF String Table Parsing (Phase 5)
 *
 * The COFF string table immediately follows the symbol table.
 * It stores names longer than 8 bytes, referenced by symbols
 * and section headers. The first 4 bytes contain the total size
 * of the string table (including the size field itself).
 *
 * String table entries are null-terminated and indexed by byte
 * offset from the start of the table (the size field is at
 * offset 0, first string at offset 4).
 *
 * Reference: Microsoft PE/COFF Specification §5.6
 */

#include "internal.h"

/*
 * Compute the file offset of the string table.
 * It follows the symbol table: symbol_table_offset + num_symbols * 18.
 */
static uint32_t pe_string_table_offset(const pe_ctx_t *ctx)
{
    if (ctx->coff.symbol_table_offset == 0) {
        return 0;
    }
    return ctx->coff.symbol_table_offset + ctx->coff.num_symbols * 18;
}

/*
 * Build an index of string entry pointers for faster lookup.
 * Walks the string table and records the start of each string.
 */
static pe_error_t pe_index_string_entries(pe_ctx_t *ctx)
{
    pe_string_table_t *st = &ctx->strings;

    if (st->size <= 4) {
        st->entries = NULL;
        st->num_entries = 0;
        return PE_OK;
    }

    /* Count strings by scanning for null terminators */
    uint32_t count = 0;
    uint32_t pos = 4;
    while (pos < st->size) {
        if (st->data[pos] == '\0') {
            count++;
            pos++;
            continue;
        }
        pos++;
    }

    if (count == 0) {
        return PE_OK;
    }

    if (count > PE_MAX_SYMBOLS) {
        count = PE_MAX_SYMBOLS;
    }

    st->entries = (char **)calloc(count, sizeof(char *));
    if (!st->entries) {
        return PE_ERR_ALLOC;
    }
    st->entries_capacity = count;

    /* Second pass: record string start positions */
    uint32_t idx = 0;
    pos = 4;
    int at_start = 1;

    while (pos < st->size && idx < count) {
        if (at_start && st->data[pos] != '\0') {
            st->entries[idx] = (char *)(st->data + pos);
            idx++;
            at_start = 0;
        }
        if (st->data[pos] == '\0') {
            at_start = 1;
        }
        pos++;
    }

    st->num_entries = idx;
    return PE_OK;
}

/*
 * Parse the COFF string table from the file data.
 */
pe_error_t pe_parse_string_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    uint32_t st_offset = pe_string_table_offset(ctx);
    if (st_offset == 0) {
        return PE_OK;
    }

    if (!PE_CHECK_OFFSET(ctx, st_offset, 4)) {
        pe_ctx_add_warning(ctx, "string table offset beyond file");
        return PE_ERR_TRUNCATED;
    }

    pe_string_table_t *st = &ctx->strings;

    /* First 4 bytes are the total size */
    uint32_t total_size = PE_READ_U32(ctx->data + st_offset);

    if (total_size < 4) {
        pe_ctx_add_warning(ctx, "string table size too small: %u", total_size);
        total_size = 4;
    }

    if (total_size > PE_MAX_STRING_TABLE) {
        pe_ctx_add_warning(ctx, "string table too large: %u", total_size);
        total_size = PE_MAX_STRING_TABLE;
    }

    /* Clamp to available file data */
    uint32_t available = total_size;
    if (st_offset + total_size > ctx->size) {
        available = (uint32_t)(ctx->size - st_offset);
    }

    /* Allocate and copy string table data */
    st->data = (uint8_t *)malloc(available);
    if (!st->data) {
        return PE_ERR_ALLOC;
    }

    memcpy(st->data, ctx->data + st_offset, available);
    st->size = available;

    /* Ensure null termination at the end */
    if (available > 0) {
        st->data[available - 1] = '\0';
    }

    /* Build string index */
    pe_error_t err = pe_index_string_entries(ctx);
    if (err != PE_OK) {
        return err;
    }

    return PE_OK;
}

/*
 * Rebuild the string table from the file data.
 * Used during validation when the string table needs to be
 * refreshed due to detected inconsistencies.
 */
pe_error_t pe_rebuild_string_table(pe_ctx_t *ctx)
{
    /* Release existing string table */
    pe_free_string_table(&ctx->strings);

    /* Re-parse from file data */
    return pe_parse_string_table(ctx);
}

/*
 * Look up a string by its byte offset in the string table.
 * Returns a pointer to the string data, or NULL if the offset
 * is out of range.
 */
const char *pe_string_table_lookup(const pe_string_table_t *st, uint32_t offset)
{
    if (!st || !st->data) {
        return NULL;
    }

    if (offset >= st->size) {
        return NULL;
    }

    if (offset < 4) {
        return NULL;
    }

    return (const char *)(st->data + offset);
}

/* Free string table resources */
void pe_free_string_table(pe_string_table_t *st)
{
    if (!st) {
        return;
    }

    free(st->data);
    st->data = NULL;
    st->size = 0;

    free(st->entries);
    st->entries = NULL;
    st->num_entries = 0;
    st->entries_capacity = 0;
}

/* Public API: get string by offset */
const char *pe_get_string(const pe_ctx_t *ctx, uint32_t offset)
{
    if (!ctx) {
        return NULL;
    }
    return pe_string_table_lookup(&ctx->strings, offset);
}
