/*
 * symbols.c — COFF Symbol Table Parsing (Phase 6)
 *
 * Parses the COFF symbol table whose offset and count are specified
 * in the COFF file header. Each symbol entry is 18 bytes. Symbols
 * with names longer than 8 bytes store a zero-filled 4-byte prefix
 * followed by a 4-byte offset into the string table.
 *
 * Auxiliary symbol entries follow certain symbol types and occupy
 * additional 18-byte slots.
 *
 * Reference: Microsoft PE/COFF Specification §5.4
 */

#include "internal.h"

/* Storage class name lookup */
const char *pe_get_symbol_class_name(uint8_t storage_class)
{
    switch (storage_class) {
    case PE_SYM_CLASS_NULL:          return "NULL";
    case PE_SYM_CLASS_EXTERNAL:      return "EXTERNAL";
    case PE_SYM_CLASS_STATIC:        return "STATIC";
    case PE_SYM_CLASS_LABEL:         return "LABEL";
    case PE_SYM_CLASS_FUNCTION:      return "FUNCTION";
    case PE_SYM_CLASS_FILE:          return "FILE";
    case PE_SYM_CLASS_SECTION:       return "SECTION";
    case PE_SYM_CLASS_WEAK_EXTERNAL: return "WEAK_EXTERNAL";
    default:                         return "OTHER";
    }
}

/*
 * Parse symbol name from the 8-byte name field.
 * If the first 4 bytes are zero, the remaining 4 bytes are
 * an offset into the string table.
 */
static void pe_parse_symbol_name(pe_ctx_t *ctx, pe_reader_t *r,
                                  pe_symbol_t *sym)
{
    uint8_t name_bytes[8];

    if (!pe_reader_read_bytes(r, name_bytes, 8)) {
        sym->short_name[0] = '\0';
        return;
    }

    /* Check for string table reference (first 4 bytes are zero) */
    uint32_t first_four = PE_READ_U32(name_bytes);

    if (first_four == 0) {
        /* String table offset in bytes 4-7 */
        uint32_t str_offset = PE_READ_U32(name_bytes + 4);
        sym->short_name[0] = '\0';

        /* Store the string table offset for later resolution */
        const char *name = pe_string_table_lookup(&ctx->strings, str_offset);
        if (name) {
            sym->resolved_name = (char *)name;
        } else {
            snprintf(sym->short_name, sizeof(sym->short_name),
                     "??_%u", str_offset);
            sym->resolved_name = sym->short_name;
        }
    } else {
        /* Inline name (up to 8 characters) */
        memcpy(sym->short_name, name_bytes, 8);
        sym->short_name[8] = '\0';
        sym->resolved_name = sym->short_name;
    }
}

/*
 * Parse a single 18-byte symbol entry from the reader.
 */
static pe_error_t pe_parse_symbol_entry(pe_ctx_t *ctx, pe_reader_t *r,
                                         pe_symbol_t *sym, uint32_t index)
{
    memset(sym, 0, sizeof(*sym));
    sym->index = index;

    pe_parse_symbol_name(ctx, r, sym);

    if (!pe_reader_read_u32(r, &sym->value)) {
        return PE_ERR_TRUNCATED;
    }

    uint16_t section_raw;
    if (!pe_reader_read_u16(r, &section_raw)) {
        return PE_ERR_TRUNCATED;
    }
    sym->section_number = (int16_t)section_raw;

    if (!pe_reader_read_u16(r, &sym->type)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u8(r, &sym->storage_class)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u8(r, &sym->aux_count)) {
        return PE_ERR_TRUNCATED;
    }

    return PE_OK;
}

/*
 * Validate a symbol entry for consistency.
 */
static void pe_validate_symbol(pe_ctx_t *ctx, const pe_symbol_t *sym,
                                uint32_t index)
{
    /* Section number validation */
    if (sym->section_number > 0) {
        uint16_t sec_idx = (uint16_t)(sym->section_number - 1);
        if (sec_idx >= ctx->sections.count) {
            pe_ctx_add_warning(ctx,
                "symbol %u '%s': section number %d out of range",
                index, sym->resolved_name ? sym->resolved_name : "??",
                sym->section_number);
        }
    }

    /* Check for reserved section numbers */
    if (sym->section_number == 0) {
        /* IMAGE_SYM_UNDEFINED — external reference */
    } else if (sym->section_number == -1) {
        /* IMAGE_SYM_ABSOLUTE */
    } else if (sym->section_number == -2) {
        /* IMAGE_SYM_DEBUG */
    }

    PE_UNUSED(index);
}

/*
 * Parse the complete COFF symbol table.
 */
pe_error_t pe_parse_symbol_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    uint32_t sym_offset = ctx->coff.symbol_table_offset;
    uint32_t sym_count = ctx->coff.num_symbols;

    if (sym_offset == 0 || sym_count == 0) {
        return PE_OK;
    }

    uint32_t table_size = sym_count * 18;
    if (!PE_CHECK_OFFSET(ctx, sym_offset, table_size)) {
        pe_ctx_add_warning(ctx,
            "symbol table extends beyond file boundary");
        /* Reduce count to what fits */
        uint32_t available = (uint32_t)((ctx->size - sym_offset) / 18);
        sym_count = available;
        if (sym_count == 0) {
            return PE_ERR_TRUNCATED;
        }
    }

    if (sym_count > PE_MAX_SYMBOLS) {
        pe_ctx_add_warning(ctx,
            "clamping symbol count from %u to %u", sym_count, PE_MAX_SYMBOLS);
        sym_count = PE_MAX_SYMBOLS;
    }

    pe_symbol_table_t *st = &ctx->symbols;

    /* Allocate symbol array (we may have fewer usable entries due to aux) */
    st->entries = (pe_symbol_t *)calloc(sym_count, sizeof(pe_symbol_t));
    if (!st->entries) {
        return PE_ERR_ALLOC;
    }
    st->capacity = sym_count;

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, sym_offset)) {
        return PE_ERR_TRUNCATED;
    }

    uint32_t actual_count = 0;
    uint32_t i = 0;

    while (i < sym_count) {
        if (actual_count >= st->capacity) {
            break;
        }

        pe_symbol_t *sym = &st->entries[actual_count];
        pe_error_t err = pe_parse_symbol_entry(ctx, &r, sym, i);

        if (err != PE_OK) {
            pe_ctx_add_warning(ctx,
                "symbol %u: parse failed, stopping", i);
            break;
        }

        pe_validate_symbol(ctx, sym, i);

        /* Skip auxiliary entries */
        uint8_t aux = sym->aux_count;
        i += 1 + aux;

        if (aux > 0) {
            if (!pe_reader_skip(&r, (size_t)aux * 18)) {
                pe_ctx_add_warning(ctx,
                    "symbol %u: aux entries truncated", i);
                break;
            }
        }

        actual_count++;
    }

    st->count = actual_count;
    return PE_OK;
}

/*
 * Resolve symbol names that reference the string table.
 * Called after the string table is loaded.
 */
pe_error_t pe_resolve_symbol_names(pe_ctx_t *ctx)
{
    pe_symbol_table_t *st = &ctx->symbols;

    for (uint32_t i = 0; i < st->count; i++) {
        pe_symbol_t *sym = &st->entries[i];

        /* If resolved_name already points to string table, nothing to do */
        if (sym->resolved_name && sym->resolved_name != sym->short_name) {
            continue;
        }

        /* Try to resolve via string table if short_name starts with "??_" */
        if (sym->short_name[0] == '?' && sym->short_name[1] == '?' &&
            sym->short_name[2] == '_') {
            uint32_t offset = 0;
            int valid = 1;
            for (int j = 3; j < 8 && sym->short_name[j] != '\0'; j++) {
                char ch = sym->short_name[j];
                if (ch < '0' || ch > '9') {
                    valid = 0;
                    break;
                }
                offset = offset * 10 + (uint32_t)(ch - '0');
            }
            if (valid && offset > 0) {
                const char *name = pe_string_table_lookup(&ctx->strings, offset);
                if (name) {
                    sym->resolved_name = (char *)name;
                }
            }
        }
    }

    return PE_OK;
}

/* Free symbol table resources */
void pe_free_symbol_table(pe_symbol_table_t *st)
{
    if (!st) {
        return;
    }
    free(st->entries);
    st->entries = NULL;
    st->count = 0;
    st->capacity = 0;
}

/* Public API: symbol count */
uint32_t pe_get_symbol_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->symbols.count;
}

/* Public API: get symbol by index */
const pe_symbol_t *pe_get_symbol(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->symbols.count) {
        return NULL;
    }
    return &ctx->symbols.entries[index];
}

/* Public API: get symbol name by index */
const char *pe_get_symbol_name(const pe_ctx_t *ctx, uint32_t index)
{
    const pe_symbol_t *sym = pe_get_symbol(ctx, index);
    if (!sym) {
        return NULL;
    }
    return sym->resolved_name;
}
