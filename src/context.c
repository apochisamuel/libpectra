/*
 * context.c — Context lifecycle and error management
 *
 * Manages the pe_ctx_t object that carries all parsing state through
 * the analysis pipeline. Provides error reporting with formatted
 * messages and a validation issue accumulator.
 */

#include "internal.h"
#include <stdarg.h>

/* Allocate a zeroed context */
pe_ctx_t *pe_ctx_alloc(void)
{
    pe_ctx_t *ctx = (pe_ctx_t *)calloc(1, sizeof(pe_ctx_t));
    if (!ctx) {
        return NULL;
    }
    ctx->last_error = PE_OK;
    ctx->error_msg[0] = '\0';
    return ctx;
}

/* Free all resources held by the context */
void pe_ctx_free(pe_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    pe_free_section_table(&ctx->sections);
    pe_free_string_table(&ctx->strings);
    pe_free_symbol_table(&ctx->symbols);
    pe_free_import_table(&ctx->imports);
    pe_free_export_table(&ctx->exports);
    pe_free_reloc_table(&ctx->relocs);
    pe_free_debug_table(&ctx->debug);
    pe_free_resource_tree(&ctx->resources);
    pe_free_exception_table(&ctx->exceptions);
    pe_free_delay_import_table(&ctx->delay_imports);
    pe_free_cache(&ctx->cache);

    free(ctx->issues);
    ctx->issues = NULL;
    ctx->issue_count = 0;
    ctx->issue_capacity = 0;

    free(ctx);
}

/* Set error code and formatted message */
void pe_ctx_set_error(pe_ctx_t *ctx, pe_error_t err, const char *fmt, ...)
{
    if (!ctx) {
        return;
    }
    ctx->last_error = err;
    ctx->error_count++;

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(ctx->error_msg, sizeof(ctx->error_msg), fmt, ap);
        va_end(ap);
    } else {
        ctx->error_msg[0] = '\0';
    }
}

/* Record a non-fatal warning */
void pe_ctx_add_warning(pe_ctx_t *ctx, const char *fmt, ...)
{
    if (!ctx) {
        return;
    }
    ctx->warning_count++;

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(ctx->error_msg, sizeof(ctx->error_msg), fmt, ap);
        va_end(ap);
    }
}

/* Append a validation issue to the issue list */
void pe_ctx_add_issue(pe_ctx_t *ctx, int severity, uint32_t section,
                      const char *fmt, ...)
{
    if (!ctx) {
        return;
    }

    if (ctx->issue_count >= PE_MAX_ISSUES) {
        return;
    }

    if (ctx->issue_count >= ctx->issue_capacity) {
        uint32_t newcap = ctx->issue_capacity == 0 ? 32 : ctx->issue_capacity * 2;
        if (newcap > PE_MAX_ISSUES) {
            newcap = PE_MAX_ISSUES;
        }
        pe_validation_issue_t *tmp = (pe_validation_issue_t *)realloc(
            ctx->issues, newcap * sizeof(pe_validation_issue_t));
        if (!tmp) {
            return;
        }
        ctx->issues = tmp;
        ctx->issue_capacity = newcap;
    }

    pe_validation_issue_t *issue = &ctx->issues[ctx->issue_count];
    issue->severity = severity;
    issue->section_index = section;

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(issue->message, sizeof(issue->message), fmt, ap);
        va_end(ap);
    } else {
        issue->message[0] = '\0';
    }

    ctx->issue_count++;
    if (severity >= 2) {
        ctx->nonfatal_errors++;
    }
}

/* Return human-readable error string */
const char *pe_error_string(pe_error_t err)
{
    switch (err) {
    case PE_OK:                       return "success";
    case PE_ERR_NULLARG:              return "null argument";
    case PE_ERR_TRUNCATED:            return "data truncated";
    case PE_ERR_INVALID_DOS:          return "invalid DOS header";
    case PE_ERR_INVALID_PE_SIG:       return "invalid PE signature";
    case PE_ERR_INVALID_COFF:         return "invalid COFF header";
    case PE_ERR_INVALID_OPTIONAL:     return "invalid optional header";
    case PE_ERR_INVALID_SECTION:      return "invalid section header";
    case PE_ERR_INVALID_STRING_TABLE: return "invalid string table";
    case PE_ERR_INVALID_SYMBOL:       return "invalid symbol table";
    case PE_ERR_INVALID_IMPORT:       return "invalid import table";
    case PE_ERR_INVALID_EXPORT:       return "invalid export table";
    case PE_ERR_INVALID_RELOC:        return "invalid relocation table";
    case PE_ERR_INVALID_DEBUG:        return "invalid debug directory";
    case PE_ERR_INVALID_RESOURCE:     return "invalid resource directory";
    case PE_ERR_VALIDATION_FAILED:    return "validation failed";
    case PE_ERR_RESOLVE_FAILED:       return "resolution failed";
    case PE_ERR_CHECKSUM_MISMATCH:    return "checksum mismatch";
    case PE_ERR_ALLOC:                return "memory allocation failed";
    case PE_ERR_OVERFLOW:             return "integer overflow";
    case PE_ERR_UNSUPPORTED:          return "unsupported feature";
    default:                          return "unknown error";
    }
}

/* ----------------------------------------------------------------
 * Public lifecycle API
 * ---------------------------------------------------------------- */

/*
 * Open a PE/COFF binary for analysis.
 *
 * Runs the full parsing pipeline: DOS header, PE signature,
 * COFF header, optional header, section table, string table,
 * symbol table, imports, exports, relocations, debug directory,
 * resource tree, cache construction, validation, and
 * cross-reference resolution.
 *
 * The input buffer must remain valid for the lifetime of the context.
 */
pe_ctx_t *pe_open(const uint8_t *data, size_t size)
{
    if (!data || size < 64) {
        return NULL;
    }

    pe_ctx_t *ctx = pe_ctx_alloc();
    if (!ctx) {
        return NULL;
    }

    ctx->data = data;
    ctx->size = size;

    /* Phase 1: DOS header */
    pe_error_t err = pe_parse_dos_header(ctx);
    if (err != PE_OK) {
        pe_ctx_free(ctx);
        return NULL;
    }

    /* Phase 2: PE signature + COFF header */
    err = pe_parse_pe_signature(ctx, ctx->dos.e_lfanew);
    if (err != PE_OK) {
        pe_ctx_free(ctx);
        return NULL;
    }

    uint32_t coff_offset = ctx->dos.e_lfanew + 4;
    err = pe_parse_coff_header(ctx);
    if (err != PE_OK) {
        pe_ctx_free(ctx);
        return NULL;
    }

    /* Phase 3: Optional header */
    uint32_t opt_offset = coff_offset + 20;
    if (ctx->coff.optional_header_size > 0) {
        err = pe_parse_optional_header(ctx, opt_offset);
        if (err != PE_OK) {
            pe_ctx_free(ctx);
            return NULL;
        }
    }

    /* Phase 4: Section table */
    uint32_t section_offset = opt_offset + ctx->coff.optional_header_size;
    err = pe_parse_section_table(ctx, section_offset);
    if (err != PE_OK) {
        pe_ctx_free(ctx);
        return NULL;
    }

    err = pe_load_section_data(ctx);
    if (err != PE_OK) {
        pe_ctx_free(ctx);
        return NULL;
    }

    /* Phase 5: String table */
    err = pe_parse_string_table(ctx);
    if (err != PE_OK && err != PE_ERR_TRUNCATED) {
        pe_ctx_add_warning(ctx, "string table parse incomplete");
    }

    /* Resolve long section names after string table is loaded */
    pe_resolve_section_names(ctx);

    /* Phase 6: Symbol table */
    err = pe_parse_symbol_table(ctx);
    if (err != PE_OK && err != PE_ERR_TRUNCATED) {
        pe_ctx_add_warning(ctx, "symbol table parse incomplete");
    }

    pe_resolve_symbol_names(ctx);

    /* Phase 7: Import table */
    if (ctx->optional.data_dirs[PE_DIR_IMPORT].rva != 0) {
        err = pe_parse_import_table(ctx);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx, "import table parse incomplete");
        }
    }

    /* Phase 8: Export table */
    if (ctx->optional.data_dirs[PE_DIR_EXPORT].rva != 0) {
        err = pe_parse_export_table(ctx);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx, "export table parse incomplete");
        }
    }

    /* Phase 9: Relocation table */
    if (ctx->optional.data_dirs[PE_DIR_BASERELOC].rva != 0) {
        err = pe_parse_reloc_table(ctx);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx, "relocation table parse incomplete");
        }
    }

    /* Phase 10: Debug directory */
    if (ctx->optional.data_dirs[PE_DIR_DEBUG].rva != 0) {
        err = pe_parse_debug_table(ctx);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx, "debug directory parse incomplete");
        }
    }

    /* Phase 11: Resource tree */
    if (ctx->optional.data_dirs[PE_DIR_RESOURCE].rva != 0) {
        err = pe_parse_resource_tree(ctx);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx, "resource tree parse incomplete");
        }
    }

    ctx->parsed = 1;

    /* Phase 7b: Delay import directory */
    err = pe_parse_delay_import_table(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "delay import table parse incomplete");
    }

    /* Phase 11b: Exception directory (x64 only) */
    err = pe_parse_exception_table(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "exception table parse incomplete");
    }

    /* Phase 12: Cross-table validation */
    err = pe_validate(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "validation incomplete");
    }
    ctx->validated = 1;

    /* Phase 13: Build caches from the validated canonical structures */
    err = pe_build_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "cache construction incomplete");
    }

    /* Phase 14: Cross-reference resolution */
    err = pe_resolve(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "cross-reference resolution incomplete");
    }
    ctx->resolved = 1;

    return ctx;
}

/* Release context and all associated memory */
void pe_close(pe_ctx_t *ctx)
{
    pe_ctx_free(ctx);
}

/* Return current error code */
pe_error_t pe_get_error(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return PE_ERR_NULLARG;
    }
    return ctx->last_error;
}

/* Return current error message */
const char *pe_get_error_message(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return "null context";
    }
    return ctx->error_msg;
}
