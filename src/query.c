/*
 * query.c — Public Query API
 *
 * Provides convenient accessor functions for querying PE metadata.
 * Accessors read the canonical parsed structures so returned pointers
 * follow the lifetime of the owning context.
 */

#include "internal.h"

/* ----------------------------------------------------------------
 * Header access
 * ---------------------------------------------------------------- */

const pe_dos_header_t *pe_get_dos_header(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return &ctx->dos;
}

const pe_coff_header_t *pe_get_coff_header(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return &ctx->coff;
}

const pe_optional_header_t *pe_get_optional_header(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return &ctx->optional;
}

/* ----------------------------------------------------------------
 * Section queries
 * ---------------------------------------------------------------- */

uint32_t pe_get_section_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->sections.count;
}

const pe_section_t *pe_get_section(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->sections.count) {
        return NULL;
    }
    return &ctx->sections.entries[index];
}

/*
 * Get the resolved name of a section by index.
 */
const char *pe_get_section_name(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->sections.count) {
        return NULL;
    }

    const pe_section_t *sec = &ctx->sections.entries[index];
    return sec->resolved_name ? sec->resolved_name : sec->short_name;
}

/* ----------------------------------------------------------------
 * Resource queries
 * ---------------------------------------------------------------- */

/*
 * Query a resource name by flat index.
 */
const char *pe_query_resource_name(const pe_ctx_t *ctx, uint32_t flat_index)
{
    if (!ctx) {
        return NULL;
    }

    if (flat_index >= ctx->resources.flat_count ||
        !ctx->resources.flat_entries) {
        return NULL;
    }

    pe_resource_node_t *node = ctx->resources.flat_entries[flat_index];
    return node ? node->name : NULL;
}

/* ----------------------------------------------------------------
 * Validation issue queries
 * ---------------------------------------------------------------- */

uint32_t pe_get_issue_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->issue_count;
}

const pe_validation_issue_t *pe_get_issue(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->issue_count) {
        return NULL;
    }
    return &ctx->issues[index];
}

/* ----------------------------------------------------------------
 * Iterator functions
 * ---------------------------------------------------------------- */

/*
 * Iterate over all sections, calling the callback for each.
 * The callback receives the context, section index, section pointer,
 * and the user-supplied data pointer. If the callback returns non-zero,
 * iteration stops and that value is returned.
 */
int pe_iterate_sections(const pe_ctx_t *ctx, pe_section_callback_t cb,
                         void *user)
{
    if (!ctx || !cb) {
        return -1;
    }

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        int ret = cb(ctx, i, &ctx->sections.entries[i], user);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/*
 * Iterate over all import thunks across all descriptors.
 * The callback receives descriptor index, thunk index, and the thunk.
 */
int pe_iterate_imports(const pe_ctx_t *ctx, pe_import_callback_t cb,
                        void *user)
{
    if (!ctx || !cb) {
        return -1;
    }

    for (uint32_t d = 0; d < ctx->imports.count; d++) {
        const pe_import_descriptor_t *desc = &ctx->imports.descriptors[d];
        for (uint32_t t = 0; t < desc->num_thunks; t++) {
            int ret = cb(ctx, d, t, &desc->thunks[t], user);
            if (ret != 0) {
                return ret;
            }
        }
    }

    return 0;
}

/*
 * Iterate over all export entries.
 */
int pe_iterate_exports(const pe_ctx_t *ctx, pe_export_callback_t cb,
                        void *user)
{
    if (!ctx || !cb) {
        return -1;
    }

    for (uint32_t i = 0; i < ctx->exports.num_functions; i++) {
        int ret = cb(ctx, i, &ctx->exports.entries[i], user);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/*
 * Iterate over all flat resource entries.
 */
int pe_iterate_resources(const pe_ctx_t *ctx, pe_resource_callback_t cb,
                          void *user)
{
    if (!ctx || !cb) {
        return -1;
    }

    for (uint32_t i = 0; i < ctx->resources.flat_count; i++) {
        int ret = cb(ctx, i, ctx->resources.flat_entries[i], user);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

/* ----------------------------------------------------------------
 * Statistics computation
 * ---------------------------------------------------------------- */

/*
 * Compute aggregate statistics about the PE image.
 * Fills in the pe_stats_t structure with counts and totals
 * derived from the parsed data.
 */
int pe_compute_stats(const pe_ctx_t *ctx, pe_stats_t *stats)
{
    if (!ctx || !stats) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));

    /* Section statistics */
    stats->total_sections = ctx->sections.count;
    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];

        stats->total_raw_size += sec->raw_data_size;
        stats->total_virtual_size += sec->virtual_size;

        if (sec->characteristics & PE_SCN_CNT_CODE) {
            stats->code_sections++;
        }
        if (sec->characteristics & PE_SCN_CNT_INIT_DATA) {
            stats->data_sections++;
        }
        if (sec->characteristics & PE_SCN_CNT_UNINIT_DATA) {
            stats->data_sections++;
        }
    }

    /* Import statistics */
    stats->total_import_dlls = ctx->imports.count;
    for (uint32_t d = 0; d < ctx->imports.count; d++) {
        stats->total_imports += ctx->imports.descriptors[d].num_thunks;
    }

    /* Export statistics */
    stats->total_exports = ctx->exports.num_functions;
    for (uint32_t i = 0; i < ctx->exports.num_functions; i++) {
        if (ctx->exports.entries[i].is_forwarder) {
            stats->total_forwarders++;
        }
    }

    /* Relocation statistics */
    for (uint32_t i = 0; i < ctx->relocs.count; i++) {
        stats->total_reloc_entries += ctx->relocs.blocks[i].count;
    }

    /* Other counts */
    stats->total_symbols = ctx->symbols.count;
    stats->total_resources = ctx->resources.flat_count;
    stats->total_debug_entries = ctx->debug.count;

    /* Validation statistics */
    stats->validation_issues = ctx->issue_count;
    for (uint32_t i = 0; i < ctx->issue_count; i++) {
        if (ctx->issues[i].severity >= 2) {
            stats->validation_errors++;
        } else if (ctx->issues[i].severity == 1) {
            stats->validation_warnings++;
        }
    }

    return 0;
}

/* ----------------------------------------------------------------
 * Section property queries
 * ---------------------------------------------------------------- */

int pe_section_is_executable(const pe_section_t *sec)
{
    if (!sec) return 0;
    return (sec->characteristics & PE_SCN_MEM_EXECUTE) != 0;
}

int pe_section_is_writable(const pe_section_t *sec)
{
    if (!sec) return 0;
    return (sec->characteristics & PE_SCN_MEM_WRITE) != 0;
}

int pe_section_is_readable(const pe_section_t *sec)
{
    if (!sec) return 0;
    return (sec->characteristics & PE_SCN_MEM_READ) != 0;
}

int pe_section_contains_code(const pe_section_t *sec)
{
    if (!sec) return 0;
    return (sec->characteristics & PE_SCN_CNT_CODE) != 0;
}

int pe_section_contains_data(const pe_section_t *sec)
{
    if (!sec) return 0;
    return (sec->characteristics &
            (PE_SCN_CNT_INIT_DATA | PE_SCN_CNT_UNINIT_DATA)) != 0;
}

uint32_t pe_section_get_alignment(const pe_section_t *sec)
{
    if (!sec) return 0;
    uint32_t align_val = (sec->characteristics & PE_SCN_ALIGN_MASK) >> 20;
    if (align_val == 0) return 0;
    return 1u << (align_val - 1);
}

/* ----------------------------------------------------------------
 * Image property queries
 * ---------------------------------------------------------------- */

int pe_is_dll(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return (ctx->coff.characteristics & 0x2000) != 0;
}

int pe_is_executable(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return (ctx->coff.characteristics & 0x0002) != 0;
}

int pe_is_64bit(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return ctx->optional.is_pe32plus;
}

int pe_has_aslr(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return (ctx->optional.dll_characteristics & PE_DLLCHAR_DYNAMIC_BASE) != 0;
}

int pe_has_dep(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return (ctx->optional.dll_characteristics & PE_DLLCHAR_NX_COMPAT) != 0;
}

int pe_has_cfg(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return (ctx->optional.dll_characteristics & PE_DLLCHAR_GUARD_CF) != 0;
}

int pe_has_seh(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    /* NO_SEH means SEH is disabled; return whether SEH is enabled */
    return (ctx->optional.dll_characteristics & PE_DLLCHAR_NO_SEH) == 0;
}
