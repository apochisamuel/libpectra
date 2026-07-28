/*
 * cache.c — Derived Cache Construction (Phase 12)
 *
 * Builds lookup caches from the parsed PE structures for efficient
 * cross-reference resolution. Each cache maps an index to a pointer
 * derived from the parsed data — import names, export names,
 * relocation targets, debug paths, symbol names, resource names,
 * and section names.
 *
 * Cache entries retain stable indices and mirror selected pointers for
 * convenience. Resolution always refreshes pointer fields from the
 * canonical parsed structures before use. The cache owns only its arrays.
 */

#include "internal.h"

/*
 * Build the import name cache.
 * Maps each import thunk to its name string and DLL name pointer.
 * Import thunk names point into section data buffers.
 * DLL names point to allocated copies held by import descriptors.
 */
pe_error_t pe_build_import_cache(pe_ctx_t *ctx)
{
    pe_import_table_t *it = &ctx->imports;
    pe_cache_t *cache = &ctx->cache;

    if (it->count == 0) {
        return PE_OK;
    }

    /* Count total thunks across all descriptors */
    uint32_t total = 0;
    for (uint32_t d = 0; d < it->count; d++) {
        total += it->descriptors[d].num_thunks;
    }

    if (total == 0) {
        return PE_OK;
    }

    cache->import_entries = (pe_import_cache_entry_t *)calloc(
        total, sizeof(pe_import_cache_entry_t));
    if (!cache->import_entries) {
        return PE_ERR_ALLOC;
    }
    cache->import_capacity = total;

    uint32_t idx = 0;
    for (uint32_t d = 0; d < it->count; d++) {
        pe_import_descriptor_t *desc = &it->descriptors[d];

        for (uint32_t t = 0; t < desc->num_thunks; t++) {
            pe_import_thunk_t *thunk = &desc->thunks[t];
            pe_import_cache_entry_t *entry = &cache->import_entries[idx];

            entry->descriptor_index = d;
            entry->thunk_index = t;
            entry->name_ptr = thunk->name;
            entry->dll_name_ptr = desc->dll_name;

            idx++;
        }
    }

    cache->import_count = idx;
    return PE_OK;
}

/*
 * Build the export name cache.
 * Maps each export entry to its name and forwarder string pointers.
 * Export names point into section data buffers.
 * Forwarder strings are allocated copies held by export entries.
 */
pe_error_t pe_build_export_cache(pe_ctx_t *ctx)
{
    pe_export_table_t *et = &ctx->exports;
    pe_cache_t *cache = &ctx->cache;

    if (et->num_functions == 0) {
        return PE_OK;
    }

    cache->export_entries = (pe_export_cache_entry_t *)calloc(
        et->num_functions, sizeof(pe_export_cache_entry_t));
    if (!cache->export_entries) {
        return PE_ERR_ALLOC;
    }
    cache->export_capacity = et->num_functions;

    for (uint32_t i = 0; i < et->num_functions; i++) {
        pe_export_entry_t *exp = &et->entries[i];
        pe_export_cache_entry_t *entry = &cache->export_entries[i];

        entry->export_index = i;
        entry->name_ptr = exp->name;
        entry->forwarder_ptr = exp->forwarder;
        entry->ordinal = exp->ordinal;
    }

    cache->export_count = et->num_functions;
    return PE_OK;
}

/*
 * Build the relocation target cache.
 * Stores the computed target pointers that reference section data
 * buffers for efficient relocation application.
 */
pe_error_t pe_build_reloc_cache(pe_ctx_t *ctx)
{
    pe_reloc_table_t *rt = &ctx->relocs;
    pe_cache_t *cache = &ctx->cache;

    if (rt->count == 0) {
        return PE_OK;
    }

    /* Count resolved relocation entries */
    uint32_t total = 0;
    for (uint32_t i = 0; i < rt->count; i++) {
        for (uint32_t j = 0; j < rt->blocks[i].count; j++) {
            if (rt->blocks[i].entries[j].resolved) {
                total++;
            }
        }
    }

    if (total == 0) {
        return PE_OK;
    }

    cache->reloc_entries = (pe_reloc_cache_entry_t *)calloc(
        total, sizeof(pe_reloc_cache_entry_t));
    if (!cache->reloc_entries) {
        return PE_ERR_ALLOC;
    }
    cache->reloc_capacity = total;

    uint32_t idx = 0;
    for (uint32_t i = 0; i < rt->count; i++) {
        pe_reloc_block_t *block = &rt->blocks[i];
        for (uint32_t j = 0; j < block->count; j++) {
            pe_reloc_entry_t *rel = &block->entries[j];
            if (!rel->resolved) {
                continue;
            }

            pe_reloc_cache_entry_t *entry = &cache->reloc_entries[idx];
            entry->block_index = i;
            entry->entry_index = j;
            entry->target_ptr = rel->target_ptr;

            /* Determine containing section */
            entry->section_index = pe_find_section_index_by_rva(
                ctx, rel->target_rva);

            idx++;
        }
    }

    cache->reloc_count = idx;
    return PE_OK;
}

/*
 * Build the debug mapping cache.
 * Maps sections to their associated debug entries.
 * PDB path pointers reference allocated strings inside CodeView structs.
 */
pe_error_t pe_build_debug_cache(pe_ctx_t *ctx)
{
    pe_debug_table_t *dt = &ctx->debug;
    pe_cache_t *cache = &ctx->cache;

    if (dt->count == 0) {
        return PE_OK;
    }

    cache->debug_entries = (pe_debug_cache_entry_t *)calloc(
        dt->count, sizeof(pe_debug_cache_entry_t));
    if (!cache->debug_entries) {
        return PE_ERR_ALLOC;
    }
    cache->debug_capacity = dt->count;

    for (uint32_t i = 0; i < dt->count; i++) {
        pe_debug_entry_t *dbg = &dt->entries[i];
        pe_debug_cache_entry_t *entry = &cache->debug_entries[i];

        entry->section_index = (dbg->section_index >= 0)
                               ? (uint32_t)dbg->section_index : UINT32_MAX;
        entry->debug_entry = dbg;

        if (dbg->codeview && dbg->codeview->pdb_path) {
            entry->pdb_path_ptr = dbg->codeview->pdb_path;
        } else {
            entry->pdb_path_ptr = NULL;
        }
    }

    cache->debug_count = dt->count;
    return PE_OK;
}

/*
 * Build the symbol name cache.
 * Maps symbol indices to their resolved name pointers.
 * Symbol names may point into the string table data buffer.
 */
pe_error_t pe_build_symbol_cache(pe_ctx_t *ctx)
{
    pe_symbol_table_t *st = &ctx->symbols;
    pe_cache_t *cache = &ctx->cache;

    if (st->count == 0) {
        return PE_OK;
    }

    cache->symbol_entries = (pe_symbol_cache_entry_t *)calloc(
        st->count, sizeof(pe_symbol_cache_entry_t));
    if (!cache->symbol_entries) {
        return PE_ERR_ALLOC;
    }
    cache->symbol_capacity = st->count;

    for (uint32_t i = 0; i < st->count; i++) {
        pe_symbol_t *sym = &st->entries[i];
        pe_symbol_cache_entry_t *entry = &cache->symbol_entries[i];

        entry->symbol_index = sym->index;
        entry->name_ptr = sym->resolved_name;
        entry->section_number = sym->section_number;
    }

    cache->symbol_count = st->count;
    return PE_OK;
}

/*
 * Build the resource name cache.
 * Maps flat resource indices to their name string pointers.
 * Resource names are allocated copies held by resource nodes.
 */
pe_error_t pe_build_resource_cache(pe_ctx_t *ctx)
{
    pe_resource_tree_t *rt = &ctx->resources;
    pe_cache_t *cache = &ctx->cache;

    if (rt->flat_count == 0) {
        return PE_OK;
    }

    cache->resource_entries = (pe_resource_cache_entry_t *)calloc(
        rt->flat_count, sizeof(pe_resource_cache_entry_t));
    if (!cache->resource_entries) {
        return PE_ERR_ALLOC;
    }
    cache->resource_capacity = rt->flat_count;

    for (uint32_t i = 0; i < rt->flat_count; i++) {
        pe_resource_node_t *node = rt->flat_entries[i];
        pe_resource_cache_entry_t *entry = &cache->resource_entries[i];

        entry->flat_index = i;
        entry->name_ptr = node->name;
        entry->type_id = node->id;
        entry->data_size = node->data_size;
    }

    cache->resource_count = rt->flat_count;
    return PE_OK;
}

/*
 * Build the section name cache.
 * Maps section indices to their resolved name pointers.
 * Section names may point into the string table data buffer
 * (for long names) or into the section header (for short names).
 */
pe_error_t pe_build_section_name_cache(pe_ctx_t *ctx)
{
    pe_section_table_t *st = &ctx->sections;
    pe_cache_t *cache = &ctx->cache;

    if (st->count == 0) {
        return PE_OK;
    }

    cache->section_names = (char **)calloc(st->count, sizeof(char *));
    if (!cache->section_names) {
        return PE_ERR_ALLOC;
    }

    for (uint32_t i = 0; i < st->count; i++) {
        cache->section_names[i] = ctx->sections.entries[i].resolved_name;
    }

    cache->section_name_count = st->count;
    return PE_OK;
}

/*
 * Build all derived caches.
 */
pe_error_t pe_build_cache(pe_ctx_t *ctx)
{
    if (!ctx) {
        return PE_ERR_NULLARG;
    }

    pe_error_t err;

    /* Support safe rebuilds after validation or future reparsing. */
    pe_free_cache(&ctx->cache);

    err = pe_build_import_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "import cache build incomplete");
    }

    err = pe_build_export_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "export cache build incomplete");
    }

    err = pe_build_reloc_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "reloc cache build incomplete");
    }

    err = pe_build_debug_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "debug cache build incomplete");
    }

    err = pe_build_symbol_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "symbol cache build incomplete");
    }

    err = pe_build_resource_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "resource cache build incomplete");
    }

    err = pe_build_section_name_cache(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "section name cache build incomplete");
    }

    ctx->cache.built = 1;
    return PE_OK;
}

/* Free all cache structures */
void pe_free_cache(pe_cache_t *cache)
{
    if (!cache) {
        return;
    }

    free(cache->import_entries);
    cache->import_entries = NULL;
    cache->import_count = 0;

    free(cache->export_entries);
    cache->export_entries = NULL;
    cache->export_count = 0;

    free(cache->reloc_entries);
    cache->reloc_entries = NULL;
    cache->reloc_count = 0;

    free(cache->debug_entries);
    cache->debug_entries = NULL;
    cache->debug_count = 0;

    free(cache->symbol_entries);
    cache->symbol_entries = NULL;
    cache->symbol_count = 0;

    free(cache->resource_entries);
    cache->resource_entries = NULL;
    cache->resource_count = 0;

    free(cache->section_names);
    cache->section_names = NULL;
    cache->section_name_count = 0;

    cache->built = 0;
}
