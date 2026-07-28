/*
 * resolve.c — Cross-Reference Resolution (Phase 14)
 *
 * Performs cross-reference checks after parsing and validation. Cache
 * entries provide stable indices into the canonical parsed structures;
 * pointers are refreshed from those structures before they are used.
 */

#include "internal.h"

static size_t pe_bounded_strlen(const char *str, size_t limit)
{
    size_t len = 0;

    if (!str) {
        return 0;
    }

    while (len < limit && str[len] != '\0') {
        len++;
    }
    return len;
}

pe_error_t pe_resolve_import_names(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t resolved = 0;

    for (uint32_t i = 0; i < cache->import_count; i++) {
        pe_import_cache_entry_t *cached = &cache->import_entries[i];
        if (cached->descriptor_index >= ctx->imports.count) {
            continue;
        }

        pe_import_descriptor_t *desc =
            &ctx->imports.descriptors[cached->descriptor_index];
        if (cached->thunk_index >= desc->num_thunks) {
            continue;
        }

        pe_import_thunk_t *thunk = &desc->thunks[cached->thunk_index];
        cached->name_ptr = thunk->name;
        cached->dll_name_ptr = desc->dll_name;

        size_t name_len = pe_bounded_strlen(thunk->name, 512);
        if (name_len > 0 && name_len < 512) {
            resolved++;
        }

        if (desc->dll_name) {
            size_t dll_len = pe_bounded_strlen(desc->dll_name, 256);
            PE_UNUSED(dll_len);
        }
    }

    ctx->resolve_state.resolved_import_count = resolved;
    ctx->resolve_state.imports_resolved = 1;
    return PE_OK;
}

pe_error_t pe_resolve_export_names(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t resolved = 0;

    for (uint32_t i = 0; i < cache->export_count; i++) {
        pe_export_cache_entry_t *cached = &cache->export_entries[i];
        if (cached->export_index >= ctx->exports.num_functions) {
            continue;
        }

        pe_export_entry_t *entry =
            &ctx->exports.entries[cached->export_index];
        cached->name_ptr = entry->name;
        cached->forwarder_ptr = entry->forwarder;

        size_t name_len = pe_bounded_strlen(entry->name, 512);
        if (name_len > 0 && name_len < 512) {
            resolved++;
        }

        size_t fwd_len = pe_bounded_strlen(entry->forwarder, 512);
        if (fwd_len > 0 && fwd_len < 512) {
            int has_dot = 0;
            for (size_t j = 0; j < fwd_len; j++) {
                if (entry->forwarder[j] == '.') {
                    has_dot = 1;
                    break;
                }
            }
            if (has_dot) {
                resolved++;
            }
        }
    }

    ctx->resolve_state.resolved_export_count = resolved;
    ctx->resolve_state.exports_resolved = 1;
    return PE_OK;
}

pe_error_t pe_resolve_relocations(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t applied = 0;

    for (uint32_t i = 0; i < cache->reloc_count; i++) {
        pe_reloc_cache_entry_t *cached = &cache->reloc_entries[i];
        if (cached->block_index >= ctx->relocs.count) {
            continue;
        }

        pe_reloc_block_t *block = &ctx->relocs.blocks[cached->block_index];
        if (cached->entry_index >= block->count) {
            continue;
        }

        pe_reloc_entry_t *rel = &block->entries[cached->entry_index];
        if (!rel->resolved) {
            continue;
        }

        size_t width;
        switch (rel->type) {
        case PE_REL_BASED_HIGHLOW:
            width = 4;
            break;
        case PE_REL_BASED_DIR64:
            width = 8;
            break;
        case PE_REL_BASED_HIGH:
        case PE_REL_BASED_LOW:
            width = 2;
            break;
        default:
            continue;
        }

        uint32_t sec_idx = pe_find_section_index_by_rva(ctx, rel->target_rva);
        if (sec_idx == UINT32_MAX) {
            rel->resolved = 0;
            rel->target_ptr = NULL;
            cached->target_ptr = NULL;
            continue;
        }

        uint8_t *target = pe_section_rva_to_ptr(ctx, sec_idx,
                                                rel->target_rva, width);
        if (!target) {
            rel->resolved = 0;
            rel->target_ptr = NULL;
            cached->target_ptr = NULL;
            continue;
        }

        rel->target_ptr = target;
        cached->target_ptr = target;
        cached->section_index = sec_idx;

        uint64_t current_value = 0;
        switch (rel->type) {
        case PE_REL_BASED_HIGHLOW:
            current_value = PE_READ_U32(target);
            break;
        case PE_REL_BASED_DIR64:
            current_value = PE_READ_U64(target);
            break;
        case PE_REL_BASED_HIGH:
        case PE_REL_BASED_LOW:
            current_value = PE_READ_U16(target);
            break;
        default:
            break;
        }

        PE_UNUSED(current_value);
        applied++;
    }

    ctx->resolve_state.applied_reloc_count = applied;
    ctx->resolve_state.relocs_applied = 1;
    return PE_OK;
}

pe_error_t pe_resolve_debug_info(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t mapped = 0;

    for (uint32_t i = 0; i < cache->debug_count && i < ctx->debug.count; i++) {
        pe_debug_cache_entry_t *cached = &cache->debug_entries[i];
        pe_debug_entry_t *entry = &ctx->debug.entries[i];

        cached->debug_entry = entry;
        cached->section_index = entry->section_index >= 0
            ? (uint32_t)entry->section_index : UINT32_MAX;
        cached->pdb_path_ptr = entry->codeview
            ? entry->codeview->pdb_path : NULL;

        size_t path_len = pe_bounded_strlen(cached->pdb_path_ptr, 512);
        if (path_len > 0 && path_len < 512) {
            mapped++;
        }
    }

    ctx->resolve_state.mapped_debug_count = mapped;
    ctx->resolve_state.debug_mapped = 1;
    return PE_OK;
}

pe_error_t pe_resolve_symbol_refs(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t resolved = 0;

    for (uint32_t i = 0; i < cache->symbol_count && i < ctx->symbols.count; i++) {
        pe_symbol_cache_entry_t *cached = &cache->symbol_entries[i];
        pe_symbol_t *symbol = &ctx->symbols.entries[i];

        cached->symbol_index = symbol->index;
        cached->name_ptr = symbol->resolved_name;
        cached->section_number = symbol->section_number;

        size_t name_len = pe_bounded_strlen(symbol->resolved_name, 512);
        if (name_len > 0 && name_len < 512) {
            resolved++;
        }
    }

    ctx->resolve_state.resolved_symbol_count = resolved;
    ctx->resolve_state.symbols_resolved = 1;
    return PE_OK;
}

pe_error_t pe_resolve_resource_names(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t resolved = 0;

    for (uint32_t i = 0; i < cache->resource_count; i++) {
        pe_resource_cache_entry_t *cached = &cache->resource_entries[i];
        if (cached->flat_index >= ctx->resources.flat_count) {
            continue;
        }

        pe_resource_node_t *node =
            ctx->resources.flat_entries[cached->flat_index];
        if (!node) {
            continue;
        }

        cached->name_ptr = node->name;
        cached->type_id = node->id;
        cached->data_size = node->data_size;

        size_t name_len = pe_bounded_strlen(node->name, 512);
        if (name_len > 0 && name_len < 512) {
            resolved++;
        }
    }

    ctx->resolve_state.resolved_resource_count = resolved;
    ctx->resolve_state.resources_resolved = 1;
    return PE_OK;
}

pe_error_t pe_resolve_cross_references(pe_ctx_t *ctx)
{
    pe_cache_t *cache = &ctx->cache;
    uint32_t count = PE_MIN(cache->section_name_count, ctx->sections.count);

    for (uint32_t i = 0; i < count; i++) {
        pe_section_t *sec = &ctx->sections.entries[i];
        char *name = sec->resolved_name ? sec->resolved_name : sec->short_name;
        cache->section_names[i] = name;

        size_t name_len = pe_bounded_strlen(name, 512);
        if (name_len == 0 || name_len == 512) {
            continue;
        }

        uint64_t span = sec->virtual_size != 0
            ? sec->virtual_size : sec->raw_data_size;
        uint64_t start = sec->virtual_address;
        uint64_t end = start + span;

        pe_data_dir_t *imp_dir = &ctx->optional.data_dirs[PE_DIR_IMPORT];
        if (imp_dir->rva != 0 &&
            (uint64_t)imp_dir->rva >= start &&
            (uint64_t)imp_dir->rva < end) {
            /* Section contains import metadata. */
        }

        pe_data_dir_t *exp_dir = &ctx->optional.data_dirs[PE_DIR_EXPORT];
        if (exp_dir->rva != 0 &&
            (uint64_t)exp_dir->rva >= start &&
            (uint64_t)exp_dir->rva < end) {
            /* Section contains export metadata. */
        }
    }

    ctx->resolve_state.cross_refs_done = 1;
    return PE_OK;
}

pe_error_t pe_resolve(pe_ctx_t *ctx)
{
    if (!ctx) {
        return PE_ERR_NULLARG;
    }
    if (!ctx->cache.built) {
        return PE_ERR_RESOLVE_FAILED;
    }

    pe_error_t err;

    err = pe_resolve_import_names(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "import resolution incomplete");

    err = pe_resolve_export_names(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "export resolution incomplete");

    err = pe_resolve_relocations(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "relocation resolution incomplete");

    err = pe_resolve_debug_info(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "debug resolution incomplete");

    err = pe_resolve_symbol_refs(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "symbol resolution incomplete");

    err = pe_resolve_resource_names(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "resource resolution incomplete");

    err = pe_resolve_cross_references(ctx);
    if (err != PE_OK) pe_ctx_add_warning(ctx, "cross-reference resolution incomplete");

    return PE_OK;
}
