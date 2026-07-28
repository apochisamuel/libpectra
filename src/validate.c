/*
 * validate.c — Cross-Table Validation (Phase 13)
 *
 * Performs consistency checks across parsed PE structures. Validation
 * records malformed relationships and may disable invalid optional data,
 * but it does not relocate section buffers or rebuild shared string data.
 * Caches are constructed only after this phase completes.
 */

#include "internal.h"

/*
 * Validate section alignment and data consistency. Misaligned file
 * offsets are reported without rewriting parsed layout or replacing
 * section buffers, because other parsed records may reference them.
 */
pe_error_t pe_validate_section_alignment(pe_ctx_t *ctx)
{
    uint32_t fa = ctx->optional.file_alignment;
    if (fa == 0) {
        return PE_OK;
    }

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        pe_section_t *sec = &ctx->sections.entries[i];

        if (sec->raw_data_offset == 0 || sec->raw_data_size == 0) {
            continue;
        }

        /* Check if raw data offset is aligned */
        if ((sec->raw_data_offset % fa) != 0) {
            pe_ctx_add_issue(ctx, 2, i,
                "section %u '%s': raw data offset 0x%X not aligned to %u",
                i, sec->short_name, sec->raw_data_offset, fa);
        }

        /* Check for section size vs virtual size mismatch */
        if (sec->raw_data_size > sec->virtual_size &&
            sec->virtual_size > 0) {
            uint32_t excess = sec->raw_data_size - sec->virtual_size;
            if (excess > fa) {
                pe_ctx_add_issue(ctx, 1, i,
                    "section %u '%s': raw size %u exceeds virtual size %u by %u",
                    i, sec->short_name, sec->raw_data_size,
                    sec->virtual_size, excess);
            }
        }
    }

    return PE_OK;
}

/*
 * Validate import table consistency and report duplicate descriptors.
 */
pe_error_t pe_validate_import_consistency(pe_ctx_t *ctx)
{
    pe_import_table_t *it = &ctx->imports;

    if (it->count < 2) {
        return PE_OK;
    }

    /* Check for duplicate DLL entries */
    uint32_t dup_count = 0;
    for (uint32_t i = 0; i < it->count; i++) {
        if (!it->descriptors[i].dll_name) {
            continue;
        }
        for (uint32_t j = i + 1; j < it->count; j++) {
            if (!it->descriptors[j].dll_name) {
                continue;
            }
            if (strcmp(it->descriptors[i].dll_name,
                       it->descriptors[j].dll_name) == 0) {
                dup_count++;
            }
        }
    }

    if (dup_count >= PE_VALIDATE_IMPORT_DUP_THRESHOLD) {
        pe_ctx_add_issue(ctx, 2, 0,
            "import table: %u duplicate DLL entries detected",
            dup_count);
    }

    /* Validate thunk RVAs resolve to valid locations */
    for (uint32_t d = 0; d < it->count; d++) {
        pe_import_descriptor_t *desc = &it->descriptors[d];
        for (uint32_t t = 0; t < desc->num_thunks; t++) {
            pe_import_thunk_t *thunk = &desc->thunks[t];
            if (!thunk->is_ordinal && thunk->name == NULL) {
                pe_ctx_add_issue(ctx, 1, 0,
                    "import '%s' thunk %u: name resolution failed",
                    desc->dll_name ? desc->dll_name : "??", t);
            }
        }
    }

    return PE_OK;
}

/*
 * Validate export table ranges and disable entries whose metadata is
 * inconsistent with overlapping directories or forwarder syntax.
 */
pe_error_t pe_validate_export_ranges(pe_ctx_t *ctx)
{
    pe_export_table_t *et = &ctx->exports;
    pe_data_dir_t *exp_dir = &ctx->optional.data_dirs[PE_DIR_EXPORT];

    if (et->num_functions == 0 || exp_dir->rva == 0) {
        return PE_OK;
    }

    uint32_t exp_start = exp_dir->rva;
    uint32_t exp_end = exp_start + exp_dir->size;

    /* Check for overlap between export directory and relocation directory */
    pe_data_dir_t *reloc_dir = &ctx->optional.data_dirs[PE_DIR_BASERELOC];
    if (reloc_dir->rva != 0 && reloc_dir->size != 0) {
        uint32_t reloc_start = reloc_dir->rva;
        uint32_t reloc_end = reloc_start + reloc_dir->size;

        if (exp_start < reloc_end && reloc_start < exp_end) {
            pe_ctx_add_issue(ctx, 2, 0,
                "export directory [0x%X-0x%X] overlaps relocation directory "
                "[0x%X-0x%X], cleaning up affected exports",
                exp_start, exp_end, reloc_start, reloc_end);

            /* Disable exports whose target lies in the overlap. */
            uint32_t cleanup_count = 0;
            for (uint32_t i = 0; i < et->num_functions; i++) {
                pe_export_entry_t *entry = &et->entries[i];
                if (entry->function_rva >= reloc_start &&
                    entry->function_rva < reloc_end) {
                    if (entry->forwarder) {
                        free(entry->forwarder);
                        entry->forwarder = NULL;
                    }
                    entry->is_forwarder = 0;
                    entry->function_rva = 0;
                    cleanup_count++;
                }
            }

            if (cleanup_count > 0) {
                pe_ctx_add_issue(ctx, 2, 0,
                    "cleaned up %u export entries in overlap region",
                    cleanup_count);
            }
        }
    }

    /* Validate forwarder string contents */
    for (uint32_t i = 0; i < et->num_functions; i++) {
        pe_export_entry_t *entry = &et->entries[i];
        if (!entry->is_forwarder || !entry->forwarder) {
            continue;
        }

        /* Forwarder must contain a '.' separator */
        int has_dot = 0;
        size_t fwd_len = strlen(entry->forwarder);
        for (size_t j = 0; j < fwd_len; j++) {
            if (entry->forwarder[j] == '.') {
                has_dot = 1;
                break;
            }
        }

        if (!has_dot) {
            pe_ctx_add_issue(ctx, 2, 0,
                "export %u: invalid forwarder '%s' (no '.' separator), "
                "removing forwarder",
                i, entry->forwarder);

            /* Remove the invalid forwarder before caches are built. */
            free(entry->forwarder);
            entry->forwarder = NULL;
            entry->is_forwarder = 0;
        }
    }

    return PE_OK;
}

/*
 * Validate relocation targets against section boundaries.
 */
pe_error_t pe_validate_reloc_targets(pe_ctx_t *ctx)
{
    pe_reloc_table_t *rt = &ctx->relocs;

    for (uint32_t i = 0; i < rt->count; i++) {
        pe_reloc_block_t *block = &rt->blocks[i];

        for (uint32_t j = 0; j < block->count; j++) {
            pe_reloc_entry_t *rel = &block->entries[j];

            if (!rel->resolved) {
                continue;
            }

            /* Verify the target pointer is still within section bounds */
            uint32_t sec_idx = pe_find_section_index_by_rva(ctx,
                                                             rel->target_rva);
            if (sec_idx == UINT32_MAX) {
                pe_ctx_add_issue(ctx, 1, 0,
                    "reloc at page 0x%X offset 0x%X: target section gone",
                    block->page_rva, rel->offset);
                rel->resolved = 0;
                continue;
            }

            pe_section_t *sec = &ctx->sections.entries[sec_idx];
            if (!sec->data) {
                rel->resolved = 0;
                continue;
            }

            uint32_t delta = rel->target_rva - sec->virtual_address;
            if (delta >= sec->data_size) {
                pe_ctx_add_issue(ctx, 1, sec_idx,
                    "reloc at page 0x%X offset 0x%X: target offset %u "
                    "exceeds section data size %zu",
                    block->page_rva, rel->offset, delta, sec->data_size);
                rel->resolved = 0;
            }
        }
    }

    return PE_OK;
}

/*
 * Validate debug entries for timestamp consistency. Entries with extreme
 * drift are retained as directory records but their optional CodeView
 * payload is discarded before caches are constructed.
 */
pe_error_t pe_validate_debug_entries(pe_ctx_t *ctx)
{
    pe_debug_table_t *dt = &ctx->debug;

    if (dt->count == 0 || ctx->coff.timestamp == 0) {
        return PE_OK;
    }

    for (uint32_t i = 0; i < dt->count; i++) {
        pe_debug_entry_t *entry = &dt->entries[i];

        if (entry->timestamp == 0) {
            continue;
        }

        int64_t drift = (int64_t)entry->timestamp -
                         (int64_t)ctx->coff.timestamp;
        if (drift < 0) {
            drift = -drift;
        }

        if ((uint64_t)drift > PE_VALIDATE_DEBUG_TIMESTAMP_DRIFT) {
            pe_ctx_add_issue(ctx, 2, 0,
                "debug entry %u (type %s): timestamp 0x%X differs from "
                "COFF timestamp 0x%X by %lld seconds, removing entry",
                i, pe_get_debug_type_name(entry->type),
                entry->timestamp, ctx->coff.timestamp,
                (long long)drift);

            /* Discard optional CodeView data for the invalid entry. */
            if (entry->codeview) {
                free(entry->codeview->pdb_path);
                entry->codeview->pdb_path = NULL;
                free(entry->codeview);
                entry->codeview = NULL;
            }

            entry->type = PE_DEBUG_TYPE_UNKNOWN;
            entry->data_size = 0;
        }
    }

    return PE_OK;
}

/*
 * Validate symbol-table slot consumption against the COFF header. Parsed
 * symbols exclude auxiliary records, so the comparison uses each symbol's
 * original table index and auxiliary count rather than the compact count.
 */
pe_error_t pe_validate_symbol_table(pe_ctx_t *ctx)
{
    uint32_t header_count = ctx->coff.num_symbols;
    uint32_t consumed_slots = 0;

    for (uint32_t i = 0; i < ctx->symbols.count; i++) {
        pe_symbol_t *sym = &ctx->symbols.entries[i];
        uint64_t end = (uint64_t)sym->index + 1u + sym->aux_count;
        if (end > consumed_slots) {
            consumed_slots = end > UINT32_MAX ? UINT32_MAX : (uint32_t)end;
        }
    }

    if (header_count != consumed_slots &&
        (header_count != 0 || consumed_slots != 0)) {
        uint32_t diff = header_count > consumed_slots
            ? header_count - consumed_slots : consumed_slots - header_count;
        int severity = diff > PE_VALIDATE_SYMBOL_MISMATCH_THRESHOLD ? 2 : 1;
        pe_ctx_add_issue(ctx, severity, 0,
            "symbol table slot mismatch: COFF header says %u, parsed records consume %u",
            header_count, consumed_slots);
    }

    for (uint32_t i = 0; i < ctx->symbols.count; i++) {
        pe_symbol_t *sym = &ctx->symbols.entries[i];
        if (sym->section_number > 0 &&
            (uint32_t)(sym->section_number - 1) >= ctx->sections.count) {
            pe_ctx_add_issue(ctx, 1, 0,
                "symbol %u '%s': section number %d out of range [1-%u]",
                i, sym->resolved_name ? sym->resolved_name : "??",
                sym->section_number, ctx->sections.count);
        }
    }

    return PE_OK;
}

/*
 * Validate resource tree entries against section boundaries. Invalid data
 * references are cleared before the post-validation cache is constructed.
 */
pe_error_t pe_validate_resource_bounds(pe_ctx_t *ctx)
{
    pe_resource_tree_t *rt = &ctx->resources;

    if (rt->flat_count == 0) {
        return PE_OK;
    }

    pe_data_dir_t *rsrc_dir = &ctx->optional.data_dirs[PE_DIR_RESOURCE];
    if (rsrc_dir->rva == 0) {
        return PE_OK;
    }

    uint32_t rsrc_end = rsrc_dir->rva + rsrc_dir->size;
    uint32_t oob_count = 0;

    for (uint32_t i = 0; i < rt->flat_count; i++) {
        pe_resource_node_t *node = rt->flat_entries[i];

        if (node->data_rva == 0 || node->data_size == 0) {
            continue;
        }

        /* Check if data RVA falls outside the resource section */
        uint32_t data_end = node->data_rva + node->data_size;
        if (data_end < node->data_rva) {
            /* Overflow */
            oob_count++;
            continue;
        }

        uint32_t sec_idx = pe_find_section_index_by_rva(ctx, node->data_rva);
        if (sec_idx == UINT32_MAX) {
            oob_count++;

            pe_ctx_add_issue(ctx, 2, 0,
                "resource %u: data RVA 0x%X outside any section, pruning",
                i, node->data_rva);

            /* Clear the invalid leaf while preserving tree structure. */
            if (node->name) {
                free(node->name);
                node->name = NULL;
            }
            node->data_rva = 0;
            node->data_size = 0;
            node->data_ptr = NULL;
        }
    }

    if (oob_count >= PE_VALIDATE_RESOURCE_BOUNDS_THRESHOLD) {
        pe_ctx_add_issue(ctx, 2, 0,
            "resource tree: %u entries with out-of-bounds data", oob_count);
    }

    PE_UNUSED(rsrc_end);
    return PE_OK;
}

/*
 * Validate string table references from sections and symbols.
 */
pe_error_t pe_validate_string_table_refs(pe_ctx_t *ctx)
{
    if (ctx->strings.size == 0) {
        return PE_OK;
    }

    /* Check that string table entries are properly null-terminated */
    uint8_t *st_data = ctx->strings.data;
    uint32_t st_size = ctx->strings.size;

    if (st_size > 4 && st_data[st_size - 1] != '\0') {
        pe_ctx_add_issue(ctx, 1, 0,
            "string table not null-terminated at end");
    }

    /* Validate section name references */
    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        pe_section_t *sec = &ctx->sections.entries[i];
        if (sec->short_name[0] == '/') {
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

            if (valid && str_offset >= st_size) {
                pe_ctx_add_issue(ctx, 2, i,
                    "section %u: string table offset %u exceeds table size %u",
                    i, str_offset, st_size);
            }
        }
    }

    return PE_OK;
}

/*
 * Run the full validation pipeline.
 */
pe_error_t pe_validate(pe_ctx_t *ctx)
{
    if (!ctx) {
        return PE_ERR_NULLARG;
    }

    pe_error_t err;

    /* Section alignment validation */
    err = pe_validate_section_alignment(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "section alignment validation incomplete");
    }

    /* Import consistency checks */
    err = pe_validate_import_consistency(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "import validation incomplete");
    }

    /* Export range overlap detection and cleanup */
    err = pe_validate_export_ranges(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "export validation incomplete");
    }

    /* Relocation target validation */
    err = pe_validate_reloc_targets(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "reloc validation incomplete");
    }

    /* Debug entry timestamp validation */
    err = pe_validate_debug_entries(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "debug validation incomplete");
    }

    /* Symbol table slot validation */
    err = pe_validate_symbol_table(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "symbol validation incomplete");
    }

    /* Resource bounds validation */
    err = pe_validate_resource_bounds(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "resource validation incomplete");
    }

    /* String table reference validation */
    err = pe_validate_string_table_refs(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "string table validation incomplete");
    }

    /* PE checksum validation */
    err = pe_validate_pe_checksum(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "checksum validation noted mismatch");
    }

    return PE_OK;
}
