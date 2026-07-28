/*
 * relocs.c — Base Relocation Table Parsing (Phase 9)
 *
 * Parses the base relocation table used to adjust addresses when
 * the PE image is loaded at a different base address than its
 * preferred image base. The table consists of blocks, each covering
 * a 4K page, containing entries that specify relocation type and
 * offset within the page.
 *
 * Relocation targets are computed as pointers into the section data
 * buffers, enabling efficient in-place relocation application during
 * the resolution phase.
 *
 * Reference: Microsoft PE/COFF Specification §6.6
 */

#include "internal.h"

/*
 * Get the relocation type name for diagnostic messages.
 */
static const char *pe_reloc_type_name(uint16_t type)
{
    switch (type) {
    case PE_REL_BASED_ABSOLUTE: return "ABSOLUTE";
    case PE_REL_BASED_HIGH:     return "HIGH";
    case PE_REL_BASED_LOW:      return "LOW";
    case PE_REL_BASED_HIGHLOW:  return "HIGHLOW";
    case PE_REL_BASED_HIGHADJ:  return "HIGHADJ";
    case PE_REL_BASED_DIR64:    return "DIR64";
    default:                    return "UNKNOWN";
    }
}

/*
 * Compute the minimum number of bytes a relocation type modifies.
 */
static size_t pe_reloc_target_size(uint16_t type)
{
    switch (type) {
    case PE_REL_BASED_HIGH:     return 2;
    case PE_REL_BASED_LOW:      return 2;
    case PE_REL_BASED_HIGHLOW:  return 4;
    case PE_REL_BASED_DIR64:    return 8;
    case PE_REL_BASED_HIGHADJ:  return 4;
    default:                    return 0;
    }
}

/*
 * Parse a single relocation block.
 * Each block starts with an 8-byte header (page RVA + block size),
 * followed by 2-byte entries encoding type (high 4 bits) and
 * offset (low 12 bits).
 */
pe_error_t pe_parse_reloc_block(pe_ctx_t *ctx, pe_reader_t *r,
                                 pe_reloc_block_t *block)
{
    memset(block, 0, sizeof(*block));

    if (!pe_reader_read_u32(r, &block->page_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &block->block_size)) {
        return PE_ERR_TRUNCATED;
    }

    if (block->block_size < 8) {
        pe_ctx_add_warning(ctx,
            "reloc block at page RVA 0x%X: invalid block size %u",
            block->page_rva, block->block_size);
        return PE_ERR_INVALID_RELOC;
    }

    uint32_t entry_bytes = block->block_size - 8;
    uint32_t num_entries = entry_bytes / 2;

    if (num_entries > PE_MAX_RELOC_ENTRIES) {
        pe_ctx_add_warning(ctx,
            "reloc block at page RVA 0x%X: too many entries %u",
            block->page_rva, num_entries);
        num_entries = PE_MAX_RELOC_ENTRIES;
    }

    if (num_entries == 0) {
        return PE_OK;
    }

    block->entries = (pe_reloc_entry_t *)calloc(num_entries,
                                                 sizeof(pe_reloc_entry_t));
    if (!block->entries) {
        return PE_ERR_ALLOC;
    }
    block->capacity = num_entries;

    uint32_t actual = 0;
    for (uint32_t i = 0; i < num_entries; i++) {
        uint16_t raw;
        if (!pe_reader_read_u16(r, &raw)) {
            break;
        }

        uint16_t type = (raw >> 12) & 0x0F;
        uint16_t offset = raw & 0x0FFF;

        /* Skip padding entries (type ABSOLUTE) */
        if (type == PE_REL_BASED_ABSOLUTE) {
            continue;
        }

        pe_reloc_entry_t *entry = &block->entries[actual];
        entry->type = type;
        entry->offset = offset;
        entry->target_rva = block->page_rva + offset;
        entry->target_ptr = NULL;
        entry->resolved = 0;

        actual++;
    }

    block->count = actual;
    return PE_OK;
}

/*
 * Compute target pointers for all relocation entries.
 * Target pointers resolve into section data buffers so that
 * relocations can be applied in-place during the resolution phase.
 */
pe_error_t pe_compute_reloc_targets(pe_ctx_t *ctx)
{
    pe_reloc_table_t *rt = &ctx->relocs;

    for (uint32_t i = 0; i < rt->count; i++) {
        pe_reloc_block_t *block = &rt->blocks[i];

        for (uint32_t j = 0; j < block->count; j++) {
            pe_reloc_entry_t *entry = &block->entries[j];

            /* Find the section containing this RVA */
            uint32_t sec_idx = pe_find_section_index_by_rva(ctx,
                                                             entry->target_rva);
            if (sec_idx == UINT32_MAX) {
                pe_ctx_add_warning(ctx,
                    "reloc target RVA 0x%X: no containing section",
                    entry->target_rva);
                continue;
            }

            size_t target_size = pe_reloc_target_size(entry->type);
            if (target_size == 0) {
                pe_ctx_add_warning(ctx,
                    "reloc target RVA 0x%X: unsupported type %s (%u)",
                    entry->target_rva, pe_reloc_type_name(entry->type),
                    entry->type);
                continue;
            }

            /* Get writable pointer into section data */
            uint8_t *target = pe_section_rva_to_ptr(ctx, sec_idx,
                                                     entry->target_rva,
                                                     target_size);
            if (target) {
                entry->target_ptr = target;
                entry->resolved = 1;
            } else {
                pe_ctx_add_warning(ctx,
                    "reloc target RVA 0x%X: section %u data too small",
                    entry->target_rva, sec_idx);
            }
        }
    }

    return PE_OK;
}

/*
 * Parse the complete base relocation table.
 */
pe_error_t pe_parse_reloc_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    pe_data_dir_t *reloc_dir = &ctx->optional.data_dirs[PE_DIR_BASERELOC];
    if (reloc_dir->rva == 0 || reloc_dir->size == 0) {
        return PE_OK;
    }

    uint32_t dir_offset = pe_rva_to_offset(ctx, reloc_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_RELOC,
                         "reloc directory RVA 0x%X does not resolve",
                         reloc_dir->rva);
        return PE_ERR_INVALID_RELOC;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_reloc_table_t *rt = &ctx->relocs;
    uint32_t dir_end = dir_offset + reloc_dir->size;

    while (pe_reader_tell(&r) < dir_end && rt->count < PE_MAX_RELOC_BLOCKS) {
        if (pe_reader_remaining(&r) < 8) {
            break;
        }

        PE_ARRAY_GROW(rt->blocks, rt->count, rt->capacity, pe_reloc_block_t);

        pe_reloc_block_t *block = &rt->blocks[rt->count];
        pe_error_t err = pe_parse_reloc_block(ctx, &r, block);
        if (err != PE_OK) {
            break;
        }

        /* Check for end-of-table sentinel (zero page RVA and size) */
        if (block->page_rva == 0 && block->block_size == 0) {
            break;
        }

        rt->count++;
    }

    /* Compute target pointers into section data */
    pe_error_t err = pe_compute_reloc_targets(ctx);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "reloc target computation incomplete");
    }

    return PE_OK;
}

/* Free relocation table */
void pe_free_reloc_table(pe_reloc_table_t *rt)
{
    if (!rt || !rt->blocks) {
        return;
    }

    for (uint32_t i = 0; i < rt->count; i++) {
        free(rt->blocks[i].entries);
        rt->blocks[i].entries = NULL;
    }

    free(rt->blocks);
    rt->blocks = NULL;
    rt->count = 0;
    rt->capacity = 0;
}

/* Public API: reloc block count */
uint32_t pe_get_reloc_block_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->relocs.count;
}

/* Public API: get reloc block */
const pe_reloc_block_t *pe_get_reloc_block(const pe_ctx_t *ctx, uint32_t index)
{
    if (!ctx || index >= ctx->relocs.count) {
        return NULL;
    }
    return &ctx->relocs.blocks[index];
}
