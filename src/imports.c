/*
 * imports.c — Import Table Parsing (Phase 7)
 *
 * Parses the import directory table and import lookup table (ILT)
 * entries. Each import descriptor references a DLL name and a list
 * of imported functions identified by name or ordinal.
 *
 * Import names are resolved by computing pointers into the section
 * data buffer that contains the hint/name table entries. DLL name
 * strings are allocated as independent copies.
 *
 * Reference: Microsoft PE/COFF Specification §6.4
 */

#include "internal.h"

/*
 * Read a null-terminated string from an RVA location within the PE image.
 * Returns an allocated copy of the string.
 */
static char *pe_read_string_at_rva(pe_ctx_t *ctx, uint32_t rva)
{
    uint32_t offset = pe_rva_to_offset(ctx, rva);
    if (offset == 0 && rva != 0) {
        return NULL;
    }

    if (offset >= ctx->size) {
        return NULL;
    }

    size_t max_len = ctx->size - offset;
    if (max_len > 512) {
        max_len = 512;
    }

    const uint8_t *start = ctx->data + offset;
    size_t len = 0;
    while (len < max_len && start[len] != '\0') {
        len++;
    }

    char *str = (char *)malloc(len + 1);
    if (!str) {
        return NULL;
    }
    memcpy(str, start, len);
    str[len] = '\0';
    return str;
}

/*
 * Resolve a hint/name table entry from an RVA.
 * Returns a pointer into the section data buffer (not a copy).
 * The hint is a 2-byte ordinal hint preceding the name string.
 */
char *pe_resolve_hint_name(pe_ctx_t *ctx, uint32_t rva,
                                   uint16_t *hint_out)
{
    uint32_t sec_idx = pe_find_section_index_by_rva(ctx, rva);
    if (sec_idx == UINT32_MAX) {
        return NULL;
    }

    /* Get pointer into section data buffer for this RVA */
    uint8_t *ptr = pe_section_rva_to_ptr(ctx, sec_idx, rva, 3);
    if (!ptr) {
        return NULL;
    }

    /* First two bytes are the hint */
    if (hint_out) {
        *hint_out = PE_READ_U16(ptr);
    }

    /* Name string follows the hint */
    char *name = (char *)(ptr + 2);

    /* Verify null termination within section bounds */
    pe_section_t *sec = &ctx->sections.entries[sec_idx];
    uint32_t delta = rva - sec->virtual_address;
    size_t remaining = sec->data_size - delta - 2;
    size_t name_len = 0;
    while (name_len < remaining && name[name_len] != '\0') {
        name_len++;
    }

    if (name_len >= remaining) {
        return NULL;
    }

    return name;
}

/*
 * Parse the import lookup table (ILT) entries for a descriptor.
 * Each ILT entry is either an ordinal (high bit set) or an
 * RVA to a hint/name table entry.
 */
pe_error_t pe_parse_import_thunks(pe_ctx_t *ctx, pe_import_descriptor_t *desc,
                                   int is_pe32plus)
{
    if (desc->ilt_rva == 0) {
        return PE_OK;
    }

    uint32_t ilt_offset = pe_rva_to_offset(ctx, desc->ilt_rva);
    if (ilt_offset == 0) {
        return PE_ERR_INVALID_IMPORT;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, ilt_offset)) {
        return PE_ERR_TRUNCATED;
    }

    uint32_t entry_size = is_pe32plus ? 8 : 4;
    uint32_t count = 0;

    /* First pass: count entries (null-terminated array) */
    size_t scan_pos = ilt_offset;
    while (PE_CHECK_OFFSET(ctx, scan_pos, entry_size) &&
           count < PE_MAX_THUNKS) {
        uint64_t val;
        if (entry_size == 8) {
            val = PE_READ_U64(ctx->data + scan_pos);
        } else {
            val = PE_READ_U32(ctx->data + scan_pos);
        }
        if (val == 0) {
            break;
        }
        count++;
        scan_pos += entry_size;
    }

    if (count == 0) {
        return PE_OK;
    }

    desc->thunks = (pe_import_thunk_t *)calloc(count, sizeof(pe_import_thunk_t));
    if (!desc->thunks) {
        return PE_ERR_ALLOC;
    }
    desc->thunks_capacity = count;

    /* Second pass: parse each thunk */
    for (uint32_t i = 0; i < count; i++) {
        uint64_t thunk_val;
        pe_import_thunk_t *thunk = &desc->thunks[i];

        if (is_pe32plus) {
            if (!pe_reader_read_u64(&r, &thunk_val)) {
                break;
            }
            thunk->thunk_rva = (uint32_t)(thunk_val & 0x7FFFFFFF);

            if (thunk_val & 0x8000000000000000ULL) {
                /* Import by ordinal */
                thunk->is_ordinal = 1;
                thunk->ordinal = (uint16_t)(thunk_val & 0xFFFF);
                thunk->name = NULL;
            } else {
                thunk->is_ordinal = 0;
                uint32_t hint_name_rva = (uint32_t)(thunk_val & 0x7FFFFFFF);
                thunk->name = pe_resolve_hint_name(ctx, hint_name_rva,
                                                    &thunk->hint);
            }
        } else {
            uint32_t val32;
            if (!pe_reader_read_u32(&r, &val32)) {
                break;
            }
            thunk_val = val32;
            thunk->thunk_rva = val32 & 0x7FFFFFFF;

            if (val32 & 0x80000000) {
                thunk->is_ordinal = 1;
                thunk->ordinal = (uint16_t)(val32 & 0xFFFF);
                thunk->name = NULL;
            } else {
                thunk->is_ordinal = 0;
                uint32_t hint_name_rva = val32 & 0x7FFFFFFF;
                thunk->name = pe_resolve_hint_name(ctx, hint_name_rva,
                                                    &thunk->hint);
            }
        }

        desc->num_thunks = i + 1;
    }

    return PE_OK;
}

/*
 * Parse a single import descriptor entry (20 bytes).
 */
pe_error_t pe_parse_import_descriptor(pe_ctx_t *ctx, pe_reader_t *r,
                                       pe_import_descriptor_t *desc)
{
    PE_UNUSED(ctx);
    memset(desc, 0, sizeof(*desc));

    if (!pe_reader_read_u32(r, &desc->ilt_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &desc->timestamp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &desc->forwarder_chain)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &desc->name_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &desc->iat_rva)) {
        return PE_ERR_TRUNCATED;
    }

    return PE_OK;
}

/*
 * Check if an import descriptor is the null terminator.
 */
static int pe_is_null_descriptor(const pe_import_descriptor_t *desc)
{
    return desc->ilt_rva == 0 && desc->timestamp == 0 &&
           desc->forwarder_chain == 0 && desc->name_rva == 0 &&
           desc->iat_rva == 0;
}

/*
 * Validate import descriptor fields.
 */
static void pe_validate_import_descriptor(pe_ctx_t *ctx,
                                           const pe_import_descriptor_t *desc,
                                           uint32_t index)
{
    if (desc->name_rva == 0) {
        pe_ctx_add_warning(ctx,
            "import descriptor %u: zero name RVA", index);
    }

    if (desc->ilt_rva == 0 && desc->iat_rva == 0) {
        pe_ctx_add_warning(ctx,
            "import descriptor %u: both ILT and IAT RVA are zero", index);
    }

    /* Check for duplicate DLL names across descriptors */
    if (desc->dll_name) {
        pe_import_table_t *it = &ctx->imports;
        for (uint32_t i = 0; i < index && i < it->count; i++) {
            if (it->descriptors[i].dll_name &&
                strcmp(it->descriptors[i].dll_name, desc->dll_name) == 0) {
                pe_ctx_add_issue(ctx, 2, 0,
                    "import descriptor %u: duplicate DLL name '%s' "
                    "(also at descriptor %u)",
                    index, desc->dll_name, i);
            }
        }
    }
}

/*
 * Parse the complete import table starting from the import directory RVA.
 */
pe_error_t pe_parse_import_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    pe_data_dir_t *import_dir = &ctx->optional.data_dirs[PE_DIR_IMPORT];
    if (import_dir->rva == 0 || import_dir->size == 0) {
        return PE_OK;
    }

    uint32_t dir_offset = pe_rva_to_offset(ctx, import_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_IMPORT,
                         "import directory RVA 0x%X does not resolve",
                         import_dir->rva);
        return PE_ERR_INVALID_IMPORT;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_import_table_t *it = &ctx->imports;

    /* Parse descriptors until null terminator */
    uint32_t count = 0;
    while (count < PE_MAX_IMPORTS) {
        pe_import_descriptor_t desc;
        pe_error_t err = pe_parse_import_descriptor(ctx, &r, &desc);
        if (err != PE_OK) {
            break;
        }

        if (pe_is_null_descriptor(&desc)) {
            break;
        }

        /* Resolve DLL name (allocated copy) */
        if (desc.name_rva != 0) {
            desc.dll_name = pe_read_string_at_rva(ctx, desc.name_rva);
        }

        /* Grow descriptor array while preserving local allocations on failure. */
        if (it->count >= it->capacity) {
            uint32_t newcap = it->capacity == 0 ? 16 : it->capacity * 2;
            pe_import_descriptor_t *tmp = (pe_import_descriptor_t *)realloc(
                it->descriptors, (size_t)newcap * sizeof(pe_import_descriptor_t));
            if (!tmp) {
                free(desc.dll_name);
                return PE_ERR_ALLOC;
            }
            it->descriptors = tmp;
            it->capacity = newcap;
        }

        it->descriptors[it->count] = desc;

        pe_validate_import_descriptor(ctx, &it->descriptors[it->count], count);

        /* Parse thunks for this descriptor */
        err = pe_parse_import_thunks(ctx, &it->descriptors[it->count],
                                      ctx->optional.is_pe32plus);
        if (err != PE_OK) {
            pe_ctx_add_warning(ctx,
                "import descriptor %u: thunk parse incomplete", count);
        }

        it->count++;
        count++;
    }

    return PE_OK;
}

/* Free a single import descriptor */
void pe_free_import_descriptor(pe_import_descriptor_t *desc)
{
    if (!desc) {
        return;
    }

    free(desc->dll_name);
    desc->dll_name = NULL;

    /* Thunk names point into section data — do not free them */
    free(desc->thunks);
    desc->thunks = NULL;
    desc->num_thunks = 0;
    desc->thunks_capacity = 0;
}

/* Free the entire import table */
void pe_free_import_table(pe_import_table_t *it)
{
    if (!it || !it->descriptors) {
        return;
    }

    for (uint32_t i = 0; i < it->count; i++) {
        pe_free_import_descriptor(&it->descriptors[i]);
    }

    free(it->descriptors);
    it->descriptors = NULL;
    it->count = 0;
    it->capacity = 0;
}

/* Public API: import descriptor count */
uint32_t pe_get_import_descriptor_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->imports.count;
}

/* Public API: get import descriptor */
const pe_import_descriptor_t *pe_get_import_descriptor(const pe_ctx_t *ctx,
                                                        uint32_t index)
{
    if (!ctx || index >= ctx->imports.count) {
        return NULL;
    }
    return &ctx->imports.descriptors[index];
}

/* Public API: get DLL name for an import descriptor */
const char *pe_get_import_dll_name(const pe_ctx_t *ctx, uint32_t desc_index)
{
    const pe_import_descriptor_t *desc = pe_get_import_descriptor(ctx, desc_index);
    if (!desc) {
        return NULL;
    }
    return desc->dll_name;
}

/* Public API: thunk count for descriptor */
uint32_t pe_get_import_thunk_count(const pe_ctx_t *ctx, uint32_t desc_index)
{
    const pe_import_descriptor_t *desc = pe_get_import_descriptor(ctx, desc_index);
    if (!desc) {
        return 0;
    }
    return desc->num_thunks;
}

/* Public API: get thunk entry */
const pe_import_thunk_t *pe_get_import_thunk(const pe_ctx_t *ctx,
                                              uint32_t desc_index,
                                              uint32_t thunk_index)
{
    const pe_import_descriptor_t *desc = pe_get_import_descriptor(ctx, desc_index);
    if (!desc || thunk_index >= desc->num_thunks) {
        return NULL;
    }
    return &desc->thunks[thunk_index];
}
