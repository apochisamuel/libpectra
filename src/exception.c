/*
 * exception.c — Exception Directory Parsing
 *
 * Parses the exception directory (data directory index 3) which
 * contains runtime function entries for structured exception
 * handling on x64. Each entry describes a code range and points
 * to unwind information that describes how to unwind the stack
 * through that function.
 *
 * On x64, the exception directory is an array of RUNTIME_FUNCTION
 * entries sorted by starting address. Each entry contains:
 *   - BeginAddress:    RVA of the function start
 *   - EndAddress:      RVA of the function end
 *   - UnwindInfoAddress: RVA of the UNWIND_INFO structure
 *
 * UNWIND_INFO contains:
 *   - Version and flags
 *   - Size of prolog
 *   - Count and array of unwind codes
 *   - Optional exception handler RVA and handler-specific data
 *
 * Reference: Microsoft x64 ABI, Exception Handling
 */

#include "internal.h"

/* Unwind operation codes for x64 */
#define UWOP_PUSH_NONVOL     0   /* Push non-volatile register */
#define UWOP_ALLOC_LARGE     1   /* Allocate large stack frame */
#define UWOP_ALLOC_SMALL     2   /* Allocate small stack frame */
#define UWOP_SET_FPREG       3   /* Set frame pointer register */
#define UWOP_SAVE_NONVOL     4   /* Save non-volatile register (far) */
#define UWOP_SAVE_NONVOL_FAR 5   /* Save non-volatile register (very far) */
#define UWOP_SAVE_XMM128     8   /* Save 128-bit XMM register */
#define UWOP_SAVE_XMM128_FAR 9   /* Save 128-bit XMM register (far) */
#define UWOP_PUSH_MACHFRAME  10  /* Push machine frame */

/* UNW_FLAG values */
#define UNW_FLAG_NHANDLER  0x00
#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

/* x64 register names indexed by register number */
static const char *pe_x64_register_name(uint8_t reg)
{
    static const char *names[] = {
        "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
        "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15"
    };
    if (reg < 16) return names[reg];
    return "???";
}

/* Return human-readable name for unwind operation code */
static const char *pe_uwop_name(uint8_t opcode)
{
    switch (opcode) {
    case UWOP_PUSH_NONVOL:     return "PUSH_NONVOL";
    case UWOP_ALLOC_LARGE:     return "ALLOC_LARGE";
    case UWOP_ALLOC_SMALL:     return "ALLOC_SMALL";
    case UWOP_SET_FPREG:       return "SET_FPREG";
    case UWOP_SAVE_NONVOL:     return "SAVE_NONVOL";
    case UWOP_SAVE_NONVOL_FAR: return "SAVE_NONVOL_FAR";
    case UWOP_SAVE_XMM128:     return "SAVE_XMM128";
    case UWOP_SAVE_XMM128_FAR: return "SAVE_XMM128_FAR";
    case UWOP_PUSH_MACHFRAME:  return "PUSH_MACHFRAME";
    default:                   return "UNKNOWN";
    }
}

/*
 * Count the number of extra UNWIND_CODE slots consumed by an
 * operation. Some operations use 2 or 3 slots.
 */
static uint32_t pe_uwop_slot_count(uint8_t opcode, uint8_t op_info)
{
    switch (opcode) {
    case UWOP_PUSH_NONVOL:
    case UWOP_ALLOC_SMALL:
    case UWOP_SET_FPREG:
    case UWOP_PUSH_MACHFRAME:
        return 1;
    case UWOP_ALLOC_LARGE:
        return (op_info == 0) ? 2 : 3;
    case UWOP_SAVE_NONVOL:
    case UWOP_SAVE_XMM128:
        return 2;
    case UWOP_SAVE_NONVOL_FAR:
    case UWOP_SAVE_XMM128_FAR:
        return 3;
    default:
        return 1;
    }
}

/*
 * Parse an UNWIND_INFO structure at the given file offset.
 * The structure layout:
 *   Byte 0: Version (3 bits) | Flags (5 bits)
 *   Byte 1: Size of prolog
 *   Byte 2: Count of unwind codes
 *   Byte 3: Frame register (4 bits) | Frame register offset (4 bits)
 *   Bytes 4+: Array of UNWIND_CODE entries (2 bytes each)
 *   After codes: optional handler RVA + handler data
 */
static pe_error_t pe_parse_unwind_info(pe_ctx_t *ctx,
                                        pe_exception_entry_t *entry,
                                        uint32_t unwind_rva)
{
    uint32_t offset32 = pe_rva_to_offset(ctx, unwind_rva);
    if (offset32 == 0) {
        return PE_ERR_TRUNCATED;
    }

    size_t offset = offset32;
    if (!PE_CHECK_OFFSET(ctx, offset, 4)) {
        return PE_ERR_TRUNCATED;
    }

    pe_unwind_info_t *info = &entry->unwind;
    uint8_t ver_flags = ctx->data[offset];
    info->version = ver_flags & 0x07;
    info->flags = (ver_flags >> 3) & 0x1F;
    info->prolog_size = ctx->data[offset + 1];
    info->code_count = ctx->data[offset + 2];

    uint8_t frame_byte = ctx->data[offset + 3];
    info->frame_register = frame_byte & 0x0F;
    info->frame_offset = (frame_byte >> 4) & 0x0F;

    size_t codes_offset = offset + 4;
    size_t codes_size = (size_t)info->code_count * 2;
    if (!PE_CHECK_OFFSET(ctx, codes_offset, codes_size)) {
        pe_ctx_add_warning(ctx,
            "exception entry 0x%X: unwind codes truncated", entry->begin_rva);
        info->code_count = 0;
        return PE_OK;
    }

    if (info->code_count > 0) {
        info->codes = (pe_unwind_code_t *)calloc(
            info->code_count, sizeof(pe_unwind_code_t));
        if (!info->codes) {
            return PE_ERR_ALLOC;
        }
        info->codes_capacity = info->code_count;

        uint32_t ci = 0;
        uint32_t slot = 0;
        while (slot < info->code_count && ci < info->codes_capacity) {
            size_t code_off = codes_offset + (size_t)slot * 2;
            pe_unwind_code_t *uc = &info->codes[ci];

            uc->offset_in_prolog = ctx->data[code_off];
            uint8_t op_and_info = ctx->data[code_off + 1];
            uc->operation = op_and_info & 0x0F;
            uc->op_info = (op_and_info >> 4) & 0x0F;

            uint32_t slots = pe_uwop_slot_count(uc->operation, uc->op_info);
            if (slots > (uint32_t)info->code_count - slot) {
                pe_ctx_add_warning(ctx,
                    "exception entry 0x%X: unwind operation exceeds code array",
                    entry->begin_rva);
                break;
            }

            if (slots >= 2) {
                uc->extra_value = PE_READ_U16(ctx->data + code_off + 2);
            }
            if (slots >= 3) {
                uc->extra_value |= (uint32_t)PE_READ_U16(
                    ctx->data + code_off + 4) << 16;
            }

            slot += slots;
            ci++;
        }
        info->parsed_code_count = ci;
    }

    size_t aligned_count = ((size_t)info->code_count + 1u) & ~(size_t)1u;
    size_t handler_off = codes_offset + aligned_count * 2;

    if (info->flags & UNW_FLAG_CHAININFO) {
        if (PE_CHECK_OFFSET(ctx, handler_off, 12)) {
            info->chained_begin = PE_READ_U32(ctx->data + handler_off);
            info->chained_end = PE_READ_U32(ctx->data + handler_off + 4);
            info->chained_unwind = PE_READ_U32(ctx->data + handler_off + 8);
            info->is_chained = 1;
        } else {
            pe_ctx_add_warning(ctx,
                "exception entry 0x%X: chained unwind record truncated",
                entry->begin_rva);
        }
    } else if (info->flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        if (PE_CHECK_OFFSET(ctx, handler_off, 4)) {
            info->handler_rva = PE_READ_U32(ctx->data + handler_off);
            info->has_handler = 1;
            if (info->handler_rva != 0) {
                entry->handler_section = pe_find_section_index_by_rva(
                    ctx, info->handler_rva);
            }
        } else {
            pe_ctx_add_warning(ctx,
                "exception entry 0x%X: handler record truncated",
                entry->begin_rva);
        }
    }

    return PE_OK;
}

/*
 * Validate that a runtime function entry has consistent addresses.
 */
static void pe_validate_exception_entry(pe_ctx_t *ctx,
                                          pe_exception_entry_t *entry,
                                          uint32_t index)
{
    /* End must be after begin */
    if (entry->end_rva <= entry->begin_rva) {
        pe_ctx_add_issue(ctx, 1, 0,
            "exception entry %u: end RVA 0x%X <= begin RVA 0x%X",
            index, entry->end_rva, entry->begin_rva);
    }

    /* Function size sanity check (> 1MB is suspicious) */
    uint32_t func_size = entry->end_rva > entry->begin_rva
        ? entry->end_rva - entry->begin_rva : 0;
    if (func_size > 1024 * 1024) {
        pe_ctx_add_issue(ctx, 1, 0,
            "exception entry %u: function size %u bytes (unusually large)",
            index, func_size);
    }

    /* Begin address should fall within a code section */
    uint32_t sec_idx = pe_find_section_index_by_rva(ctx, entry->begin_rva);
    if (sec_idx != UINT32_MAX) {
        entry->code_section = sec_idx;
        pe_section_t *sec = &ctx->sections.entries[sec_idx];
        if (!(sec->characteristics & PE_SCN_MEM_EXECUTE)) {
            pe_ctx_add_issue(ctx, 1, sec_idx,
                "exception entry %u: code range in non-executable section",
                index);
        }
    } else {
        pe_ctx_add_issue(ctx, 1, 0,
            "exception entry %u: begin RVA 0x%X not in any section",
            index, entry->begin_rva);
    }

    /* Unwind version check */
    if (entry->unwind.version > 2) {
        pe_ctx_add_issue(ctx, 1, 0,
            "exception entry %u: unsupported unwind version %u",
            index, entry->unwind.version);
    }

    /* Validate unwind codes */
    for (uint32_t i = 0; i < entry->unwind.parsed_code_count; i++) {
        pe_unwind_code_t *uc = &entry->unwind.codes[i];
        if (uc->offset_in_prolog > entry->unwind.prolog_size) {
            pe_ctx_add_issue(ctx, 1, 0,
                "exception entry %u: unwind code %u offset %u exceeds prolog %u",
                index, i, uc->offset_in_prolog, entry->unwind.prolog_size);
        }
    }
}

/*
 * Compute aggregate statistics about the exception table.
 */
static void pe_compute_exception_stats(pe_ctx_t *ctx)
{
    pe_exception_table_t *et = &ctx->exceptions;
    uint64_t total_code_size = 0;
    uint32_t max_func_size = 0;
    uint32_t min_func_size = UINT32_MAX;
    uint32_t handler_count = 0;
    uint32_t chained_count = 0;
    uint32_t valid_ranges = 0;

    for (uint32_t i = 0; i < et->count; i++) {
        pe_exception_entry_t *entry = &et->entries[i];
        uint32_t func_size = entry->end_rva > entry->begin_rva
            ? entry->end_rva - entry->begin_rva : 0;

        if (func_size > 0) {
            total_code_size += func_size;
            if (func_size > max_func_size) max_func_size = func_size;
            if (func_size < min_func_size) min_func_size = func_size;
            valid_ranges++;
        }
        if (entry->unwind.has_handler) handler_count++;
        if (entry->unwind.is_chained) chained_count++;
    }

    et->total_code_size = total_code_size > UINT32_MAX
        ? UINT32_MAX : (uint32_t)total_code_size;
    et->max_function_size = max_func_size;
    et->min_function_size = valid_ranges > 0 ? min_func_size : 0;
    et->handler_count = handler_count;
    et->chained_count = chained_count;
}

/*
 * Verify sort order of runtime function entries.
 * The exception table must be sorted by begin address for
 * binary search during exception dispatch.
 */
static int pe_verify_exception_sort_order(pe_ctx_t *ctx)
{
    pe_exception_table_t *et = &ctx->exceptions;
    int sorted = 1;

    for (uint32_t i = 1; i < et->count; i++) {
        if (et->entries[i].begin_rva < et->entries[i - 1].begin_rva) {
            pe_ctx_add_issue(ctx, 2, 0,
                "exception table: entries %u and %u are not sorted "
                "(0x%X > 0x%X)",
                i - 1, i,
                et->entries[i - 1].begin_rva, et->entries[i].begin_rva);
            sorted = 0;
        }
    }

    et->is_sorted = sorted;
    return sorted;
}

/*
 * Find overlapping function ranges in the exception table.
 * Overlapping ranges may indicate corrupted or packed data.
 */
static uint32_t pe_find_exception_overlaps(pe_ctx_t *ctx)
{
    pe_exception_table_t *et = &ctx->exceptions;
    uint32_t overlap_count = 0;

    for (uint32_t i = 0; i < et->count; i++) {
        for (uint32_t j = i + 1; j < et->count; j++) {
            pe_exception_entry_t *a = &et->entries[i];
            pe_exception_entry_t *b = &et->entries[j];

            if (a->begin_rva < b->end_rva && b->begin_rva < a->end_rva) {
                overlap_count++;
                if (overlap_count <= 5) {
                    pe_ctx_add_issue(ctx, 1, 0,
                        "exception entries %u [0x%X-0x%X] and %u [0x%X-0x%X] overlap",
                        i, a->begin_rva, a->end_rva,
                        j, b->begin_rva, b->end_rva);
                }
            }

            /* Stop checking after a non-overlapping entry if sorted */
            if (et->is_sorted && b->begin_rva >= a->end_rva) {
                break;
            }
        }
    }

    return overlap_count;
}

/*
 * Map exception entries to their covering sections and compute
 * per-section exception coverage statistics.
 */
static void pe_map_exceptions_to_sections(pe_ctx_t *ctx)
{
    pe_exception_table_t *et = &ctx->exceptions;

    for (uint32_t i = 0; i < et->count; i++) {
        pe_exception_entry_t *entry = &et->entries[i];

        /* Map begin address to a section */
        uint32_t sec_idx = pe_find_section_index_by_rva(ctx, entry->begin_rva);
        if (sec_idx != UINT32_MAX) {
            entry->code_section = sec_idx;
        }

        /* Map handler to a section if present */
        if (entry->unwind.has_handler && entry->unwind.handler_rva != 0) {
            entry->handler_section = pe_find_section_index_by_rva(
                ctx, entry->unwind.handler_rva);
        }
    }
}

/*
 * Parse the complete exception directory.
 * On x64, this is an array of 12-byte RUNTIME_FUNCTION entries.
 */
pe_error_t pe_parse_exception_table(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    /* Only meaningful for x64 */
    if (ctx->coff.machine != 0x8664 && ctx->coff.machine != 0xAA64) {
        return PE_OK;
    }

    pe_data_dir_t *exc_dir = &ctx->optional.data_dirs[PE_DIR_EXCEPTION];
    if (exc_dir->rva == 0 || exc_dir->size == 0) {
        return PE_OK;
    }

    uint32_t dir_offset = pe_rva_to_offset(ctx, exc_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_EXCEPTION,
                         "exception directory RVA 0x%X does not resolve",
                         exc_dir->rva);
        return PE_ERR_INVALID_EXCEPTION;
    }

    /* Each RUNTIME_FUNCTION is 12 bytes */
    uint32_t num_entries = exc_dir->size / 12;
    if (num_entries > PE_MAX_EXCEPTION_ENTRIES) {
        pe_ctx_add_warning(ctx,
            "exception table has %u entries, clamping to %u",
            num_entries, PE_MAX_EXCEPTION_ENTRIES);
        num_entries = PE_MAX_EXCEPTION_ENTRIES;
    }

    if (dir_offset >= ctx->size) {
        return PE_ERR_TRUNCATED;
    }

    uint32_t available = (uint32_t)((ctx->size - dir_offset) / 12);
    if (available < num_entries) {
        pe_ctx_add_warning(ctx, "exception directory truncated");
        num_entries = available;
    }

    if (num_entries == 0) {
        return PE_OK;
    }

    pe_exception_table_t *et = &ctx->exceptions;
    et->entries = (pe_exception_entry_t *)calloc(num_entries,
                                                   sizeof(pe_exception_entry_t));
    if (!et->entries) {
        return PE_ERR_ALLOC;
    }
    et->capacity = num_entries;

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) {
        return PE_ERR_TRUNCATED;
    }

    for (uint32_t i = 0; i < num_entries; i++) {
        pe_exception_entry_t *entry = &et->entries[et->count];

        if (!pe_reader_read_u32(&r, &entry->begin_rva)) break;
        if (!pe_reader_read_u32(&r, &entry->end_rva)) break;
        if (!pe_reader_read_u32(&r, &entry->unwind_rva)) break;

        /* Skip zero entries (padding) */
        if (entry->begin_rva == 0 && entry->end_rva == 0) {
            continue;
        }

        entry->code_section = UINT32_MAX;
        entry->handler_section = UINT32_MAX;

        /* Parse unwind info */
        if (entry->unwind_rva != 0) {
            pe_error_t err = pe_parse_unwind_info(ctx, entry, entry->unwind_rva);
            if (err != PE_OK) {
                pe_ctx_add_warning(ctx,
                    "exception entry %u: unwind info parse failed", i);
            }
        }

        pe_validate_exception_entry(ctx, entry, i);
        et->count++;
    }

    /* Post-processing */
    pe_verify_exception_sort_order(ctx);
    pe_map_exceptions_to_sections(ctx);
    pe_find_exception_overlaps(ctx);
    pe_compute_exception_stats(ctx);

    return PE_OK;
}

/* Free an unwind info structure */
static void pe_free_unwind_info(pe_unwind_info_t *info)
{
    if (!info) return;
    free(info->codes);
    info->codes = NULL;
    info->code_count = 0;
    info->parsed_code_count = 0;
    info->codes_capacity = 0;
}

/* Free the exception table */
void pe_free_exception_table(pe_exception_table_t *et)
{
    if (!et || !et->entries) return;
    for (uint32_t i = 0; i < et->count; i++) {
        pe_free_unwind_info(&et->entries[i].unwind);
    }
    free(et->entries);
    et->entries = NULL;
    et->count = 0;
    et->capacity = 0;
}

/* Public API: exception entry count */
uint32_t pe_get_exception_count(const pe_ctx_t *ctx)
{
    if (!ctx) return 0;
    return ctx->exceptions.count;
}

/* Public API: get exception entry */
const pe_exception_entry_t *pe_get_exception_entry(const pe_ctx_t *ctx,
                                                     uint32_t index)
{
    if (!ctx || index >= ctx->exceptions.count) return NULL;
    return &ctx->exceptions.entries[index];
}

/* Public API: get register name */
const char *pe_get_x64_register_name(uint8_t reg)
{
    return pe_x64_register_name(reg);
}

/* Public API: get unwind operation name */
const char *pe_get_unwind_op_name(uint8_t opcode)
{
    return pe_uwop_name(opcode);
}

/* Public API: find exception entry covering an RVA */
const pe_exception_entry_t *pe_find_exception_by_rva(const pe_ctx_t *ctx,
                                                       uint32_t rva)
{
    if (!ctx || ctx->exceptions.count == 0) return NULL;

    /* Binary search if sorted */
    if (ctx->exceptions.is_sorted) {
        uint32_t lo = 0, hi = ctx->exceptions.count;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            const pe_exception_entry_t *e = &ctx->exceptions.entries[mid];
            if (rva < e->begin_rva) {
                hi = mid;
            } else if (rva >= e->end_rva) {
                lo = mid + 1;
            } else {
                return e;
            }
        }
        return NULL;
    }

    /* Linear scan fallback */
    for (uint32_t i = 0; i < ctx->exceptions.count; i++) {
        const pe_exception_entry_t *e = &ctx->exceptions.entries[i];
        if (rva >= e->begin_rva && rva < e->end_rva) {
            return e;
        }
    }
    return NULL;
}
