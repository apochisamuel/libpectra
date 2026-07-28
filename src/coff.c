/*
 * coff.c — PE Signature and COFF File Header Parsing (Phase 2)
 *
 * Validates the PE signature ("PE\0\0") and parses the 20-byte
 * COFF file header that follows. The COFF header provides the
 * machine type, section count, symbol table location, and
 * optional header size.
 *
 * Reference: Microsoft PE/COFF Specification §3
 */

#include "internal.h"

/* Validate the 4-byte PE signature at the offset specified by e_lfanew */
pe_error_t pe_parse_pe_signature(pe_ctx_t *ctx, uint32_t offset)
{
    if (!PE_CHECK_OFFSET(ctx, offset, 4)) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED,
                         "PE signature truncated at offset 0x%X", offset);
        return PE_ERR_TRUNCATED;
    }

    uint32_t sig = PE_READ_U32(ctx->data + offset);
    if (sig != PE_SIGNATURE) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_PE_SIG,
                         "invalid PE signature: 0x%08X at offset 0x%X",
                         sig, offset);
        return PE_ERR_INVALID_PE_SIG;
    }

    return PE_OK;
}

/* Check whether a machine type value is recognized */
static int pe_is_known_machine(uint16_t machine)
{
    switch (machine) {
    case PE_MACHINE_UNKNOWN:
    case PE_MACHINE_I386:
    case PE_MACHINE_AMD64:
    case PE_MACHINE_ARM:
    case PE_MACHINE_ARM64:
    case PE_MACHINE_ARMNT:
    case PE_MACHINE_IA64:
        return 1;
    default:
        return 0;
    }
}

/* Return a human-readable machine type name */
const char *pe_get_machine_name(uint16_t machine)
{
    switch (machine) {
    case PE_MACHINE_UNKNOWN: return "Unknown";
    case PE_MACHINE_I386:    return "i386";
    case PE_MACHINE_AMD64:   return "AMD64";
    case PE_MACHINE_ARM:     return "ARM";
    case PE_MACHINE_ARM64:   return "ARM64";
    case PE_MACHINE_ARMNT:   return "ARM Thumb-2";
    case PE_MACHINE_IA64:    return "IA-64";
    default:                 return "Unrecognized";
    }
}

/*
 * Validate COFF header field ranges.
 * Non-fatal issues are recorded as warnings.
 */
static pe_error_t pe_validate_coff_fields(pe_ctx_t *ctx)
{
    pe_coff_header_t *coff = &ctx->coff;

    if (!pe_is_known_machine(coff->machine)) {
        pe_ctx_add_warning(ctx, "unrecognized machine type: 0x%04X",
                           coff->machine);
    }

    if (coff->num_sections == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_COFF,
                         "COFF header specifies zero sections");
        return PE_ERR_INVALID_COFF;
    }

    if (coff->num_sections > PE_MAX_SECTIONS) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_COFF,
                         "too many sections: %u (max %u)",
                         coff->num_sections, PE_MAX_SECTIONS);
        return PE_ERR_INVALID_COFF;
    }

    if (coff->optional_header_size > 0 &&
        coff->optional_header_size < 28) {
        pe_ctx_add_warning(ctx,
            "optional header size unexpectedly small: %u bytes",
            coff->optional_header_size);
    }

    if (coff->symbol_table_offset != 0 &&
        coff->symbol_table_offset >= ctx->size) {
        pe_ctx_add_warning(ctx,
            "symbol table offset beyond file: 0x%X", coff->symbol_table_offset);
    }

    if (coff->num_symbols > PE_MAX_SYMBOLS) {
        pe_ctx_add_warning(ctx,
            "large symbol count: %u", coff->num_symbols);
    }

    return PE_OK;
}

/*
 * Analyze COFF characteristics flags to determine binary properties.
 * Results are informational and stored as context metadata.
 */
static void pe_analyze_characteristics(pe_ctx_t *ctx)
{
    uint16_t chars = ctx->coff.characteristics;

    if (chars & 0x0001) {
        /* IMAGE_FILE_RELOCS_STRIPPED */
    }
    if (chars & 0x0002) {
        /* IMAGE_FILE_EXECUTABLE_IMAGE */
    }
    if (chars & 0x2000) {
        /* IMAGE_FILE_DLL */
    }
    if (chars & 0x0100) {
        /* IMAGE_FILE_32BIT_MACHINE */
    }
    if (chars & 0x0020) {
        /* IMAGE_FILE_LARGE_ADDRESS_AWARE */
    }

    if ((chars & 0x0002) == 0 && (chars & 0x2000) == 0) {
        pe_ctx_add_warning(ctx,
            "neither executable nor DLL flag set in characteristics");
    }
}

/*
 * Parse the 20-byte COFF file header following the PE signature.
 * The header is located at e_lfanew + 4.
 */
pe_error_t pe_parse_coff_header(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    uint32_t offset = ctx->dos.e_lfanew + 4;

    if (!PE_CHECK_OFFSET(ctx, offset, 20)) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED,
                         "COFF header truncated at offset 0x%X", offset);
        return PE_ERR_TRUNCATED;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_coff_header_t *coff = &ctx->coff;

    if (!pe_reader_read_u16(&r, &coff->machine)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(&r, &coff->num_sections)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &coff->timestamp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &coff->symbol_table_offset)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &coff->num_symbols)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(&r, &coff->optional_header_size)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(&r, &coff->characteristics)) {
        return PE_ERR_TRUNCATED;
    }

    pe_error_t err = pe_validate_coff_fields(ctx);
    if (err != PE_OK) {
        return err;
    }

    pe_analyze_characteristics(ctx);

    return PE_OK;
}
