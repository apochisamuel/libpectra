/*
 * optional.c — PE Optional Header Parsing (Phase 3)
 *
 * Parses the optional header which appears after the COFF header in
 * PE executables. Supports both PE32 (32-bit) and PE32+ (64-bit)
 * formats. Extracts data directory entries that provide RVA+size
 * pairs for import, export, relocation, debug, and resource tables.
 *
 * Reference: Microsoft PE/COFF Specification §3.4
 */

#include "internal.h"

/* Parse PE32-specific address fields (32-bit) */
pe_error_t pe_parse_pe32_fields(pe_ctx_t *ctx, pe_reader_t *r)
{
    pe_optional_header_t *opt = &ctx->optional;
    uint32_t tmp32;

    if (!pe_reader_read_u32(r, &opt->base_of_data)) {
        return PE_ERR_TRUNCATED;
    }

    if (!pe_reader_read_u32(r, &tmp32)) {
        return PE_ERR_TRUNCATED;
    }
    opt->image_base = tmp32;

    if (!pe_reader_read_u32(r, &opt->section_alignment)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->file_alignment)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->major_os_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->minor_os_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->major_image_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->minor_image_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->major_subsystem_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->minor_subsystem_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->win32_version_value)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->size_of_image)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->size_of_headers)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->checksum)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->subsystem)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->dll_characteristics)) {
        return PE_ERR_TRUNCATED;
    }

    /* PE32: 4-byte stack/heap fields */
    if (!pe_reader_read_u32(r, &tmp32)) {
        return PE_ERR_TRUNCATED;
    }
    opt->stack_reserve = tmp32;

    if (!pe_reader_read_u32(r, &tmp32)) {
        return PE_ERR_TRUNCATED;
    }
    opt->stack_commit = tmp32;

    if (!pe_reader_read_u32(r, &tmp32)) {
        return PE_ERR_TRUNCATED;
    }
    opt->heap_reserve = tmp32;

    if (!pe_reader_read_u32(r, &tmp32)) {
        return PE_ERR_TRUNCATED;
    }
    opt->heap_commit = tmp32;

    if (!pe_reader_read_u32(r, &opt->loader_flags)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->num_data_dirs)) {
        return PE_ERR_TRUNCATED;
    }

    opt->is_pe32plus = 0;
    return PE_OK;
}

/* Parse PE32+-specific address fields (64-bit) */
pe_error_t pe_parse_pe32plus_fields(pe_ctx_t *ctx, pe_reader_t *r)
{
    pe_optional_header_t *opt = &ctx->optional;

    opt->base_of_data = 0;

    if (!pe_reader_read_u64(r, &opt->image_base)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->section_alignment)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->file_alignment)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->major_os_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->minor_os_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->major_image_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->minor_image_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->major_subsystem_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->minor_subsystem_version)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->win32_version_value)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->size_of_image)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->size_of_headers)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->checksum)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->subsystem)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &opt->dll_characteristics)) {
        return PE_ERR_TRUNCATED;
    }

    /* PE32+: 8-byte stack/heap fields */
    if (!pe_reader_read_u64(r, &opt->stack_reserve)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u64(r, &opt->stack_commit)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u64(r, &opt->heap_reserve)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u64(r, &opt->heap_commit)) {
        return PE_ERR_TRUNCATED;
    }

    if (!pe_reader_read_u32(r, &opt->loader_flags)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &opt->num_data_dirs)) {
        return PE_ERR_TRUNCATED;
    }

    opt->is_pe32plus = 1;
    return PE_OK;
}

/* Parse the data directory array */
pe_error_t pe_parse_data_directories(pe_ctx_t *ctx, pe_reader_t *r)
{
    pe_optional_header_t *opt = &ctx->optional;

    uint32_t count = opt->num_data_dirs;
    if (count > PE_NUM_DATA_DIRS) {
        pe_ctx_add_warning(ctx,
            "data directory count %u exceeds standard %u, clamping",
            count, PE_NUM_DATA_DIRS);
        count = PE_NUM_DATA_DIRS;
    }

    memset(opt->data_dirs, 0, sizeof(opt->data_dirs));

    for (uint32_t i = 0; i < count; i++) {
        if (!pe_reader_read_u32(r, &opt->data_dirs[i].rva)) {
            return PE_ERR_TRUNCATED;
        }
        if (!pe_reader_read_u32(r, &opt->data_dirs[i].size)) {
            return PE_ERR_TRUNCATED;
        }
    }

    /* Skip any extra data directory entries beyond the standard set */
    if (opt->num_data_dirs > PE_NUM_DATA_DIRS) {
        uint32_t extra = opt->num_data_dirs - PE_NUM_DATA_DIRS;
        if (!pe_reader_skip(r, extra * 8)) {
            return PE_ERR_TRUNCATED;
        }
    }

    return PE_OK;
}

/*
 * Validate optional header fields for internal consistency.
 */
static pe_error_t pe_validate_optional_fields(pe_ctx_t *ctx)
{
    pe_optional_header_t *opt = &ctx->optional;

    if (opt->section_alignment == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_OPTIONAL,
                         "section alignment is zero");
        return PE_ERR_INVALID_OPTIONAL;
    }

    if (opt->file_alignment == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_OPTIONAL,
                         "file alignment is zero");
        return PE_ERR_INVALID_OPTIONAL;
    }

    /* File alignment must be a power of 2 between 512 and 65536 */
    if (opt->file_alignment < 512 || opt->file_alignment > 65536) {
        pe_ctx_add_warning(ctx,
            "unusual file alignment: %u", opt->file_alignment);
    }

    if ((opt->file_alignment & (opt->file_alignment - 1)) != 0) {
        pe_ctx_add_warning(ctx,
            "file alignment not power of 2: %u", opt->file_alignment);
    }

    /* Section alignment must be >= file alignment */
    if (opt->section_alignment < opt->file_alignment) {
        pe_ctx_add_warning(ctx,
            "section alignment %u < file alignment %u",
            opt->section_alignment, opt->file_alignment);
    }

    if (opt->size_of_image == 0) {
        pe_ctx_add_warning(ctx, "size of image is zero");
    }

    if (opt->size_of_headers == 0) {
        pe_ctx_add_warning(ctx, "size of headers is zero");
    }

    if (opt->entry_point_rva != 0 && opt->size_of_image != 0 &&
        opt->entry_point_rva >= opt->size_of_image) {
        pe_ctx_add_warning(ctx,
            "entry point RVA 0x%X exceeds image size 0x%X",
            opt->entry_point_rva, opt->size_of_image);
    }

    /* Validate data directory entries reference valid RVAs */
    for (uint32_t i = 0; i < PE_NUM_DATA_DIRS; i++) {
        pe_data_dir_t *dd = &opt->data_dirs[i];
        if (dd->rva == 0 && dd->size == 0) {
            continue;
        }
        if (dd->rva != 0 && dd->size == 0) {
            pe_ctx_add_warning(ctx,
                "data directory %u has RVA 0x%X but zero size", i, dd->rva);
        }
        if (dd->size != 0 && dd->rva == 0) {
            pe_ctx_add_warning(ctx,
                "data directory %u has size %u but zero RVA", i, dd->size);
        }
    }

    return PE_OK;
}

/* Return the subsystem name */
const char *pe_get_subsystem_name(uint16_t subsystem)
{
    switch (subsystem) {
    case PE_SUBSYS_UNKNOWN:      return "Unknown";
    case PE_SUBSYS_NATIVE:       return "Native";
    case PE_SUBSYS_WINDOWS_GUI:  return "Windows GUI";
    case PE_SUBSYS_WINDOWS_CUI:  return "Windows Console";
    case PE_SUBSYS_POSIX_CUI:    return "POSIX Console";
    case PE_SUBSYS_WINDOWS_CE:   return "Windows CE";
    case PE_SUBSYS_EFI_APP:      return "EFI Application";
    default:                     return "Other";
    }
}

/*
 * Parse the complete optional header at the given file offset.
 * Determines PE32 vs PE32+ from the magic field.
 */
pe_error_t pe_parse_optional_header(pe_ctx_t *ctx, uint32_t offset)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    if (!PE_CHECK_OFFSET(ctx, offset, 2)) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED,
                         "optional header truncated at offset 0x%X", offset);
        return PE_ERR_TRUNCATED;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_optional_header_t *opt = &ctx->optional;

    /* Standard fields common to PE32 and PE32+ */
    if (!pe_reader_read_u16(&r, &opt->magic)) {
        return PE_ERR_TRUNCATED;
    }

    if (opt->magic != PE_OPT_MAGIC_PE32 && opt->magic != PE_OPT_MAGIC_PE32PLUS) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_OPTIONAL,
                         "invalid optional header magic: 0x%04X", opt->magic);
        return PE_ERR_INVALID_OPTIONAL;
    }

    if (!pe_reader_read_u8(&r, &opt->major_linker)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u8(&r, &opt->minor_linker)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &opt->size_of_code)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &opt->size_of_init_data)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &opt->size_of_uninit_data)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &opt->entry_point_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &opt->base_of_code)) {
        return PE_ERR_TRUNCATED;
    }

    /* Format-specific fields */
    pe_error_t err;
    if (opt->magic == PE_OPT_MAGIC_PE32) {
        err = pe_parse_pe32_fields(ctx, &r);
    } else {
        err = pe_parse_pe32plus_fields(ctx, &r);
    }

    if (err != PE_OK) {
        pe_ctx_set_error(ctx, err, "optional header fields parse failed");
        return err;
    }

    /* Data directories follow the format-specific fields */
    err = pe_parse_data_directories(ctx, &r);
    if (err != PE_OK) {
        pe_ctx_set_error(ctx, err, "data directory parse failed");
        return err;
    }

    err = pe_validate_optional_fields(ctx);
    if (err != PE_OK) {
        return err;
    }

    return PE_OK;
}
