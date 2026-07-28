/*
 * dos.c — DOS Stub Header Parsing (Phase 1)
 *
 * Parses the legacy DOS MZ header that precedes the PE signature.
 * The critical field is e_lfanew, which provides the file offset
 * to the PE signature. The remaining DOS header fields are preserved
 * for completeness but are not used in the PE analysis pipeline.
 *
 * Reference: Microsoft PE/COFF Specification §2
 */

#include "internal.h"

/*
 * Validate and extract DOS header fields from the raw data.
 * The DOS header occupies the first 64 bytes of the file.
 */
static pe_error_t pe_read_dos_fields(pe_ctx_t *ctx, pe_reader_t *r)
{
    pe_dos_header_t *dos = &ctx->dos;

    if (!pe_reader_read_u16(r, &dos->e_magic)) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED, "DOS header truncated at magic");
        return PE_ERR_TRUNCATED;
    }

    if (dos->e_magic != PE_DOS_MAGIC) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_DOS,
                         "invalid DOS magic: 0x%04X (expected 0x%04X)",
                         dos->e_magic, PE_DOS_MAGIC);
        return PE_ERR_INVALID_DOS;
    }

    if (!pe_reader_read_u16(r, &dos->e_cblp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_cp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_crlc)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_cparhdr)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_minalloc)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_maxalloc)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_ss)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_sp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_csum)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_ip)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_cs)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_lfarlc)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_ovno)) {
        return PE_ERR_TRUNCATED;
    }

    /* Reserved words (e_res[4]) */
    for (int i = 0; i < 4; i++) {
        if (!pe_reader_read_u16(r, &dos->e_res[i])) {
            return PE_ERR_TRUNCATED;
        }
    }

    if (!pe_reader_read_u16(r, &dos->e_oemid)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &dos->e_oeminfo)) {
        return PE_ERR_TRUNCATED;
    }

    /* Reserved words (e_res2[10]) */
    for (int i = 0; i < 10; i++) {
        if (!pe_reader_read_u16(r, &dos->e_res2[i])) {
            return PE_ERR_TRUNCATED;
        }
    }

    if (!pe_reader_read_u32(r, &dos->e_lfanew)) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED, "DOS header truncated at e_lfanew");
        return PE_ERR_TRUNCATED;
    }

    return PE_OK;
}

/*
 * Validate e_lfanew points to a valid location within the file
 * and is properly aligned.
 */
static pe_error_t pe_validate_lfanew(pe_ctx_t *ctx)
{
    uint32_t lfanew = ctx->dos.e_lfanew;

    if (lfanew < 64) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_DOS,
                         "e_lfanew too small: 0x%X (overlaps DOS header)", lfanew);
        return PE_ERR_INVALID_DOS;
    }

    if (lfanew > ctx->size - 4) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_DOS,
                         "e_lfanew points beyond file: 0x%X (file size: %zu)",
                         lfanew, ctx->size);
        return PE_ERR_INVALID_DOS;
    }

    if (lfanew & 3) {
        pe_ctx_add_warning(ctx, "e_lfanew not 4-byte aligned: 0x%X", lfanew);
    }

    if (lfanew > 1024) {
        pe_ctx_add_warning(ctx, "large DOS stub: e_lfanew = 0x%X", lfanew);
    }

    return PE_OK;
}

/*
 * Analyze the DOS stub region between the header and the PE signature.
 * Some compilers embed additional data in the DOS stub area.
 */
static void pe_analyze_dos_stub(pe_ctx_t *ctx)
{
    uint32_t stub_start = 64;
    uint32_t stub_end = ctx->dos.e_lfanew;

    if (stub_end <= stub_start) {
        return;
    }

    uint32_t stub_size = stub_end - stub_start;
    PE_UNUSED(stub_size);

    /* Check for Rich header signature */
    if (stub_end > 8) {
        for (uint32_t i = stub_start; i < stub_end - 8; i += 4) {
            if (PE_CHECK_OFFSET(ctx, i, 4)) {
                uint32_t val = PE_READ_U32(ctx->data + i);
                if (val == 0x68636952) { /* "Rich" */
                    pe_ctx_add_warning(ctx,
                        "Rich header detected at offset 0x%X", i);
                    break;
                }
            }
        }
    }
}

/* Public entry point: parse the DOS header (Phase 1) */
pe_error_t pe_parse_dos_header(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    if (ctx->size < 64) {
        pe_ctx_set_error(ctx, PE_ERR_TRUNCATED,
                         "file too small for DOS header: %zu bytes", ctx->size);
        return PE_ERR_TRUNCATED;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);

    pe_error_t err = pe_read_dos_fields(ctx, &r);
    if (err != PE_OK) {
        return err;
    }

    err = pe_validate_lfanew(ctx);
    if (err != PE_OK) {
        return err;
    }

    pe_analyze_dos_stub(ctx);

    return PE_OK;
}
