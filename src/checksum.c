/*
 * checksum.c — PE Checksum Computation
 *
 * Implements the PE checksum algorithm used to verify image
 * integrity. The checksum is a 32-bit value stored in the
 * optional header that covers the entire file contents, excluding
 * the checksum field itself.
 *
 * The algorithm processes the file as an array of 16-bit words,
 * accumulating a fold-carry sum similar to the TCP/IP checksum.
 *
 * Reference: Microsoft PE/COFF Specification §3.4 (CheckSum field)
 */

#include "internal.h"

/*
 * Compute the PE checksum over the raw file data.
 *
 * The checksum field is located at a specific offset within the
 * optional header (offset 64 from the start of the optional header
 * in both PE32 and PE32+). The bytes at this position are skipped
 * during computation to avoid a circular dependency.
 *
 * Parameters:
 *   data            - Raw PE file data
 *   size            - Size of the data in bytes
 *   checksum_offset - File offset of the checksum field (4 bytes)
 *
 * Returns the computed checksum value.
 */
uint32_t pe_compute_checksum(const uint8_t *data, size_t size,
                              uint32_t checksum_offset)
{
    if (!data || size == 0) {
        return 0;
    }

    uint64_t sum = 0;
    uint32_t word_count = (uint32_t)(size / 2);

    /*
     * Process the file as 16-bit little-endian words.
     * Skip the two 16-bit words that make up the checksum field.
     */
    for (uint32_t i = 0; i < word_count; i++) {
        uint32_t byte_offset = i * 2;

        /* Skip the checksum field (4 bytes = 2 words) */
        if (byte_offset == checksum_offset ||
            byte_offset == checksum_offset + 2) {
            continue;
        }

        uint16_t word = PE_READ_U16(data + byte_offset);
        sum += word;
    }

    /* Handle odd trailing byte */
    if (size & 1) {
        sum += data[size - 1];
    }

    /* Fold 64-bit sum to 32 bits with carry propagation */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* Add file size to produce the final checksum */
    sum += (uint32_t)size;

    return (uint32_t)sum;
}

/*
 * Verify the PE checksum stored in the optional header.
 *
 * Computes the expected checksum and compares it against the
 * value stored in the file. A mismatch may indicate file
 * corruption or modification after signing.
 */
int pe_verify_checksum(const pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return 0;
    }

    uint32_t stored_checksum = ctx->optional.checksum;
    if (stored_checksum == 0) {
        /* Zero checksum is valid — many linkers don't set it */
        return 1;
    }

    /*
     * Compute the offset of the checksum field in the file.
     * It's at optional header offset + 64 in both PE32 and PE32+.
     */
    uint32_t opt_offset = ctx->dos.e_lfanew + 4 + 20;
    uint32_t checksum_field_offset = opt_offset + 64;

    if (checksum_field_offset + 4 > ctx->size) {
        return 0;
    }

    uint32_t computed = pe_compute_checksum(ctx->data, ctx->size,
                                            checksum_field_offset);

    return computed == stored_checksum;
}

/*
 * Validate the PE checksum and record the result.
 * Called from the validation phase.
 */
pe_error_t pe_validate_pe_checksum(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    uint32_t stored = ctx->optional.checksum;
    if (stored == 0) {
        return PE_OK;
    }

    uint32_t opt_offset = ctx->dos.e_lfanew + 4 + 20;
    uint32_t cs_offset = opt_offset + 64;

    if (cs_offset + 4 > ctx->size) {
        pe_ctx_add_issue(ctx, 1, 0,
            "checksum field offset 0x%X beyond file size %zu",
            cs_offset, ctx->size);
        return PE_ERR_CHECKSUM_MISMATCH;
    }

    uint32_t computed = pe_compute_checksum(ctx->data, ctx->size, cs_offset);

    if (computed != stored) {
        pe_ctx_add_issue(ctx, 1, 0,
            "PE checksum mismatch: stored 0x%08X, computed 0x%08X",
            stored, computed);
        return PE_ERR_CHECKSUM_MISMATCH;
    }

    return PE_OK;
}
