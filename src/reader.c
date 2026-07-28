/*
 * reader.c — Binary data reader utilities
 *
 * Provides a cursor-based reader for safe sequential and random access
 * to the raw PE binary data. All multi-byte reads are little-endian
 * per the PE/COFF specification.
 */

#include "internal.h"

/* Initialize reader over a data buffer */
void pe_reader_init(pe_reader_t *r, const uint8_t *data, size_t size)
{
    r->base = data;
    r->total_size = size;
    r->offset = 0;
}

/* Seek to absolute offset, returns 1 on success */
int pe_reader_seek(pe_reader_t *r, size_t offset)
{
    if (offset > r->total_size) {
        return 0;
    }
    r->offset = offset;
    return 1;
}

/* Skip forward by count bytes */
int pe_reader_skip(pe_reader_t *r, size_t count)
{
    if (count > r->total_size - r->offset) {
        return 0;
    }
    r->offset += count;
    return 1;
}

/* Return current read position */
size_t pe_reader_tell(const pe_reader_t *r)
{
    return r->offset;
}

/* Return bytes remaining from current position */
size_t pe_reader_remaining(const pe_reader_t *r)
{
    if (r->offset >= r->total_size) {
        return 0;
    }
    return r->total_size - r->offset;
}

/* Check if count bytes can be read from current position */
int pe_reader_can_read(const pe_reader_t *r, size_t count)
{
    return r->offset <= r->total_size && count <= r->total_size - r->offset;
}

/* Read unsigned 8-bit integer */
int pe_reader_read_u8(pe_reader_t *r, uint8_t *out)
{
    if (!pe_reader_can_read(r, 1)) {
        return 0;
    }
    *out = r->base[r->offset];
    r->offset += 1;
    return 1;
}

/* Read unsigned 16-bit integer (little-endian) */
int pe_reader_read_u16(pe_reader_t *r, uint16_t *out)
{
    if (!pe_reader_can_read(r, 2)) {
        return 0;
    }
    *out = PE_READ_U16(r->base + r->offset);
    r->offset += 2;
    return 1;
}

/* Read unsigned 32-bit integer (little-endian) */
int pe_reader_read_u32(pe_reader_t *r, uint32_t *out)
{
    if (!pe_reader_can_read(r, 4)) {
        return 0;
    }
    *out = PE_READ_U32(r->base + r->offset);
    r->offset += 4;
    return 1;
}

/* Read unsigned 64-bit integer (little-endian) */
int pe_reader_read_u64(pe_reader_t *r, uint64_t *out)
{
    if (!pe_reader_can_read(r, 8)) {
        return 0;
    }
    *out = PE_READ_U64(r->base + r->offset);
    r->offset += 8;
    return 1;
}

/* Read a block of raw bytes into buffer */
int pe_reader_read_bytes(pe_reader_t *r, void *buf, size_t count)
{
    if (!pe_reader_can_read(r, count)) {
        return 0;
    }
    memcpy(buf, r->base + r->offset, count);
    r->offset += count;
    return 1;
}

/* Peek at data without advancing cursor */
const uint8_t *pe_reader_peek(const pe_reader_t *r, size_t count)
{
    if (!pe_reader_can_read(r, count)) {
        return NULL;
    }
    return r->base + r->offset;
}

/* Read null-terminated C string into buffer with maximum length */
int pe_reader_read_cstring(pe_reader_t *r, char *buf, size_t bufsz,
                           size_t *out_len)
{
    if (bufsz == 0) {
        return 0;
    }

    size_t i = 0;
    size_t max_read = pe_reader_remaining(r);
    if (max_read > bufsz - 1) {
        max_read = bufsz - 1;
    }

    while (i < max_read) {
        uint8_t ch = r->base[r->offset + i];
        if (ch == 0) {
            buf[i] = '\0';
            r->offset += i + 1;
            if (out_len) {
                *out_len = i;
            }
            return 1;
        }
        buf[i] = (char)ch;
        i++;
    }

    buf[i] = '\0';
    r->offset += i;
    if (out_len) {
        *out_len = i;
    }
    return 1;
}

/* Read fixed-length string field (may not be null-terminated) */
int pe_reader_read_fixed_string(pe_reader_t *r, char *buf, size_t len)
{
    if (!pe_reader_can_read(r, len)) {
        return 0;
    }
    memcpy(buf, r->base + r->offset, len);
    buf[len] = '\0';
    r->offset += len;
    return 1;
}

/* Copy a range of bytes from the underlying data, returns allocated buffer */
uint8_t *pe_reader_copy_range(pe_reader_t *r, size_t offset, size_t length)
{
    if (offset > r->total_size || length > r->total_size - offset) {
        return NULL;
    }
    if (length == 0) {
        return NULL;
    }

    uint8_t *buf = (uint8_t *)malloc(length);
    if (!buf) {
        return NULL;
    }
    memcpy(buf, r->base + offset, length);
    return buf;
}

/*
 * Resolve an RVA to a file offset using the section table.
 * Returns the file offset, or 0 on failure.
 */
uint32_t pe_rva_to_offset(const pe_ctx_t *ctx, uint32_t rva)
{
    if (!ctx) {
        return 0;
    }

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        uint64_t start = sec->virtual_address;
        uint64_t span = sec->virtual_size != 0
            ? sec->virtual_size : sec->raw_data_size;
        uint64_t end = start + span;

        if ((uint64_t)rva >= start && (uint64_t)rva < end) {
            uint64_t delta = (uint64_t)rva - start;
            if (delta >= sec->raw_data_size) {
                return 0;
            }

            uint64_t file_offset = (uint64_t)sec->raw_data_offset + delta;
            if (file_offset > UINT32_MAX || file_offset >= ctx->size) {
                return 0;
            }
            return (uint32_t)file_offset;
        }
    }

    if (rva < ctx->optional.size_of_headers && (uint64_t)rva < ctx->size) {
        return rva;
    }

    return 0;
}

/*
 * Resolve an RVA to a data pointer within the loaded image.
 * Verifies that at least min_size bytes are accessible.
 */
const uint8_t *pe_rva_to_ptr(const pe_ctx_t *ctx, uint32_t rva, size_t min_size)
{
    uint32_t offset = pe_rva_to_offset(ctx, rva);
    if (offset == 0 && rva != 0) {
        return NULL;
    }

    if (!PE_CHECK_OFFSET(ctx, offset, min_size)) {
        return NULL;
    }

    return ctx->data + offset;
}

/* Find the section index that contains a given RVA */
uint32_t pe_find_section_index_by_rva(const pe_ctx_t *ctx, uint32_t rva)
{
    if (!ctx) {
        return UINT32_MAX;
    }

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        uint64_t start = sec->virtual_address;
        uint64_t span = sec->virtual_size != 0
            ? sec->virtual_size : sec->raw_data_size;
        uint64_t end = start + span;

        if ((uint64_t)rva >= start && (uint64_t)rva < end) {
            return i;
        }
    }
    return UINT32_MAX;
}

/*
 * Get a writable pointer into a section's loaded data buffer
 * corresponding to the given RVA.
 */
uint8_t *pe_section_rva_to_ptr(const pe_ctx_t *ctx, uint32_t section_index,
                                uint32_t rva, size_t min_size)
{
    if (section_index >= ctx->sections.count) {
        return NULL;
    }

    const pe_section_t *sec = &ctx->sections.entries[section_index];
    if (!sec->data || sec->data_size == 0) {
        return NULL;
    }

    if (rva < sec->virtual_address) {
        return NULL;
    }

    uint32_t delta = rva - sec->virtual_address;
    if (delta >= sec->data_size || min_size > sec->data_size - delta) {
        return NULL;
    }

    return sec->data + delta;
}
