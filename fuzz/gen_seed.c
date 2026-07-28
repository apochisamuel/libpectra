/*
 * gen_seed.c — Generate minimal PE seed corpus files
 *
 * Creates minimal valid PE32+ files suitable for use as seed
 * inputs for the fuzzer harnesses. Each seed targets different
 * structural features (imports, exports, resources, etc.).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void w16(uint8_t *b, size_t o, uint16_t v) {
    b[o] = (uint8_t)(v & 0xFF);
    b[o+1] = (uint8_t)((v >> 8) & 0xFF);
}

static void w32(uint8_t *b, size_t o, uint32_t v) {
    b[o] = (uint8_t)(v & 0xFF);
    b[o+1] = (uint8_t)((v >> 8) & 0xFF);
    b[o+2] = (uint8_t)((v >> 16) & 0xFF);
    b[o+3] = (uint8_t)((v >> 24) & 0xFF);
}

static void w64(uint8_t *b, size_t o, uint64_t v) {
    w32(b, o, (uint32_t)(v & 0xFFFFFFFF));
    w32(b, o+4, (uint32_t)(v >> 32));
}

static void wstr(uint8_t *b, size_t o, const char *s, size_t l) {
    size_t sl = strlen(s);
    if (sl > l) sl = l;
    memcpy(b + o, s, sl);
}

/* Build a minimal PE32+ with configurable sections */
static size_t build_seed(uint8_t *buf, size_t bufsz, int num_secs,
                          const char *sec_names[], uint32_t sec_chars[])
{
    memset(buf, 0, bufsz);

    /* DOS header */
    w16(buf, 0, 0x5A4D);
    w32(buf, 60, 0x80);

    /* PE signature */
    w32(buf, 0x80, 0x00004550);

    /* COFF header */
    w16(buf, 0x84, 0x8664);  /* AMD64 */
    w16(buf, 0x86, (uint16_t)num_secs);
    w32(buf, 0x88, 0x60001234);
    w16(buf, 0x94, 240);     /* optional header size */
    w16(buf, 0x96, 0x0022);  /* EXEC | LARGE_ADDR */

    /* Optional header */
    w16(buf, 0x98, 0x020B);  /* PE32+ */
    buf[0x9A] = 14;
    w32(buf, 0x9C, 0x1000);
    w32(buf, 0xA0, 0x1000);
    w32(buf, 0xA8, 0x1000);
    w32(buf, 0xAC, 0x1000);
    w64(buf, 0xB0, 0x140000000ULL);
    w32(buf, 0xB8, 0x1000);
    w32(buf, 0xBC, 0x200);
    w32(buf, 0xCC, 0x10000);
    w32(buf, 0xD0, 0x200);
    w16(buf, 0xD8, 3);
    w16(buf, 0xDA, 0x8160);
    w64(buf, 0xDC, 0x100000);
    w64(buf, 0xE4, 0x1000);
    w64(buf, 0xEC, 0x100000);
    w64(buf, 0xF4, 0x1000);
    w32(buf, 0x104, 16);

    /* Section headers at 0x188 (after 240 bytes of optional header) */
    size_t sec_hdr = 0x188;
    for (int i = 0; i < num_secs; i++) {
        wstr(buf, sec_hdr, sec_names[i], 8);
        w32(buf, sec_hdr + 8, 0x1000);
        w32(buf, sec_hdr + 12, 0x1000 * (uint32_t)(i + 1));
        w32(buf, sec_hdr + 16, 0x200);
        w32(buf, sec_hdr + 20, 0x200 * (uint32_t)(i + 1));
        w32(buf, sec_hdr + 36, sec_chars[i]);
        sec_hdr += 40;
    }

    /* Section data */
    size_t data_start = 0x200;
    for (int i = 0; i < num_secs; i++) {
        size_t off = data_start + (size_t)i * 0x200;
        if (off + 0x200 > bufsz) break;
        for (size_t j = 0; j < 0x200; j++) {
            buf[off + j] = (uint8_t)((i * 17 + j) & 0xFF);
        }
    }

    return data_start + (size_t)num_secs * 0x200;
}

static void write_file(const char *path, const uint8_t *data, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Cannot create %s\n", path);
        return;
    }
    fwrite(data, 1, size, f);
    fclose(f);
    printf("  Created %s (%zu bytes)\n", path, size);
}

int main(void)
{
    uint8_t buf[8192];

    printf("Generating seed corpus files...\n");

    /* Seed 1: minimal 2-section PE */
    {
        const char *names[] = {".text", ".rdata"};
        uint32_t chars[] = {0x60000020, 0x40000040};
        size_t sz = build_seed(buf, sizeof(buf), 2, names, chars);
        write_file("fuzz/corpus/parse_fuzzer/seed_minimal.bin", buf, sz);
        write_file("fuzz/corpus/import_fuzzer/seed_minimal.bin", buf, sz);
        write_file("fuzz/corpus/resource_fuzzer/seed_minimal.bin", buf, sz);
    }

    /* Seed 2: 4-section PE */
    {
        const char *names[] = {".text", ".rdata", ".data", ".rsrc"};
        uint32_t chars[] = {0x60000020, 0x40000040, 0xC0000040, 0x40000040};
        size_t sz = build_seed(buf, sizeof(buf), 4, names, chars);
        write_file("fuzz/corpus/parse_fuzzer/seed_4sec.bin", buf, sz);
    }

    /* Seed 3: writable code section (suspicious pattern) */
    {
        const char *names[] = {".text", ".reloc"};
        uint32_t chars[] = {0xE0000020, 0x42000040};
        size_t sz = build_seed(buf, sizeof(buf), 2, names, chars);
        write_file("fuzz/corpus/parse_fuzzer/seed_rwx.bin", buf, sz);
    }

    printf("Done.\n");
    return 0;
}
