/*
 * test_basic.c — Basic Integration Tests for libpectra
 *
 * Constructs minimal synthetic PE files in memory and verifies
 * that the parsing pipeline produces correct results. Each test
 * builds a PE binary from scratch with specific features enabled
 * to exercise different code paths.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "internal.h"

/* Write a little-endian 16-bit value at a buffer offset */
static void write_u16(uint8_t *buf, size_t off, uint16_t val)
{
    buf[off + 0] = (uint8_t)(val & 0xFF);
    buf[off + 1] = (uint8_t)((val >> 8) & 0xFF);
}

/* Write a little-endian 32-bit value at a buffer offset */
static void write_u32(uint8_t *buf, size_t off, uint32_t val)
{
    buf[off + 0] = (uint8_t)(val & 0xFF);
    buf[off + 1] = (uint8_t)((val >> 8) & 0xFF);
    buf[off + 2] = (uint8_t)((val >> 16) & 0xFF);
    buf[off + 3] = (uint8_t)((val >> 24) & 0xFF);
}

/* Write a little-endian 64-bit value at a buffer offset */
static void write_u64(uint8_t *buf, size_t off, uint64_t val)
{
    write_u32(buf, off, (uint32_t)(val & 0xFFFFFFFF));
    write_u32(buf, off + 4, (uint32_t)(val >> 32));
}

/* Write a fixed-length string at a buffer offset (padded with zeros) */
static void write_str(uint8_t *buf, size_t off, const char *str, size_t len)
{
    size_t slen = strlen(str);
    if (slen > len) slen = len;
    memcpy(buf + off, str, slen);
    if (slen < len) {
        memset(buf + off + slen, 0, len - slen);
    }
}

/* ----------------------------------------------------------------
 * Test infrastructure
 * ---------------------------------------------------------------- */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg)                                         \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("  FAIL: %s (line %d)\n", msg, __LINE__);           \
            tests_failed++;                                             \
            return;                                                     \
        }                                                               \
    } while (0)

#define TEST_BEGIN(name)                                                \
    do {                                                                \
        printf("  [%3d] %-50s ", tests_run + 1, name);                 \
        tests_run++;                                                    \
    } while (0)

#define TEST_PASS()                                                     \
    do {                                                                \
        printf("PASS\n");                                               \
        tests_passed++;                                                 \
    } while (0)

/* ----------------------------------------------------------------
 * Synthetic PE builder
 * ---------------------------------------------------------------- */

#define PE_BUF_SIZE 8192

/*
 * Build a minimal PE32+ file with configurable features.
 * Returns the total size written to buf.
 */
static size_t build_minimal_pe(uint8_t *buf, size_t bufsz,
                                uint16_t machine, uint16_t num_sections,
                                uint32_t timestamp, int with_optional)
{
    memset(buf, 0, bufsz);
    size_t pos = 0;

    /* DOS Header (64 bytes) */
    write_u16(buf, 0, 0x5A4D);       /* e_magic = "MZ" */
    write_u16(buf, 2, 0x0090);       /* e_cblp */
    write_u16(buf, 4, 0x0003);       /* e_cp */
    write_u16(buf, 8, 0x0004);       /* e_cparhdr */
    write_u16(buf, 24, 0x00B8);      /* e_sp */
    write_u16(buf, 36, 0x0040);      /* e_lfarlc */
    write_u32(buf, 60, 0x00000080);  /* e_lfanew */
    pos = 128;

    /* PE Signature at offset 0x80 */
    write_u32(buf, 0x80, 0x00004550);  /* "PE\0\0" */
    pos = 0x84;

    /* COFF Header (20 bytes) at offset 0x84 */
    write_u16(buf, pos + 0, machine);
    write_u16(buf, pos + 2, num_sections);
    write_u32(buf, pos + 4, timestamp);
    write_u32(buf, pos + 8, 0);    /* symbol table offset */
    write_u32(buf, pos + 12, 0);   /* num symbols */

    uint16_t opt_size = with_optional ? 240 : 0;
    write_u16(buf, pos + 16, opt_size);  /* optional header size */
    write_u16(buf, pos + 18, 0x0022);    /* characteristics: EXEC | LARGE_ADDR */
    pos += 20;

    /* Optional Header (PE32+: 240 bytes) at offset 0x98 */
    if (with_optional) {
        uint32_t opt_start = (uint32_t)pos;

        write_u16(buf, pos + 0, 0x020B);  /* PE32+ magic */
        buf[pos + 2] = 14;                /* major linker version */
        buf[pos + 3] = 0;                 /* minor linker version */
        write_u32(buf, pos + 4, 0x1000);  /* size of code */
        write_u32(buf, pos + 8, 0x1000);  /* size of init data */
        write_u32(buf, pos + 16, 0x1000); /* entry point RVA */
        write_u32(buf, pos + 20, 0x1000); /* base of code */

        /* PE32+ specific fields */
        write_u64(buf, pos + 24, 0x0000000140000000ULL); /* image base */
        write_u32(buf, pos + 32, 0x1000);  /* section alignment */
        write_u32(buf, pos + 36, 0x0200);  /* file alignment */
        write_u16(buf, pos + 40, 6);       /* major OS version */
        write_u16(buf, pos + 42, 0);       /* minor OS version */
        write_u32(buf, pos + 56, 0x10000); /* size of image */
        write_u32(buf, pos + 60, 0x0200);  /* size of headers */
        write_u32(buf, pos + 64, 0);       /* checksum */
        write_u16(buf, pos + 68, 3);       /* subsystem: console */
        write_u16(buf, pos + 70, 0x8160);  /* DLL characteristics */
        write_u64(buf, pos + 72, 0x100000);  /* stack reserve */
        write_u64(buf, pos + 80, 0x1000);    /* stack commit */
        write_u64(buf, pos + 88, 0x100000);  /* heap reserve */
        write_u64(buf, pos + 96, 0x1000);    /* heap commit */
        write_u32(buf, pos + 108, 16);       /* num data dirs */

        /* Data directories (16 * 8 = 128 bytes) — all zeros */
        pos += 240;

        (void)opt_start;
    }

    /* Section headers (40 bytes each) */
    for (uint16_t s = 0; s < num_sections; s++) {
        uint32_t sec_off = (uint32_t)pos;
        char sec_name[9];
        snprintf(sec_name, sizeof(sec_name), ".sec%u", (unsigned)(s % 1000));

        write_str(buf, sec_off, sec_name, 8);
        write_u32(buf, sec_off + 8, 0x1000);                /* virtual size */
        write_u32(buf, sec_off + 12, 0x1000 * (s + 1));     /* virtual address */
        write_u32(buf, sec_off + 16, 0x0200);                /* raw data size */
        write_u32(buf, sec_off + 20, 0x0200 * (s + 1));     /* raw data offset */
        write_u32(buf, sec_off + 36, 0x60000020);            /* CODE | EXEC | READ */

        pos += 40;
    }

    /* Pad to file alignment for section data */
    while (pos < 0x0200 && pos < bufsz) {
        pos++;
    }

    /* Section data (each section gets 0x200 bytes of zeroed data) */
    for (uint16_t s = 0; s < num_sections; s++) {
        if (pos + 0x200 > bufsz) break;
        /* Fill with pattern */
        for (size_t j = 0; j < 0x200; j++) {
            buf[pos + j] = (uint8_t)((s * 0x11 + j) & 0xFF);
        }
        pos += 0x200;
    }

    return pos;
}

/* ----------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------- */

static void test_null_input(void)
{
    TEST_BEGIN("pe_open with NULL data");
    pe_ctx_t *ctx = pe_open(NULL, 0);
    TEST_ASSERT(ctx == NULL, "should return NULL for NULL data");
    TEST_PASS();
}

static void test_too_small(void)
{
    TEST_BEGIN("pe_open with too-small data");
    uint8_t tiny[32] = {0};
    pe_ctx_t *ctx = pe_open(tiny, sizeof(tiny));
    TEST_ASSERT(ctx == NULL, "should return NULL for 32-byte input");
    TEST_PASS();
}

static void test_invalid_magic(void)
{
    TEST_BEGIN("pe_open with invalid DOS magic");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 2, 0x60000000, 1);
    buf[0] = 0x00;  /* Corrupt magic */
    buf[1] = 0x00;
    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx == NULL, "should fail with invalid magic");
    TEST_PASS();
}

static void test_minimal_pe32plus(void)
{
    TEST_BEGIN("minimal PE32+ with 2 sections");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 2, 0x60000000, 1);
    TEST_ASSERT(sz > 0, "build should succeed");

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    const pe_dos_header_t *dos = pe_get_dos_header(ctx);
    TEST_ASSERT(dos != NULL, "DOS header should be present");
    TEST_ASSERT(dos->e_magic == 0x5A4D, "DOS magic should be MZ");
    TEST_ASSERT(dos->e_lfanew == 0x80, "e_lfanew should be 0x80");

    const pe_coff_header_t *coff = pe_get_coff_header(ctx);
    TEST_ASSERT(coff != NULL, "COFF header should be present");
    TEST_ASSERT(coff->machine == 0x8664, "machine should be AMD64");
    TEST_ASSERT(coff->num_sections == 2, "should have 2 sections");
    TEST_ASSERT(coff->timestamp == 0x60000000, "timestamp should match");

    const pe_optional_header_t *opt = pe_get_optional_header(ctx);
    TEST_ASSERT(opt != NULL, "optional header should be present");
    TEST_ASSERT(opt->is_pe32plus == 1, "should be PE32+");
    TEST_ASSERT(opt->image_base == 0x0000000140000000ULL, "image base");
    TEST_ASSERT(opt->section_alignment == 0x1000, "section alignment");
    TEST_ASSERT(opt->file_alignment == 0x0200, "file alignment");

    uint32_t sec_count = pe_get_section_count(ctx);
    TEST_ASSERT(sec_count == 2, "should have 2 sections");

    const pe_section_t *sec0 = pe_get_section(ctx, 0);
    TEST_ASSERT(sec0 != NULL, "section 0 should exist");
    TEST_ASSERT(sec0->virtual_address == 0x1000, "sec0 VA");
    TEST_ASSERT(sec0->raw_data_size == 0x0200, "sec0 raw size");

    const pe_section_t *sec1 = pe_get_section(ctx, 1);
    TEST_ASSERT(sec1 != NULL, "section 1 should exist");
    TEST_ASSERT(sec1->virtual_address == 0x2000, "sec1 VA");

    pe_close(ctx);
    TEST_PASS();
}

static void test_section_names(void)
{
    TEST_BEGIN("section name resolution");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 3, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    const char *name0 = pe_get_section_name(ctx, 0);
    TEST_ASSERT(name0 != NULL, "section 0 name should exist");
    TEST_ASSERT(strncmp(name0, ".sec0", 5) == 0, "section 0 name mismatch");

    const char *name1 = pe_get_section_name(ctx, 1);
    TEST_ASSERT(name1 != NULL, "section 1 name should exist");
    TEST_ASSERT(strncmp(name1, ".sec1", 5) == 0, "section 1 name mismatch");

    const pe_section_t *found = pe_find_section_by_name(ctx, ".sec0");
    TEST_ASSERT(found != NULL, "find by name should succeed");
    TEST_ASSERT(found->virtual_address == 0x1000, "found section VA");

    pe_close(ctx);
    TEST_PASS();
}

static void test_section_by_rva(void)
{
    TEST_BEGIN("find section by RVA");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 2, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    const pe_section_t *sec = pe_find_section_by_rva(ctx, 0x1500);
    TEST_ASSERT(sec != NULL, "should find section at RVA 0x1500");
    TEST_ASSERT(sec->virtual_address == 0x1000, "should be first section");

    sec = pe_find_section_by_rva(ctx, 0x2500);
    TEST_ASSERT(sec != NULL, "should find section at RVA 0x2500");
    TEST_ASSERT(sec->virtual_address == 0x2000, "should be second section");

    sec = pe_find_section_by_rva(ctx, 0x5000);
    TEST_ASSERT(sec == NULL, "should not find section at RVA 0x5000");

    pe_close(ctx);
    TEST_PASS();
}

static void test_rva_to_offset(void)
{
    TEST_BEGIN("RVA to file offset conversion");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 2, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    uint32_t off = pe_rva_to_offset(ctx, 0x1000);
    TEST_ASSERT(off == 0x0200, "RVA 0x1000 should map to offset 0x200");

    off = pe_rva_to_offset(ctx, 0x1010);
    TEST_ASSERT(off == 0x0210, "RVA 0x1010 should map to offset 0x210");

    off = pe_rva_to_offset(ctx, 0x2000);
    TEST_ASSERT(off == 0x0400, "RVA 0x2000 should map to offset 0x400");

    pe_close(ctx);
    TEST_PASS();
}

static void test_machine_names(void)
{
    TEST_BEGIN("machine type name lookup");
    TEST_ASSERT(strcmp(pe_get_machine_name(0x014C), "i386") == 0, "i386");
    TEST_ASSERT(strcmp(pe_get_machine_name(0x8664), "AMD64") == 0, "AMD64");
    TEST_ASSERT(strcmp(pe_get_machine_name(0xAA64), "ARM64") == 0, "ARM64");
    TEST_ASSERT(strcmp(pe_get_machine_name(0xFFFF), "Unrecognized") == 0, "other");
    TEST_PASS();
}

static void test_subsystem_names(void)
{
    TEST_BEGIN("subsystem name lookup");
    TEST_ASSERT(strcmp(pe_get_subsystem_name(2), "Windows GUI") == 0, "GUI");
    TEST_ASSERT(strcmp(pe_get_subsystem_name(3), "Windows Console") == 0, "CUI");
    TEST_ASSERT(strcmp(pe_get_subsystem_name(1), "Native") == 0, "Native");
    TEST_PASS();
}

static void test_error_strings(void)
{
    TEST_BEGIN("error string lookup");
    TEST_ASSERT(strcmp(pe_error_string(PE_OK), "success") == 0, "OK");
    TEST_ASSERT(strcmp(pe_error_string(PE_ERR_ALLOC),
                       "memory allocation failed") == 0, "ALLOC");
    TEST_ASSERT(strcmp(pe_error_string(PE_ERR_TRUNCATED),
                       "data truncated") == 0, "TRUNCATED");
    TEST_ASSERT(pe_error_string(99) != NULL, "unknown should not be NULL");
    TEST_PASS();
}

static void test_format_characteristics(void)
{
    TEST_BEGIN("characteristics formatting");
    char buf[512];
    int len;

    len = pe_format_characteristics(0x0002, buf, sizeof(buf));
    TEST_ASSERT(len > 0, "should produce output");
    TEST_ASSERT(strstr(buf, "EXECUTABLE") != NULL, "should contain EXECUTABLE");

    len = pe_format_characteristics(0x2002, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "DLL") != NULL, "should contain DLL");
    TEST_ASSERT(strstr(buf, "EXECUTABLE") != NULL, "should contain EXECUTABLE");

    len = pe_format_characteristics(0, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "none") != NULL, "zero flags should be (none)");

    TEST_PASS();
}

static void test_format_section_flags(void)
{
    TEST_BEGIN("section flags formatting");
    char buf[512];

    pe_format_section_flags(0x60000020, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "CODE") != NULL, "should contain CODE");
    TEST_ASSERT(strstr(buf, "EXECUTE") != NULL, "should contain EXECUTE");
    TEST_ASSERT(strstr(buf, "READ") != NULL, "should contain READ");

    pe_format_section_flags(0xC0000040, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "INITIALIZED_DATA") != NULL, "should have INIT_DATA");
    TEST_ASSERT(strstr(buf, "READ") != NULL, "should have READ");
    TEST_ASSERT(strstr(buf, "WRITE") != NULL, "should have WRITE");

    TEST_PASS();
}

static void test_format_timestamp(void)
{
    TEST_BEGIN("timestamp formatting");
    char buf[64];

    pe_format_timestamp(0, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "not set") != NULL, "zero should be (not set)");

    pe_format_timestamp(0x60000000, buf, sizeof(buf));
    TEST_ASSERT(strlen(buf) > 10, "should produce date string");
    TEST_ASSERT(strstr(buf, "2021") != NULL, "should be year 2021");

    TEST_PASS();
}

static void test_format_guid(void)
{
    TEST_BEGIN("GUID formatting");
    uint8_t guid[16] = {
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10
    };
    char buf[64];

    int len = pe_format_guid(guid, buf, sizeof(buf));
    TEST_ASSERT(len > 30, "GUID should be at least 30 chars");
    TEST_ASSERT(buf[0] == '{', "should start with {");
    TEST_ASSERT(buf[len - 1] == '}', "should end with }");

    TEST_PASS();
}

static void test_hex_dump(void)
{
    TEST_BEGIN("hex dump formatting");
    uint8_t data[] = {0x4D, 0x5A, 0x90, 0x00};
    char buf[64];

    int len = pe_format_hex_dump(data, 4, buf, sizeof(buf));
    TEST_ASSERT(len > 0, "should produce output");
    TEST_ASSERT(strstr(buf, "4D") != NULL, "should contain 4D");
    TEST_ASSERT(strstr(buf, "5A") != NULL, "should contain 5A");
    TEST_ASSERT(strstr(buf, "90") != NULL, "should contain 90");

    TEST_PASS();
}

static void test_data_dir_names(void)
{
    TEST_BEGIN("data directory name formatting");
    char buf[64];

    pe_format_data_dir_name(PE_DIR_EXPORT, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "Export") != NULL, "should be Export Table");

    pe_format_data_dir_name(PE_DIR_IMPORT, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "Import") != NULL, "should be Import Table");

    pe_format_data_dir_name(PE_DIR_DEBUG, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "Debug") != NULL, "should be Debug");

    pe_format_data_dir_name(PE_DIR_BASERELOC, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "Reloc") != NULL, "should be Relocation");

    TEST_PASS();
}

static void test_checksum_zero(void)
{
    TEST_BEGIN("checksum verification with zero checksum");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 1, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    int ok = pe_verify_checksum(ctx);
    TEST_ASSERT(ok == 1, "zero checksum should verify as OK");

    pe_close(ctx);
    TEST_PASS();
}

static void test_no_optional_header(void)
{
    TEST_BEGIN("PE without optional header");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 1, 0x60000000, 0);

    pe_ctx_t *ctx = pe_open(buf, sz);
    /* Should still parse the DOS + COFF headers */
    TEST_ASSERT(ctx != NULL, "pe_open should succeed without optional");

    const pe_optional_header_t *opt = pe_get_optional_header(ctx);
    TEST_ASSERT(opt->magic == 0, "optional magic should be zero");

    pe_close(ctx);
    TEST_PASS();
}

static void test_section_data_loaded(void)
{
    TEST_BEGIN("section data loading");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 2, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    const pe_section_t *sec = pe_get_section(ctx, 0);
    TEST_ASSERT(sec != NULL, "section 0 should exist");
    TEST_ASSERT(sec->data != NULL, "section 0 data should be loaded");
    TEST_ASSERT(sec->data_size > 0, "section 0 data size should be > 0");

    pe_close(ctx);
    TEST_PASS();
}

static void test_error_api(void)
{
    TEST_BEGIN("error API");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 1, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    pe_error_t err = pe_get_error(ctx);
    /* Error state depends on validation results */
    const char *msg = pe_get_error_message(ctx);
    TEST_ASSERT(msg != NULL, "error message should not be NULL");
    (void)err;

    pe_close(ctx);
    TEST_PASS();
}

static void test_i386_machine(void)
{
    TEST_BEGIN("PE with i386 machine type");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x014C, 1, 0x50000000, 1);
    /* Fix the magic to PE32 */
    /* Find optional header offset and change magic to PE32 */
    uint32_t opt_off = 0x98;
    write_u16(buf, opt_off, 0x010B);  /* PE32 */

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    const pe_coff_header_t *coff = pe_get_coff_header(ctx);
    TEST_ASSERT(coff->machine == 0x014C, "machine should be i386");
    TEST_ASSERT(strcmp(pe_get_machine_name(coff->machine), "i386") == 0, "name");

    pe_close(ctx);
    TEST_PASS();
}

static void test_resource_type_names(void)
{
    TEST_BEGIN("resource type name lookup");
    TEST_ASSERT(strcmp(pe_get_resource_type_name(PE_RT_ICON), "ICON") == 0, "ICON");
    TEST_ASSERT(strcmp(pe_get_resource_type_name(PE_RT_MANIFEST), "MANIFEST") == 0,
                "MANIFEST");
    TEST_ASSERT(strcmp(pe_get_resource_type_name(PE_RT_VERSION), "VERSION") == 0,
                "VERSION");
    TEST_ASSERT(strcmp(pe_get_resource_type_name(999), "UNKNOWN") == 0, "unknown");
    TEST_PASS();
}

static void test_debug_type_names(void)
{
    TEST_BEGIN("debug type name lookup");
    TEST_ASSERT(strcmp(pe_get_debug_type_name(PE_DEBUG_TYPE_CODEVIEW),
                       "CODEVIEW") == 0, "CODEVIEW");
    TEST_ASSERT(strcmp(pe_get_debug_type_name(PE_DEBUG_TYPE_FPO),
                       "FPO") == 0, "FPO");
    TEST_ASSERT(strcmp(pe_get_debug_type_name(99), "OTHER") == 0, "OTHER");
    TEST_PASS();
}

static void test_symbol_class_names(void)
{
    TEST_BEGIN("symbol class name lookup");
    TEST_ASSERT(strcmp(pe_get_symbol_class_name(PE_SYM_CLASS_EXTERNAL),
                       "EXTERNAL") == 0, "EXTERNAL");
    TEST_ASSERT(strcmp(pe_get_symbol_class_name(PE_SYM_CLASS_STATIC),
                       "STATIC") == 0, "STATIC");
    TEST_ASSERT(strcmp(pe_get_symbol_class_name(PE_SYM_CLASS_FILE),
                       "FILE") == 0, "FILE");
    TEST_ASSERT(strcmp(pe_get_symbol_class_name(99), "OTHER") == 0, "OTHER");
    TEST_PASS();
}

static void test_dll_characteristics_format(void)
{
    TEST_BEGIN("DLL characteristics formatting");
    char buf[512];

    pe_format_dll_characteristics(0x8160, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "HIGH_ENTROPY_VA") != NULL, "HIGH_ENTROPY_VA");
    TEST_ASSERT(strstr(buf, "DYNAMIC_BASE") != NULL, "DYNAMIC_BASE");
    TEST_ASSERT(strstr(buf, "NX_COMPAT") != NULL, "NX_COMPAT");
    TEST_ASSERT(strstr(buf, "TERMINAL_SERVER") != NULL, "TERMINAL_SERVER");

    pe_format_dll_characteristics(0, buf, sizeof(buf));
    TEST_ASSERT(strstr(buf, "none") != NULL, "zero should be (none)");

    TEST_PASS();
}

static void test_query_null_context(void)
{
    TEST_BEGIN("query API with NULL context");
    TEST_ASSERT(pe_get_dos_header(NULL) == NULL, "dos header");
    TEST_ASSERT(pe_get_coff_header(NULL) == NULL, "coff header");
    TEST_ASSERT(pe_get_optional_header(NULL) == NULL, "optional header");
    TEST_ASSERT(pe_get_section_count(NULL) == 0, "section count");
    TEST_ASSERT(pe_get_section(NULL, 0) == NULL, "section");
    TEST_ASSERT(pe_get_section_name(NULL, 0) == NULL, "section name");
    TEST_ASSERT(pe_get_symbol_count(NULL) == 0, "symbol count");
    TEST_ASSERT(pe_get_import_descriptor_count(NULL) == 0, "import count");
    TEST_ASSERT(pe_get_export_count(NULL) == 0, "export count");
    TEST_ASSERT(pe_get_reloc_block_count(NULL) == 0, "reloc count");
    TEST_ASSERT(pe_get_debug_entry_count(NULL) == 0, "debug count");
    TEST_ASSERT(pe_get_resource_count(NULL) == 0, "resource count");
    TEST_ASSERT(pe_get_issue_count(NULL) == 0, "issue count");
    TEST_ASSERT(pe_get_error(NULL) == PE_ERR_NULLARG, "error code");
    TEST_ASSERT(pe_find_section_by_name(NULL, ".text") == NULL, "find by name");
    TEST_ASSERT(pe_find_section_by_rva(NULL, 0x1000) == NULL, "find by rva");
    TEST_ASSERT(pe_find_export_by_name(NULL, "test") == NULL, "find export");
    TEST_PASS();
}

static void test_pe_close_null(void)
{
    TEST_BEGIN("pe_close with NULL");
    pe_close(NULL);  /* Should not crash */
    TEST_PASS();
}

static void test_out_of_range_indices(void)
{
    TEST_BEGIN("out-of-range index queries");
    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 1, 0x60000000, 1);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "pe_open should succeed");

    TEST_ASSERT(pe_get_section(ctx, 999) == NULL, "bad section index");
    TEST_ASSERT(pe_get_section_name(ctx, 999) == NULL, "bad section name index");
    TEST_ASSERT(pe_get_symbol(ctx, 999) == NULL, "bad symbol index");
    TEST_ASSERT(pe_get_import_descriptor(ctx, 999) == NULL, "bad import index");
    TEST_ASSERT(pe_get_export(ctx, 999) == NULL, "bad export index");
    TEST_ASSERT(pe_get_debug_entry(ctx, 999) == NULL, "bad debug index");
    TEST_ASSERT(pe_get_resource_entry(ctx, 999) == NULL, "bad resource index");
    TEST_ASSERT(pe_get_issue(ctx, 999) == NULL, "bad issue index");

    pe_close(ctx);
    TEST_PASS();
}


static char *test_strdup(const char *text)
{
    size_t len = strlen(text);
    char *copy = (char *)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, text, len + 1);
    return copy;
}

static void test_validation_cache_lifetime(void)
{
    TEST_BEGIN("validation refreshes cached references");

    uint8_t *file_data = (uint8_t *)calloc(1, 2048);
    pe_ctx_t *ctx = pe_ctx_alloc();
    TEST_ASSERT(file_data != NULL && ctx != NULL, "allocate test context");

    ctx->data = file_data;
    ctx->size = 2048;
    ctx->coff.timestamp = 1;
    ctx->coff.num_symbols = 100;
    ctx->optional.file_alignment = 0x200;
    ctx->optional.data_dirs[PE_DIR_EXPORT].rva = 0x1000;
    ctx->optional.data_dirs[PE_DIR_EXPORT].size = 0x100;
    ctx->optional.data_dirs[PE_DIR_RESOURCE].rva = 0x1000;
    ctx->optional.data_dirs[PE_DIR_RESOURCE].size = 0x100;

    ctx->sections.entries = (pe_section_t *)calloc(1, sizeof(pe_section_t));
    ctx->sections.count = ctx->sections.capacity = 1;
    pe_section_t *sec = &ctx->sections.entries[0];
    memcpy(sec->short_name, ".text", 6);
    sec->resolved_name = sec->short_name;
    sec->virtual_address = 0x1000;
    sec->virtual_size = 0x100;
    sec->raw_data_offset = 0x201;
    sec->raw_data_size = 0x100;
    sec->data = (uint8_t *)calloc(1, 0x100);
    sec->data_size = 0x100;
    sec->data_owned = 1;
    memcpy(sec->data, "ImportedName", 13);

    ctx->imports.descriptors = (pe_import_descriptor_t *)calloc(
        1, sizeof(pe_import_descriptor_t));
    ctx->imports.count = ctx->imports.capacity = 1;
    ctx->imports.descriptors[0].dll_name = test_strdup("sample.dll");
    ctx->imports.descriptors[0].thunks = (pe_import_thunk_t *)calloc(
        1, sizeof(pe_import_thunk_t));
    ctx->imports.descriptors[0].num_thunks =
        ctx->imports.descriptors[0].thunks_capacity = 1;
    ctx->imports.descriptors[0].thunks[0].name = (char *)sec->data;

    ctx->exports.entries = (pe_export_entry_t *)calloc(
        1, sizeof(pe_export_entry_t));
    ctx->exports.num_functions = ctx->exports.entries_capacity = 1;
    ctx->exports.entries[0].name = (char *)sec->data;
    ctx->exports.entries[0].forwarder = test_strdup("invalid-forwarder");
    ctx->exports.entries[0].is_forwarder = 1;

    ctx->relocs.blocks = (pe_reloc_block_t *)calloc(
        1, sizeof(pe_reloc_block_t));
    ctx->relocs.count = ctx->relocs.capacity = 1;
    ctx->relocs.blocks[0].entries = (pe_reloc_entry_t *)calloc(
        1, sizeof(pe_reloc_entry_t));
    ctx->relocs.blocks[0].count = ctx->relocs.blocks[0].capacity = 1;
    ctx->relocs.blocks[0].entries[0].type = PE_REL_BASED_HIGHLOW;
    ctx->relocs.blocks[0].entries[0].target_rva = 0x1000;
    ctx->relocs.blocks[0].entries[0].target_ptr = sec->data;
    ctx->relocs.blocks[0].entries[0].resolved = 1;

    ctx->debug.entries = (pe_debug_entry_t *)calloc(
        1, sizeof(pe_debug_entry_t));
    ctx->debug.count = ctx->debug.capacity = 1;
    ctx->debug.entries[0].timestamp = 1000000;
    ctx->debug.entries[0].type = PE_DEBUG_TYPE_CODEVIEW;
    ctx->debug.entries[0].codeview = (pe_codeview_info_t *)calloc(
        1, sizeof(pe_codeview_info_t));
    ctx->debug.entries[0].codeview->pdb_path = test_strdup("sample.pdb");

    ctx->strings.data = (uint8_t *)calloc(1, 32);
    ctx->strings.size = 32;
    memcpy(ctx->strings.data + 4, "LongSymbol", 11);
    ctx->symbols.entries = (pe_symbol_t *)calloc(1, sizeof(pe_symbol_t));
    ctx->symbols.count = ctx->symbols.capacity = 1;
    ctx->symbols.entries[0].index = 0;
    ctx->symbols.entries[0].section_number = 1;
    ctx->symbols.entries[0].resolved_name = (char *)ctx->strings.data + 4;

    ctx->resources.root = (pe_resource_node_t *)calloc(
        1, sizeof(pe_resource_node_t));
    ctx->resources.root->name = test_strdup("ResourceName");
    ctx->resources.root->data_rva = 0x5000;
    ctx->resources.root->data_size = 4;
    ctx->resources.flat_entries = (pe_resource_node_t **)calloc(
        1, sizeof(pe_resource_node_t *));
    ctx->resources.flat_entries[0] = ctx->resources.root;
    ctx->resources.flat_count = ctx->resources.flat_capacity = 1;

    TEST_ASSERT(pe_build_cache(ctx) == PE_OK, "build initial cache");
    TEST_ASSERT(pe_validate(ctx) == PE_OK, "validate context");
    TEST_ASSERT(pe_resolve(ctx) == PE_OK, "resolve validated context");
    TEST_ASSERT(ctx->resolve_state.resolved_import_count == 1,
                "import name remains valid");
    TEST_ASSERT(ctx->resolve_state.resolved_symbol_count == 1,
                "symbol name remains valid");
    TEST_ASSERT(ctx->cache.export_entries[0].forwarder_ptr == NULL,
                "removed forwarder is not retained");
    TEST_ASSERT(ctx->cache.debug_entries[0].pdb_path_ptr == NULL,
                "discarded debug path is not retained");
    TEST_ASSERT(ctx->cache.resource_entries[0].name_ptr == NULL,
                "pruned resource name is not retained");

    pe_ctx_free(ctx);
    free(file_data);
    TEST_PASS();
}

static void test_exception_unwind_offset_overflow(void)
{
    TEST_BEGIN("exception unwind offset overflow is rejected");

    uint8_t buf[PE_BUF_SIZE];
    size_t sz = build_minimal_pe(buf, sizeof(buf), 0x8664, 2,
                                 0x60000000, 1);
    const size_t opt = 0x98;
    const size_t section_table = opt + 240;

    /* Exception directory: one RUNTIME_FUNCTION in section 0. */
    write_u32(buf, opt + 112 + PE_DIR_EXCEPTION * 8, 0x1000);
    write_u32(buf, opt + 112 + PE_DIR_EXCEPTION * 8 + 4, 12);
    write_u32(buf, 0x200, 0x1000);
    write_u32(buf, 0x204, 0x1010);
    write_u32(buf, 0x208, 0x200F);

    /* Make section 1 map the unwind RVA to UINT32_MAX as a file offset. */
    write_u32(buf, section_table + 40 + 20, 0xFFFFFFF0u);

    pe_ctx_t *ctx = pe_open(buf, sz);
    TEST_ASSERT(ctx != NULL, "malformed unwind offset must not crash parser");
    TEST_ASSERT(pe_get_exception_count(ctx) == 1,
                "runtime function record remains queryable");
    pe_close(ctx);
    TEST_PASS();
}

/* ----------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------- */

int main(void)
{
    printf("libpectra test suite\n");
    printf("====================\n\n");

    test_null_input();
    test_too_small();
    test_invalid_magic();
    test_minimal_pe32plus();
    test_section_names();
    test_section_by_rva();
    test_rva_to_offset();
    test_machine_names();
    test_subsystem_names();
    test_error_strings();
    test_format_characteristics();
    test_format_section_flags();
    test_format_timestamp();
    test_format_guid();
    test_hex_dump();
    test_data_dir_names();
    test_checksum_zero();
    test_no_optional_header();
    test_section_data_loaded();
    test_error_api();
    test_i386_machine();
    test_resource_type_names();
    test_debug_type_names();
    test_symbol_class_names();
    test_dll_characteristics_format();
    test_query_null_context();
    test_pe_close_null();
    test_out_of_range_indices();
    test_validation_cache_lifetime();
    test_exception_unwind_offset_overflow();

    printf("\n====================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
