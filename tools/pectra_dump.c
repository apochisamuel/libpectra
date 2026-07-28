/*
 * pectra_dump.c — PE File Analysis Tool
 *
 * Command-line utility for inspecting PE/COFF binary files.
 * Reads a PE file and prints detailed information about its
 * structure including headers, sections, imports, exports,
 * relocations, debug info, resources, and symbols.
 *
 * Usage: pectra_dump [options] <file.exe|file.dll>
 *
 * Options:
 *   -a, --all        Show all information
 *   -h, --headers    Show headers (DOS, COFF, Optional)
 *   -s, --sections   Show section table
 *   -i, --imports    Show import table
 *   -e, --exports    Show export table
 *   -r, --relocs     Show relocation table
 *   -d, --debug      Show debug directory
 *   -R, --resources  Show resource tree
 *   -S, --symbols    Show symbol table
 *   -v, --validate   Show validation issues
 *   -c, --checksum   Verify PE checksum
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pectra.h"

#define DUMP_HEADERS    0x0001
#define DUMP_SECTIONS   0x0002
#define DUMP_IMPORTS    0x0004
#define DUMP_EXPORTS    0x0008
#define DUMP_RELOCS     0x0010
#define DUMP_DEBUG      0x0020
#define DUMP_RESOURCES  0x0040
#define DUMP_SYMBOLS    0x0080
#define DUMP_VALIDATE   0x0100
#define DUMP_CHECKSUM   0x0200
#define DUMP_ALL        0xFFFF

/* Print a separator line */
static void print_separator(const char *title)
{
    printf("\n=== %s ", title);
    size_t len = strlen(title);
    for (size_t i = len + 5; i < 70; i++) {
        putchar('=');
    }
    putchar('\n');
}

/* Print DOS header information */
static void dump_dos_header(const pe_ctx_t *ctx)
{
    print_separator("DOS Header");

    const pe_dos_header_t *dos = pe_get_dos_header(ctx);
    if (!dos) {
        printf("  (not available)\n");
        return;
    }

    printf("  Magic:                 0x%04X (%c%c)\n",
           dos->e_magic,
           dos->e_magic & 0xFF,
           (dos->e_magic >> 8) & 0xFF);
    printf("  Bytes on last page:    %u\n", dos->e_cblp);
    printf("  Pages in file:         %u\n", dos->e_cp);
    printf("  Relocations:           %u\n", dos->e_crlc);
    printf("  Header paragraphs:     %u\n", dos->e_cparhdr);
    printf("  Min extra paragraphs:  %u\n", dos->e_minalloc);
    printf("  Max extra paragraphs:  %u\n", dos->e_maxalloc);
    printf("  Initial SS:            0x%04X\n", dos->e_ss);
    printf("  Initial SP:            0x%04X\n", dos->e_sp);
    printf("  Checksum:              0x%04X\n", dos->e_csum);
    printf("  Initial IP:            0x%04X\n", dos->e_ip);
    printf("  Initial CS:            0x%04X\n", dos->e_cs);
    printf("  Reloc table offset:    0x%04X\n", dos->e_lfarlc);
    printf("  Overlay number:        %u\n", dos->e_ovno);
    printf("  OEM ID:                0x%04X\n", dos->e_oemid);
    printf("  OEM info:              0x%04X\n", dos->e_oeminfo);
    printf("  PE header offset:      0x%08X\n", dos->e_lfanew);
}

/* Print COFF header information */
static void dump_coff_header(const pe_ctx_t *ctx)
{
    print_separator("COFF File Header");

    const pe_coff_header_t *coff = pe_get_coff_header(ctx);
    if (!coff) {
        printf("  (not available)\n");
        return;
    }

    char machine_buf[64];
    pe_format_machine(coff->machine, machine_buf, sizeof(machine_buf));

    char ts_buf[64];
    pe_format_timestamp(coff->timestamp, ts_buf, sizeof(ts_buf));

    char chars_buf[512];
    pe_format_characteristics(coff->characteristics,
                               chars_buf, sizeof(chars_buf));

    printf("  Machine:               %s\n", machine_buf);
    printf("  Number of sections:    %u\n", coff->num_sections);
    printf("  Timestamp:             %s (0x%08X)\n", ts_buf, coff->timestamp);
    printf("  Symbol table offset:   0x%08X\n", coff->symbol_table_offset);
    printf("  Number of symbols:     %u\n", coff->num_symbols);
    printf("  Optional header size:  %u\n", coff->optional_header_size);
    printf("  Characteristics:       %s\n", chars_buf);
}

/* Print optional header information */
static void dump_optional_header(const pe_ctx_t *ctx)
{
    print_separator("Optional Header");

    const pe_optional_header_t *opt = pe_get_optional_header(ctx);
    if (!opt) {
        printf("  (not available)\n");
        return;
    }

    printf("  Magic:                 0x%04X (%s)\n",
           opt->magic,
           opt->is_pe32plus ? "PE32+" : "PE32");
    printf("  Linker version:        %u.%u\n",
           opt->major_linker, opt->minor_linker);
    printf("  Size of code:          0x%08X\n", opt->size_of_code);
    printf("  Size of init data:     0x%08X\n", opt->size_of_init_data);
    printf("  Size of uninit data:   0x%08X\n", opt->size_of_uninit_data);
    printf("  Entry point:           0x%08X\n", opt->entry_point_rva);
    printf("  Base of code:          0x%08X\n", opt->base_of_code);

    if (!opt->is_pe32plus) {
        printf("  Base of data:          0x%08X\n", opt->base_of_data);
    }

    printf("  Image base:            0x%016llX\n",
           (unsigned long long)opt->image_base);
    printf("  Section alignment:     0x%08X\n", opt->section_alignment);
    printf("  File alignment:        0x%08X\n", opt->file_alignment);
    printf("  OS version:            %u.%u\n",
           opt->major_os_version, opt->minor_os_version);
    printf("  Image version:         %u.%u\n",
           opt->major_image_version, opt->minor_image_version);
    printf("  Subsystem version:     %u.%u\n",
           opt->major_subsystem_version, opt->minor_subsystem_version);
    printf("  Size of image:         0x%08X\n", opt->size_of_image);
    printf("  Size of headers:       0x%08X\n", opt->size_of_headers);
    printf("  Checksum:              0x%08X\n", opt->checksum);
    printf("  Subsystem:             %s (%u)\n",
           pe_get_subsystem_name(opt->subsystem), opt->subsystem);

    char dll_chars[512];
    pe_format_dll_characteristics(opt->dll_characteristics,
                                   dll_chars, sizeof(dll_chars));
    printf("  DLL characteristics:   %s\n", dll_chars);
    printf("  Stack reserve:         0x%016llX\n",
           (unsigned long long)opt->stack_reserve);
    printf("  Stack commit:          0x%016llX\n",
           (unsigned long long)opt->stack_commit);
    printf("  Heap reserve:          0x%016llX\n",
           (unsigned long long)opt->heap_reserve);
    printf("  Heap commit:           0x%016llX\n",
           (unsigned long long)opt->heap_commit);
    printf("  Number of data dirs:   %u\n", opt->num_data_dirs);

    /* Data directories */
    printf("\n  Data Directories:\n");
    for (uint32_t i = 0; i < PE_NUM_DATA_DIRS; i++) {
        if (opt->data_dirs[i].rva == 0 && opt->data_dirs[i].size == 0) {
            continue;
        }
        char dir_name[64];
        pe_format_data_dir_name(i, dir_name, sizeof(dir_name));
        printf("    [%2u] %-24s RVA: 0x%08X  Size: 0x%08X\n",
               i, dir_name, opt->data_dirs[i].rva, opt->data_dirs[i].size);
    }
}

/* Print section table */
static void dump_sections(const pe_ctx_t *ctx)
{
    print_separator("Section Table");

    uint32_t count = pe_get_section_count(ctx);
    if (count == 0) {
        printf("  (no sections)\n");
        return;
    }

    printf("  %-8s %-12s %-12s %-12s %-12s %-12s %s\n",
           "Idx", "Name", "VirtSize", "VirtAddr",
           "RawSize", "RawOffset", "Flags");

    for (uint32_t i = 0; i < count; i++) {
        const pe_section_t *sec = pe_get_section(ctx, i);
        if (!sec) {
            continue;
        }

        const char *name = pe_get_section_name(ctx, i);
        if (!name) {
            name = "(null)";
        }

        char flags_buf[512];
        pe_format_section_flags(sec->characteristics,
                                flags_buf, sizeof(flags_buf));

        printf("  [%2u]   %-12s 0x%08X   0x%08X   0x%08X   0x%08X   %s\n",
               i, name,
               sec->virtual_size, sec->virtual_address,
               sec->raw_data_size, sec->raw_data_offset,
               flags_buf);
    }
}

/* Print import table */
static void dump_imports(const pe_ctx_t *ctx)
{
    print_separator("Import Table");

    uint32_t desc_count = pe_get_import_descriptor_count(ctx);
    if (desc_count == 0) {
        printf("  (no imports)\n");
        return;
    }

    for (uint32_t d = 0; d < desc_count; d++) {
        const char *dll = pe_get_import_dll_name(ctx, d);
        const pe_import_descriptor_t *desc = pe_get_import_descriptor(ctx, d);
        if (!desc) {
            continue;
        }

        printf("\n  DLL: %s\n", dll ? dll : "(unknown)");
        printf("    ILT RVA: 0x%08X  IAT RVA: 0x%08X  Timestamp: 0x%08X\n",
               desc->ilt_rva, desc->iat_rva, desc->timestamp);

        uint32_t thunk_count = pe_get_import_thunk_count(ctx, d);
        for (uint32_t t = 0; t < thunk_count; t++) {
            const pe_import_thunk_t *thunk = pe_get_import_thunk(ctx, d, t);
            if (!thunk) {
                continue;
            }

            if (thunk->is_ordinal) {
                printf("      [%3u] Ordinal: %u\n", t, thunk->ordinal);
            } else {
                printf("      [%3u] Hint: %3u  Name: %s\n",
                       t, thunk->hint,
                       thunk->name ? thunk->name : "(unresolved)");
            }
        }
    }
}

/* Print export table */
static void dump_exports(const pe_ctx_t *ctx)
{
    print_separator("Export Table");

    uint32_t exp_count = pe_get_export_count(ctx);
    if (exp_count == 0) {
        printf("  (no exports)\n");
        return;
    }

    const char *dll_name = pe_get_export_dll_name(ctx);
    printf("  DLL Name: %s\n", dll_name ? dll_name : "(unknown)");

    printf("\n  %-8s %-8s %-12s %-30s %s\n",
           "Idx", "Ordinal", "RVA", "Name", "Forwarder");

    for (uint32_t i = 0; i < exp_count; i++) {
        const pe_export_entry_t *exp = pe_get_export(ctx, i);
        if (!exp) {
            continue;
        }

        printf("  [%4u]  %5u    0x%08X   %-30s %s\n",
               i, exp->ordinal, exp->function_rva,
               exp->has_name && exp->name ? exp->name : "(by ordinal)",
               exp->is_forwarder && exp->forwarder ? exp->forwarder : "");
    }
}

/* Print relocation table */
static void dump_relocs(const pe_ctx_t *ctx)
{
    print_separator("Base Relocations");

    uint32_t block_count = pe_get_reloc_block_count(ctx);
    if (block_count == 0) {
        printf("  (no relocations)\n");
        return;
    }

    printf("  %u relocation blocks\n", block_count);

    for (uint32_t i = 0; i < block_count; i++) {
        const pe_reloc_block_t *block = pe_get_reloc_block(ctx, i);
        if (!block) {
            continue;
        }

        printf("\n  Block %u: Page RVA 0x%08X, %u entries\n",
               i, block->page_rva, block->count);

        for (uint32_t j = 0; j < block->count && j < 20; j++) {
            const pe_reloc_entry_t *entry = &block->entries[j];
            printf("    [%3u] Type: %u  Offset: 0x%03X  Target RVA: 0x%08X\n",
                   j, entry->type, entry->offset, entry->target_rva);
        }

        if (block->count > 20) {
            printf("    ... (%u more entries)\n", block->count - 20);
        }
    }
}

/* Print debug directory */
static void dump_debug(const pe_ctx_t *ctx)
{
    print_separator("Debug Directory");

    uint32_t dbg_count = pe_get_debug_entry_count(ctx);
    if (dbg_count == 0) {
        printf("  (no debug entries)\n");
        return;
    }

    for (uint32_t i = 0; i < dbg_count; i++) {
        const pe_debug_entry_t *dbg = pe_get_debug_entry(ctx, i);
        if (!dbg) {
            continue;
        }

        char ts_buf[64];
        pe_format_timestamp(dbg->timestamp, ts_buf, sizeof(ts_buf));

        printf("\n  Entry %u:\n", i);
        printf("    Type:           %s (%u)\n",
               pe_get_debug_type_name(dbg->type), dbg->type);
        printf("    Timestamp:      %s\n", ts_buf);
        printf("    Version:        %u.%u\n",
               dbg->major_version, dbg->minor_version);
        printf("    Data size:      %u\n", dbg->data_size);
        printf("    Address RVA:    0x%08X\n", dbg->address_rva);
        printf("    Raw data ptr:   0x%08X\n", dbg->raw_data_offset);

        const char *pdb = pe_get_pdb_path(ctx, i);
        if (pdb) {
            printf("    PDB path:       %s\n", pdb);
        }

        if (dbg->codeview) {
            char guid_buf[64];
            pe_format_guid(dbg->codeview->guid, guid_buf, sizeof(guid_buf));
            printf("    CV Signature:   0x%08X\n", dbg->codeview->cv_signature);
            printf("    GUID:           %s\n", guid_buf);
            printf("    Age:            %u\n", dbg->codeview->age);
        }
    }
}

/* Print resource tree (recursive) */
static void dump_resource_node(const pe_resource_node_t *node, int indent)
{
    if (!node) {
        return;
    }

    for (int i = 0; i < indent; i++) {
        printf("  ");
    }

    if (node->is_named && node->name) {
        printf("Name: \"%s\"", node->name);
    } else {
        const char *type_name = pe_get_resource_type_name(node->id);
        printf("ID: %u (%s)", node->id, type_name);
    }

    if (node->is_directory) {
        printf(" [directory, %u children]\n", node->num_children);
        for (uint32_t i = 0; i < node->num_children; i++) {
            dump_resource_node(&node->children[i], indent + 1);
        }
    } else {
        printf(" [data: RVA 0x%08X, size %u, codepage %u]\n",
               node->data_rva, node->data_size, node->codepage);
    }
}

static void dump_resources(const pe_ctx_t *ctx)
{
    print_separator("Resource Directory");

    const pe_resource_node_t *root = pe_get_resource_root(ctx);
    if (!root) {
        printf("  (no resources)\n");
        return;
    }

    uint32_t flat_count = pe_get_resource_count(ctx);
    printf("  %u leaf resource entries\n\n", flat_count);

    dump_resource_node(root, 1);
}

/* Print symbol table */
static void dump_symbols(const pe_ctx_t *ctx)
{
    print_separator("Symbol Table");

    uint32_t count = pe_get_symbol_count(ctx);
    if (count == 0) {
        printf("  (no symbols)\n");
        return;
    }

    printf("  %-8s %-30s %-12s %-8s %-16s %s\n",
           "Idx", "Name", "Value", "Section", "Class", "Type");

    for (uint32_t i = 0; i < count; i++) {
        const pe_symbol_t *sym = pe_get_symbol(ctx, i);
        if (!sym) {
            continue;
        }

        const char *name = pe_get_symbol_name(ctx, i);
        const char *cls = pe_get_symbol_class_name(sym->storage_class);

        printf("  [%4u]  %-30s 0x%08X   %5d    %-16s 0x%04X\n",
               i, name ? name : "(null)",
               sym->value, sym->section_number,
               cls, sym->type);
    }
}

/* Print validation issues */
static void dump_validation(const pe_ctx_t *ctx)
{
    print_separator("Validation Issues");

    uint32_t count = pe_get_issue_count(ctx);
    if (count == 0) {
        printf("  No issues found.\n");
        return;
    }

    printf("  %u issues detected:\n\n", count);

    for (uint32_t i = 0; i < count; i++) {
        const pe_validation_issue_t *issue = pe_get_issue(ctx, i);
        if (!issue) {
            continue;
        }

        const char *sev_str;
        switch (issue->severity) {
        case 0:  sev_str = "INFO"; break;
        case 1:  sev_str = "WARN"; break;
        case 2:  sev_str = "ERROR"; break;
        default: sev_str = "CRIT"; break;
        }

        printf("  [%s] Section %u: %s\n",
               sev_str, issue->section_index, issue->message);
    }
}

/* Verify PE checksum */
static void dump_checksum(const pe_ctx_t *ctx)
{
    print_separator("Checksum Verification");

    const pe_optional_header_t *opt = pe_get_optional_header(ctx);
    if (!opt) {
        printf("  Optional header not available.\n");
        return;
    }

    printf("  Stored checksum:   0x%08X\n", opt->checksum);

    if (opt->checksum == 0) {
        printf("  (checksum not set by linker)\n");
        return;
    }

    int valid = pe_verify_checksum(ctx);
    printf("  Verification:      %s\n",
           valid ? "PASS" : "FAIL (mismatch)");
}

/* Print usage information */
static void print_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options] <pe-file>\n\n", progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --all        Show all information\n");
    fprintf(stderr, "  -h, --headers    Show headers\n");
    fprintf(stderr, "  -s, --sections   Show section table\n");
    fprintf(stderr, "  -i, --imports    Show import table\n");
    fprintf(stderr, "  -e, --exports    Show export table\n");
    fprintf(stderr, "  -r, --relocs     Show relocations\n");
    fprintf(stderr, "  -d, --debug      Show debug info\n");
    fprintf(stderr, "  -R, --resources  Show resource tree\n");
    fprintf(stderr, "  -S, --symbols    Show symbol table\n");
    fprintf(stderr, "  -v, --validate   Show validation issues\n");
    fprintf(stderr, "  -c, --checksum   Verify checksum\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    uint32_t flags = 0;
    const char *filename = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            flags = DUMP_ALL;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--headers") == 0) {
            flags |= DUMP_HEADERS;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--sections") == 0) {
            flags |= DUMP_SECTIONS;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--imports") == 0) {
            flags |= DUMP_IMPORTS;
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--exports") == 0) {
            flags |= DUMP_EXPORTS;
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--relocs") == 0) {
            flags |= DUMP_RELOCS;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            flags |= DUMP_DEBUG;
        } else if (strcmp(argv[i], "-R") == 0 || strcmp(argv[i], "--resources") == 0) {
            flags |= DUMP_RESOURCES;
        } else if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--symbols") == 0) {
            flags |= DUMP_SYMBOLS;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--validate") == 0) {
            flags |= DUMP_VALIDATE;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--checksum") == 0) {
            flags |= DUMP_CHECKSUM;
        } else if (argv[i][0] != '-') {
            filename = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!filename) {
        fprintf(stderr, "Error: no input file specified\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Default to showing all */
    if (flags == 0) {
        flags = DUMP_ALL;
    }

    /* Read file */
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", filename);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 256 * 1024 * 1024) {
        fprintf(stderr, "Error: invalid file size (%ld bytes)\n", file_size);
        fclose(f);
        return 1;
    }

    uint8_t *data = (uint8_t *)malloc((size_t)file_size);
    if (!data) {
        fprintf(stderr, "Error: memory allocation failed\n");
        fclose(f);
        return 1;
    }

    size_t read = fread(data, 1, (size_t)file_size, f);
    fclose(f);

    if (read != (size_t)file_size) {
        fprintf(stderr, "Error: short read (%zu of %ld bytes)\n",
                read, file_size);
        free(data);
        return 1;
    }

    /* Parse */
    printf("File: %s (%ld bytes)\n", filename, file_size);

    pe_ctx_t *ctx = pe_open(data, (size_t)file_size);
    if (!ctx) {
        fprintf(stderr, "Error: failed to parse PE file\n");
        free(data);
        return 1;
    }

    /* Dump requested sections */
    if (flags & DUMP_HEADERS) {
        dump_dos_header(ctx);
        dump_coff_header(ctx);
        dump_optional_header(ctx);
    }
    if (flags & DUMP_SECTIONS)  dump_sections(ctx);
    if (flags & DUMP_IMPORTS)   dump_imports(ctx);
    if (flags & DUMP_EXPORTS)   dump_exports(ctx);
    if (flags & DUMP_RELOCS)    dump_relocs(ctx);
    if (flags & DUMP_DEBUG)     dump_debug(ctx);
    if (flags & DUMP_RESOURCES) dump_resources(ctx);
    if (flags & DUMP_SYMBOLS)   dump_symbols(ctx);
    if (flags & DUMP_VALIDATE)  dump_validation(ctx);
    if (flags & DUMP_CHECKSUM)  dump_checksum(ctx);

    /* Summary */
    printf("\n");
    print_separator("Summary");
    printf("  Sections:   %u\n", pe_get_section_count(ctx));
    printf("  Symbols:    %u\n", pe_get_symbol_count(ctx));
    printf("  Imports:    %u DLLs\n", pe_get_import_descriptor_count(ctx));
    printf("  Exports:    %u functions\n", pe_get_export_count(ctx));
    printf("  Reloc blks: %u\n", pe_get_reloc_block_count(ctx));
    printf("  Debug:      %u entries\n", pe_get_debug_entry_count(ctx));
    printf("  Resources:  %u entries\n", pe_get_resource_count(ctx));
    printf("  Issues:     %u\n", pe_get_issue_count(ctx));

    pe_close(ctx);
    free(data);

    return 0;
}
