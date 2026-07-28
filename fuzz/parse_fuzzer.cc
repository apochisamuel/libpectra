/*
 * parse_fuzzer.cc — Full PE parsing pipeline fuzzer
 *
 * Exercises the complete libpectra parsing pipeline from DOS header
 * through cross-reference resolution. This is the primary harness
 * for discovering memory safety issues across all parsing phases.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "pectra.h"
}

/*
 * LLVMFuzzerTestOneInput — standard libFuzzer entry point.
 *
 * Feeds the fuzzer input directly to pe_open() which runs the
 * full 14-phase pipeline. If parsing succeeds, exercises the
 * query API to read parsed data structures.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Minimum viable PE: DOS header (64) + PE sig (4) + COFF (20) */
    if (size < 88) {
        return 0;
    }

    pe_ctx_t *ctx = pe_open(data, size);
    if (!ctx) {
        return 0;
    }

    /* Exercise header accessors */
    const pe_dos_header_t *dos = pe_get_dos_header(ctx);
    if (dos) {
        (void)dos->e_lfanew;
        (void)dos->e_magic;
    }

    const pe_coff_header_t *coff = pe_get_coff_header(ctx);
    if (coff) {
        (void)pe_get_machine_name(coff->machine);
        (void)coff->num_sections;
        (void)coff->timestamp;
    }

    const pe_optional_header_t *opt = pe_get_optional_header(ctx);
    if (opt) {
        (void)pe_get_subsystem_name(opt->subsystem);
        (void)opt->image_base;
        (void)opt->entry_point_rva;
        (void)opt->is_pe32plus;

        /* Exercise data directory formatting */
        for (uint32_t i = 0; i < PE_NUM_DATA_DIRS; i++) {
            char buf[64];
            pe_format_data_dir_name(i, buf, sizeof(buf));
        }
    }

    /* Exercise section queries */
    uint32_t sec_count = pe_get_section_count(ctx);
    for (uint32_t i = 0; i < sec_count; i++) {
        const pe_section_t *sec = pe_get_section(ctx, i);
        if (sec) {
            const char *name = pe_get_section_name(ctx, i);
            if (name) {
                (void)strlen(name);
            }

            char flags_buf[512];
            pe_format_section_flags(sec->characteristics,
                                    flags_buf, sizeof(flags_buf));
        }
    }

    /* Exercise symbol queries */
    uint32_t sym_count = pe_get_symbol_count(ctx);
    for (uint32_t i = 0; i < sym_count && i < 100; i++) {
        const pe_symbol_t *sym = pe_get_symbol(ctx, i);
        if (sym) {
            const char *name = pe_get_symbol_name(ctx, i);
            if (name) {
                (void)strlen(name);
            }
            (void)pe_get_symbol_class_name(sym->storage_class);
        }
    }

    /* Exercise import queries */
    uint32_t imp_count = pe_get_import_descriptor_count(ctx);
    for (uint32_t d = 0; d < imp_count; d++) {
        const char *dll = pe_get_import_dll_name(ctx, d);
        if (dll) {
            (void)strlen(dll);
        }

        uint32_t thunk_count = pe_get_import_thunk_count(ctx, d);
        for (uint32_t t = 0; t < thunk_count && t < 100; t++) {
            const pe_import_thunk_t *thunk = pe_get_import_thunk(ctx, d, t);
            if (thunk && !thunk->is_ordinal && thunk->name) {
                (void)strlen(thunk->name);
            }
        }
    }

    /* Exercise export queries */
    uint32_t exp_count = pe_get_export_count(ctx);
    for (uint32_t i = 0; i < exp_count && i < 100; i++) {
        const pe_export_entry_t *exp = pe_get_export(ctx, i);
        if (exp) {
            if (exp->name) {
                (void)strlen(exp->name);
            }
            if (exp->forwarder) {
                (void)strlen(exp->forwarder);
            }
        }
    }

    const char *exp_dll = pe_get_export_dll_name(ctx);
    if (exp_dll) {
        (void)strlen(exp_dll);
    }

    /* Exercise reloc queries */
    uint32_t reloc_count = pe_get_reloc_block_count(ctx);
    for (uint32_t i = 0; i < reloc_count && i < 50; i++) {
        const pe_reloc_block_t *block = pe_get_reloc_block(ctx, i);
        if (block) {
            (void)block->page_rva;
            (void)block->count;
        }
    }

    /* Exercise debug queries */
    uint32_t dbg_count = pe_get_debug_entry_count(ctx);
    for (uint32_t i = 0; i < dbg_count; i++) {
        const pe_debug_entry_t *dbg = pe_get_debug_entry(ctx, i);
        if (dbg) {
            (void)pe_get_debug_type_name(dbg->type);
            const char *pdb = pe_get_pdb_path(ctx, i);
            if (pdb) {
                (void)strlen(pdb);
            }
        }
    }

    /* Exercise resource queries */
    uint32_t res_count = pe_get_resource_count(ctx);
    for (uint32_t i = 0; i < res_count && i < 100; i++) {
        const pe_resource_node_t *res = pe_get_resource_entry(ctx, i);
        if (res) {
            const char *name = pe_query_resource_name(ctx, i);
            if (name) {
                (void)strlen(name);
            }
            if (!res->is_named) {
                (void)pe_get_resource_type_name(res->id);
            }
        }
    }

    /* Exercise formatting */
    if (coff) {
        char chars_buf[512];
        pe_format_characteristics(coff->characteristics,
                                   chars_buf, sizeof(chars_buf));

        char ts_buf[64];
        pe_format_timestamp(coff->timestamp, ts_buf, sizeof(ts_buf));

        char machine_buf[64];
        pe_format_machine(coff->machine, machine_buf, sizeof(machine_buf));
    }

    if (opt) {
        char dll_buf[512];
        pe_format_dll_characteristics(opt->dll_characteristics,
                                       dll_buf, sizeof(dll_buf));
    }

    /* Exercise validation issue queries */
    uint32_t issue_count = pe_get_issue_count(ctx);
    for (uint32_t i = 0; i < issue_count; i++) {
        const pe_validation_issue_t *issue = pe_get_issue(ctx, i);
        if (issue) {
            (void)issue->severity;
            (void)strlen(issue->message);
        }
    }

    /* Exercise checksum */
    (void)pe_verify_checksum(ctx);

    pe_close(ctx);
    return 0;
}
