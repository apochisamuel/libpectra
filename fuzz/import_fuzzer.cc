/*
 * import_fuzzer.cc — Import table focused fuzzer
 *
 * Targeted fuzzer that emphasizes the import parsing and resolution
 * code paths. Performs additional import-specific queries after
 * the full pipeline runs.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "pectra.h"
}

/*
 * Perform deep import inspection on the parsed context.
 * Reads import names, DLL names, thunk data, and exercises
 * import-export cross-references.
 */
static void inspect_imports(pe_ctx_t *ctx)
{
    uint32_t desc_count = pe_get_import_descriptor_count(ctx);

    for (uint32_t d = 0; d < desc_count; d++) {
        const pe_import_descriptor_t *desc = pe_get_import_descriptor(ctx, d);
        if (!desc) {
            continue;
        }

        /* Read DLL name string */
        const char *dll_name = pe_get_import_dll_name(ctx, d);
        if (dll_name) {
            size_t dll_len = strlen(dll_name);
            (void)dll_len;

            /* Try to find matching export from the same image */
            const pe_export_entry_t *exp = pe_find_export_by_name(ctx, dll_name);
            (void)exp;
        }

        /* Iterate all thunks */
        uint32_t thunk_count = pe_get_import_thunk_count(ctx, d);
        for (uint32_t t = 0; t < thunk_count; t++) {
            const pe_import_thunk_t *thunk = pe_get_import_thunk(ctx, d, t);
            if (!thunk) {
                continue;
            }

            if (thunk->is_ordinal) {
                /* Look up ordinal in export table */
                const pe_export_entry_t *exp =
                    pe_find_export_by_ordinal(ctx, thunk->ordinal);
                if (exp && exp->name) {
                    (void)strlen(exp->name);
                }
            } else if (thunk->name) {
                /* Read import name and compute hash */
                size_t name_len = strlen(thunk->name);
                uint32_t hash = 0;
                for (size_t i = 0; i < name_len; i++) {
                    hash = hash * 31 + (uint8_t)thunk->name[i];
                }
                (void)hash;

                /* Look up in export table */
                const pe_export_entry_t *exp =
                    pe_find_export_by_name(ctx, thunk->name);
                if (exp) {
                    (void)exp->function_rva;
                    (void)exp->ordinal;
                    if (exp->forwarder) {
                        (void)strlen(exp->forwarder);
                    }
                }
            }

            (void)thunk->hint;
            (void)thunk->thunk_rva;
        }
    }
}

/*
 * Inspect section data that may contain import tables.
 */
static void inspect_import_sections(pe_ctx_t *ctx)
{
    const pe_optional_header_t *opt = pe_get_optional_header(ctx);
    if (!opt) {
        return;
    }

    /* Find the section containing the import directory */
    uint32_t import_rva = opt->data_dirs[PE_DIR_IMPORT].rva;
    if (import_rva == 0) {
        return;
    }

    const pe_section_t *imp_sec = pe_find_section_by_rva(ctx, import_rva);
    if (imp_sec) {
        const char *sec_name = imp_sec->resolved_name;
        if (sec_name) {
            (void)strlen(sec_name);
        }

        /* Read section characteristics */
        char flags_buf[512];
        pe_format_section_flags(imp_sec->characteristics,
                                flags_buf, sizeof(flags_buf));

        /* Check section data */
        if (imp_sec->data && imp_sec->data_size > 0) {
            /* Compute simple checksum of section data */
            uint32_t cs = 0;
            for (size_t i = 0; i < imp_sec->data_size; i++) {
                cs += imp_sec->data[i];
            }
            (void)cs;
        }
    }

    /* Find the section containing the IAT */
    uint32_t iat_rva = opt->data_dirs[PE_DIR_IAT].rva;
    if (iat_rva != 0) {
        const pe_section_t *iat_sec = pe_find_section_by_rva(ctx, iat_rva);
        if (iat_sec) {
            const char *name = iat_sec->resolved_name;
            if (name) {
                (void)strlen(name);
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 88) {
        return 0;
    }

    pe_ctx_t *ctx = pe_open(data, size);
    if (!ctx) {
        return 0;
    }

    inspect_imports(ctx);
    inspect_import_sections(ctx);

    /* Also exercise symbol-import cross-references */
    uint32_t sym_count = pe_get_symbol_count(ctx);
    uint32_t imp_count = pe_get_import_descriptor_count(ctx);

    if (sym_count > 0 && imp_count > 0) {
        for (uint32_t s = 0; s < sym_count && s < 50; s++) {
            const char *sym_name = pe_get_symbol_name(ctx, s);
            if (!sym_name) {
                continue;
            }

            /* Check if symbol name matches any import */
            for (uint32_t d = 0; d < imp_count; d++) {
                uint32_t tc = pe_get_import_thunk_count(ctx, d);
                for (uint32_t t = 0; t < tc && t < 20; t++) {
                    const pe_import_thunk_t *thunk =
                        pe_get_import_thunk(ctx, d, t);
                    if (thunk && !thunk->is_ordinal && thunk->name) {
                        if (strcmp(sym_name, thunk->name) == 0) {
                            /* Match found */
                            (void)thunk->hint;
                        }
                    }
                }
            }
        }
    }

    /* Exercise error reporting */
    (void)pe_get_error(ctx);
    const char *err_msg = pe_get_error_message(ctx);
    if (err_msg) {
        (void)strlen(err_msg);
    }

    pe_close(ctx);
    return 0;
}
