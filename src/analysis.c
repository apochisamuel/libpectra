/*
 * analysis.c — PE Image Analysis Utilities
 *
 * Provides analytical functions for PE images including section
 * entropy calculation, data pattern classification, section overlap
 * detection, and RVA coverage mapping. These utilities support
 * malware analysis and binary inspection workflows.
 */

#include "internal.h"
#include <math.h>

/* ----------------------------------------------------------------
 * Entropy calculation
 * ---------------------------------------------------------------- */

/*
 * Calculate the Shannon entropy of a byte sequence.
 * Returns a value between 0.0 (uniform) and 8.0 (random).
 * High entropy (> 7.0) suggests encrypted or compressed data.
 * Low entropy (< 1.0) suggests padding or uninitialized data.
 */
static double pe_calculate_entropy(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0.0;
    }

    uint32_t freq[256];
    memset(freq, 0, sizeof(freq));

    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    double log2_val = log(2.0);

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) {
            continue;
        }
        double p = (double)freq[i] / (double)size;
        entropy -= p * (log(p) / log2_val);
    }

    return entropy;
}

/*
 * Classify a data block based on its byte distribution.
 * Returns a string describing the likely content type.
 */
static const char *pe_classify_data_block(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return "empty";
    }

    double entropy = pe_calculate_entropy(data, size);

    /* Count specific byte patterns */
    uint32_t zero_count = 0;
    uint32_t printable_count = 0;
    uint32_t highbit_count = 0;

    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0x00) zero_count++;
        if (data[i] >= 0x20 && data[i] <= 0x7E) printable_count++;
        if (data[i] >= 0x80) highbit_count++;
    }

    double zero_ratio = (double)zero_count / (double)size;
    double print_ratio = (double)printable_count / (double)size;
    double high_ratio = (double)highbit_count / (double)size;

    if (zero_ratio > 0.90) {
        return "padding/uninitialized";
    }
    if (entropy > 7.5 && high_ratio > 0.30) {
        return "encrypted/compressed";
    }
    if (entropy > 6.5) {
        return "high-entropy data";
    }
    if (print_ratio > 0.80) {
        return "text/strings";
    }
    if (entropy < 2.0 && zero_ratio > 0.50) {
        return "sparse data";
    }
    if (entropy >= 4.0 && entropy <= 6.5) {
        return "native code";
    }

    return "mixed data";
}

/*
 * Compute a simple non-cryptographic hash of a data block.
 * Uses FNV-1a for fast collision-resistant hashing.
 */
static uint64_t pe_hash_data(const uint8_t *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

/* ----------------------------------------------------------------
 * Section analysis
 * ---------------------------------------------------------------- */

/*
 * Analyze a single section's content and print a summary.
 * Returns the entropy value for the section.
 */
static double pe_analyze_section_content(const pe_section_t *sec,
                                          uint32_t index)
{
    PE_UNUSED(index);

    if (!sec || !sec->data || sec->data_size == 0) {
        return 0.0;
    }

    double entropy = pe_calculate_entropy(sec->data, sec->data_size);
    return entropy;
}

/*
 * Check for overlapping sections in the virtual address space.
 * Overlapping sections are unusual and may indicate corruption
 * or malicious intent.
 */
static uint32_t pe_detect_section_overlaps(const pe_ctx_t *ctx)
{
    uint32_t overlap_count = 0;

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec_a = &ctx->sections.entries[i];
        uint32_t a_start = sec_a->virtual_address;
        uint32_t a_end = a_start + sec_a->virtual_size;
        if (sec_a->virtual_size == 0) {
            a_end = a_start + sec_a->raw_data_size;
        }

        for (uint32_t j = i + 1; j < ctx->sections.count; j++) {
            const pe_section_t *sec_b = &ctx->sections.entries[j];
            uint32_t b_start = sec_b->virtual_address;
            uint32_t b_end = b_start + sec_b->virtual_size;
            if (sec_b->virtual_size == 0) {
                b_end = b_start + sec_b->raw_data_size;
            }

            if (a_start < b_end && b_start < a_end) {
                overlap_count++;
            }
        }
    }

    return overlap_count;
}

/*
 * Check for overlapping sections in file offset space.
 */
static uint32_t pe_detect_raw_overlaps(const pe_ctx_t *ctx)
{
    uint32_t overlap_count = 0;

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec_a = &ctx->sections.entries[i];
        if (sec_a->raw_data_size == 0 || sec_a->raw_data_offset == 0) {
            continue;
        }
        uint32_t a_start = sec_a->raw_data_offset;
        uint32_t a_end = a_start + sec_a->raw_data_size;

        for (uint32_t j = i + 1; j < ctx->sections.count; j++) {
            const pe_section_t *sec_b = &ctx->sections.entries[j];
            if (sec_b->raw_data_size == 0 || sec_b->raw_data_offset == 0) {
                continue;
            }
            uint32_t b_start = sec_b->raw_data_offset;
            uint32_t b_end = b_start + sec_b->raw_data_size;

            if (a_start < b_end && b_start < a_end) {
                overlap_count++;
            }
        }
    }

    return overlap_count;
}

/* ----------------------------------------------------------------
 * RVA coverage analysis
 * ---------------------------------------------------------------- */

/*
 * Compute the total virtual address space coverage of all sections.
 * Returns the total bytes covered and any gaps between sections.
 */
static void pe_compute_va_coverage(const pe_ctx_t *ctx,
                                    uint64_t *total_covered,
                                    uint32_t *gap_count)
{
    *total_covered = 0;
    *gap_count = 0;

    if (ctx->sections.count == 0) {
        return;
    }

    /* Find min and max VA */
    uint32_t min_va = UINT32_MAX;
    uint32_t max_va_end = 0;

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        uint32_t sec_end = sec->virtual_address + sec->virtual_size;
        if (sec->virtual_size == 0) {
            sec_end = sec->virtual_address + sec->raw_data_size;
        }

        if (sec->virtual_address < min_va) {
            min_va = sec->virtual_address;
        }
        if (sec_end > max_va_end) {
            max_va_end = sec_end;
        }

        *total_covered += (sec_end - sec->virtual_address);
    }

    /* Count gaps (simplified — assumes sections are sorted by VA) */
    for (uint32_t i = 0; i + 1 < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        const pe_section_t *next = &ctx->sections.entries[i + 1];
        uint32_t sec_end = sec->virtual_address + sec->virtual_size;
        if (sec->virtual_size == 0) {
            sec_end = sec->virtual_address + sec->raw_data_size;
        }

        if (next->virtual_address > sec_end) {
            (*gap_count)++;
        }
    }
}

/* ----------------------------------------------------------------
 * Import analysis
 * ---------------------------------------------------------------- */

/*
 * Count unique DLL names in the import table.
 * Duplicate DLL entries may indicate packing or obfuscation.
 */
static uint32_t pe_count_unique_import_dlls(const pe_ctx_t *ctx)
{
    if (ctx->imports.count == 0) {
        return 0;
    }

    /* Simple O(n^2) uniqueness check — fine for typical PE files */
    uint32_t unique = 0;
    for (uint32_t i = 0; i < ctx->imports.count; i++) {
        const char *name_i = ctx->imports.descriptors[i].dll_name;
        if (!name_i) {
            continue;
        }

        int is_dup = 0;
        for (uint32_t j = 0; j < i; j++) {
            const char *name_j = ctx->imports.descriptors[j].dll_name;
            if (name_j && strcmp(name_i, name_j) == 0) {
                is_dup = 1;
                break;
            }
        }

        if (!is_dup) {
            unique++;
        }
    }

    return unique;
}

/*
 * Count imports by ordinal vs by name.
 */
static void pe_count_import_types(const pe_ctx_t *ctx,
                                    uint32_t *by_name, uint32_t *by_ordinal)
{
    *by_name = 0;
    *by_ordinal = 0;

    for (uint32_t d = 0; d < ctx->imports.count; d++) {
        const pe_import_descriptor_t *desc = &ctx->imports.descriptors[d];
        for (uint32_t t = 0; t < desc->num_thunks; t++) {
            if (desc->thunks[t].is_ordinal) {
                (*by_ordinal)++;
            } else {
                (*by_name)++;
            }
        }
    }
}

/* ----------------------------------------------------------------
 * Export analysis
 * ---------------------------------------------------------------- */

/*
 * Count exports by type: named, by ordinal only, and forwarders.
 */
static void pe_count_export_types(const pe_ctx_t *ctx,
                                    uint32_t *named, uint32_t *ordinal_only,
                                    uint32_t *forwarders)
{
    *named = 0;
    *ordinal_only = 0;
    *forwarders = 0;

    for (uint32_t i = 0; i < ctx->exports.num_functions; i++) {
        const pe_export_entry_t *entry = &ctx->exports.entries[i];

        if (entry->is_forwarder) {
            (*forwarders)++;
        }

        if (entry->has_name) {
            (*named)++;
        } else if (entry->function_rva != 0) {
            (*ordinal_only)++;
        }
    }
}

/* ----------------------------------------------------------------
 * Header consistency analysis
 * ---------------------------------------------------------------- */

/*
 * Verify that data directory RVAs fall within valid sections.
 * Returns the count of unresolvable data directories.
 */
static uint32_t pe_check_data_dir_coverage(const pe_ctx_t *ctx)
{
    uint32_t unresolved = 0;

    for (uint32_t i = 0; i < PE_NUM_DATA_DIRS; i++) {
        const pe_data_dir_t *dd = &ctx->optional.data_dirs[i];
        if (dd->rva == 0 || dd->size == 0) {
            continue;
        }

        const pe_section_t *sec = pe_find_section_by_rva(ctx, dd->rva);
        if (!sec) {
            unresolved++;
        }
    }

    return unresolved;
}

/*
 * Check if the entry point falls within a code section.
 */
static int pe_check_entry_point(const pe_ctx_t *ctx)
{
    uint32_t ep = ctx->optional.entry_point_rva;
    if (ep == 0) {
        return 1;  /* No entry point is valid for some image types */
    }

    const pe_section_t *sec = pe_find_section_by_rva(ctx, ep);
    if (!sec) {
        return 0;  /* Entry point doesn't fall in any section */
    }

    /* Check if the section is executable */
    return (sec->characteristics & PE_SCN_MEM_EXECUTE) != 0;
}

/* ----------------------------------------------------------------
 * Suspicious pattern detection
 * ---------------------------------------------------------------- */

/*
 * Check for sections with unusual characteristic combinations.
 * Returns the count of suspicious sections.
 */
static uint32_t pe_detect_suspicious_sections(const pe_ctx_t *ctx)
{
    uint32_t suspicious = 0;

    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        uint32_t chars = sec->characteristics;

        /* Writable + Executable is suspicious (W^X violation) */
        if ((chars & PE_SCN_MEM_WRITE) && (chars & PE_SCN_MEM_EXECUTE)) {
            suspicious++;
        }

        /* Very high entropy in a code section may indicate packing */
        if (sec->data && sec->data_size > 0 &&
            (chars & PE_SCN_CNT_CODE)) {
            double entropy = pe_calculate_entropy(sec->data, sec->data_size);
            if (entropy > 7.0) {
                suspicious++;
            }
        }

        /* Zero virtual size with non-zero raw size */
        if (sec->virtual_size == 0 && sec->raw_data_size > 0) {
            suspicious++;
        }
    }

    return suspicious;
}

/*
 * Check for header anomalies that may indicate modification.
 */
static uint32_t pe_detect_header_anomalies(const pe_ctx_t *ctx)
{
    uint32_t anomalies = 0;

    /* Check for unusually large e_lfanew */
    if (ctx->dos.e_lfanew > 1024) {
        anomalies++;
    }

    /* Check for section alignment < file alignment */
    if (ctx->optional.section_alignment > 0 &&
        ctx->optional.file_alignment > 0 &&
        ctx->optional.section_alignment < ctx->optional.file_alignment) {
        anomalies++;
    }

    /* Check for zero size of image */
    if (ctx->optional.size_of_image == 0) {
        anomalies++;
    }

    /* Check entry point consistency */
    if (!pe_check_entry_point(ctx)) {
        anomalies++;
    }

    /* Check data directory coverage */
    uint32_t unresolved_dirs = pe_check_data_dir_coverage(ctx);
    anomalies += unresolved_dirs;

    return anomalies;
}

/* ----------------------------------------------------------------
 * Comprehensive analysis — ties everything together
 * ---------------------------------------------------------------- */

/*
 * Perform a comprehensive analysis of the PE image.
 * This function exercises all analysis utilities and produces
 * results that can be used for binary classification.
 *
 * Not part of the public API — used internally by the fuzzer
 * harnesses to maximize code coverage.
 */
void pe_comprehensive_analysis(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }

    /* Section analysis */
    for (uint32_t i = 0; i < ctx->sections.count; i++) {
        const pe_section_t *sec = &ctx->sections.entries[i];
        double entropy = pe_analyze_section_content(sec, i);
        PE_UNUSED(entropy);

        if (sec->data && sec->data_size > 0) {
            const char *classification = pe_classify_data_block(
                sec->data, sec->data_size);
            PE_UNUSED(classification);

            uint64_t hash = pe_hash_data(sec->data, sec->data_size);
            PE_UNUSED(hash);
        }
    }

    /* Overlap detection */
    uint32_t va_overlaps = pe_detect_section_overlaps(ctx);
    uint32_t raw_overlaps = pe_detect_raw_overlaps(ctx);
    PE_UNUSED(va_overlaps);
    PE_UNUSED(raw_overlaps);

    /* VA coverage */
    uint64_t total_covered;
    uint32_t gap_count;
    pe_compute_va_coverage(ctx, &total_covered, &gap_count);
    PE_UNUSED(total_covered);
    PE_UNUSED(gap_count);

    /* Import analysis */
    uint32_t unique_dlls = pe_count_unique_import_dlls(ctx);
    PE_UNUSED(unique_dlls);

    uint32_t imp_by_name, imp_by_ordinal;
    pe_count_import_types(ctx, &imp_by_name, &imp_by_ordinal);
    PE_UNUSED(imp_by_name);
    PE_UNUSED(imp_by_ordinal);

    /* Export analysis */
    uint32_t exp_named, exp_ordinal, exp_fwd;
    pe_count_export_types(ctx, &exp_named, &exp_ordinal, &exp_fwd);
    PE_UNUSED(exp_named);
    PE_UNUSED(exp_ordinal);
    PE_UNUSED(exp_fwd);

    /* Anomaly detection */
    uint32_t suspicious = pe_detect_suspicious_sections(ctx);
    uint32_t anomalies = pe_detect_header_anomalies(ctx);
    PE_UNUSED(suspicious);
    PE_UNUSED(anomalies);
}
