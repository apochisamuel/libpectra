/*
 * resource_fuzzer.cc — Resource tree focused fuzzer
 *
 * Targeted fuzzer that emphasizes resource directory parsing,
 * tree traversal, and resource name resolution. Exercises the
 * resource cache and cross-references with debug and export data.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
#include "pectra.h"
}

/*
 * Recursively traverse a resource tree node and inspect all fields.
 */
static void traverse_resource_tree(const pe_resource_node_t *node,
                                    uint32_t depth)
{
    if (!node || depth > 8) {
        return;
    }

    if (node->is_named && node->name) {
        size_t name_len = strlen(node->name);
        (void)name_len;
    } else {
        (void)pe_get_resource_type_name(node->id);
    }

    (void)node->data_rva;
    (void)node->data_size;
    (void)node->codepage;

    if (node->data_ptr && node->data_size > 0) {
        /* Read first few bytes of resource data */
        uint32_t check_size = node->data_size;
        if (check_size > 64) {
            check_size = 64;
        }
        uint32_t cs = 0;
        for (uint32_t i = 0; i < check_size; i++) {
            cs += node->data_ptr[i];
        }
        (void)cs;
    }

    if (node->is_directory && node->children) {
        for (uint32_t i = 0; i < node->num_children; i++) {
            traverse_resource_tree(&node->children[i], depth + 1);
        }
    }
}

/*
 * Perform deep resource inspection.
 */
static void inspect_resources(pe_ctx_t *ctx)
{
    /* Traverse the full resource tree */
    const pe_resource_node_t *root = pe_get_resource_root(ctx);
    if (root) {
        traverse_resource_tree(root, 0);
    }

    /* Enumerate flat resource list */
    uint32_t res_count = pe_get_resource_count(ctx);
    for (uint32_t i = 0; i < res_count; i++) {
        const pe_resource_node_t *entry = pe_get_resource_entry(ctx, i);
        if (!entry) {
            continue;
        }

        /* Query cached name */
        const char *name = pe_query_resource_name(ctx, i);
        if (name) {
            size_t len = strlen(name);
            (void)len;
        }

        /* Check resource type */
        if (!entry->is_named) {
            const char *type_name = pe_get_resource_type_name(entry->id);
            if (type_name) {
                (void)strlen(type_name);
            }
        }

        /* Verify resource data accessibility */
        if (entry->data_rva != 0) {
            const uint8_t *ptr = pe_rva_to_ptr(ctx, entry->data_rva, 1);
            if (ptr) {
                (void)*ptr;
            }
        }
    }
}

/*
 * Cross-reference resources with sections and debug info.
 */
static void cross_reference_resources(pe_ctx_t *ctx)
{
    uint32_t res_count = pe_get_resource_count(ctx);
    uint32_t sec_count = pe_get_section_count(ctx);

    /* For each resource, find its containing section */
    for (uint32_t i = 0; i < res_count && i < 100; i++) {
        const pe_resource_node_t *entry = pe_get_resource_entry(ctx, i);
        if (!entry || entry->data_rva == 0) {
            continue;
        }

        const pe_section_t *sec = pe_find_section_by_rva(ctx, entry->data_rva);
        if (sec) {
            const char *sec_name = sec->resolved_name;
            if (sec_name) {
                (void)strlen(sec_name);
            }
        }
    }

    /* Cross-reference with debug entries */
    uint32_t dbg_count = pe_get_debug_entry_count(ctx);
    for (uint32_t d = 0; d < dbg_count; d++) {
        const pe_debug_entry_t *dbg = pe_get_debug_entry(ctx, d);
        if (!dbg) {
            continue;
        }

        /* Check if debug data overlaps with any resource */
        for (uint32_t r = 0; r < res_count && r < 50; r++) {
            const pe_resource_node_t *res = pe_get_resource_entry(ctx, r);
            if (!res || res->data_rva == 0) {
                continue;
            }

            if (dbg->address_rva != 0 &&
                dbg->address_rva >= res->data_rva &&
                dbg->address_rva < res->data_rva + res->data_size) {
                /* Overlap detected */
                (void)dbg->type;
            }
        }
    }

    /* Section name queries via cache */
    for (uint32_t i = 0; i < sec_count; i++) {
        const char *name = pe_get_section_name(ctx, i);
        if (name) {
            (void)strlen(name);
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

    inspect_resources(ctx);
    cross_reference_resources(ctx);

    /* Exercise export queries alongside resources */
    uint32_t exp_count = pe_get_export_count(ctx);
    for (uint32_t i = 0; i < exp_count && i < 50; i++) {
        const pe_export_entry_t *exp = pe_get_export(ctx, i);
        if (exp) {
            if (exp->name) {
                (void)strlen(exp->name);
            }
            if (exp->is_forwarder && exp->forwarder) {
                (void)strlen(exp->forwarder);
            }
        }
    }

    /* Exercise relocation queries */
    uint32_t reloc_count = pe_get_reloc_block_count(ctx);
    for (uint32_t i = 0; i < reloc_count && i < 50; i++) {
        const pe_reloc_block_t *block = pe_get_reloc_block(ctx, i);
        if (block) {
            for (uint32_t j = 0; j < block->count && j < 100; j++) {
                (void)block->entries[j].type;
                (void)block->entries[j].offset;
            }
        }
    }

    /* Hex dump exercise */
    if (size > 0) {
        char hex_buf[256];
        uint32_t dump_len = (uint32_t)(size < 32 ? size : 32);
        pe_format_hex_dump(data, dump_len, hex_buf, sizeof(hex_buf));
    }

    /* Checksum verification */
    (void)pe_verify_checksum(ctx);

    /* Issue query */
    uint32_t issue_count = pe_get_issue_count(ctx);
    for (uint32_t i = 0; i < issue_count; i++) {
        const pe_validation_issue_t *issue = pe_get_issue(ctx, i);
        if (issue) {
            (void)issue->message;
            (void)issue->severity;
        }
    }

    pe_close(ctx);
    return 0;
}
