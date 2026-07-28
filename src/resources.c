/*
 * resources.c — Resource Directory Tree Parsing (Phase 11)
 *
 * Parses the PE resource directory, which is organized as a
 * three-level tree: Type → Name/ID → Language/ID. Each level
 * can contain named entries (with Unicode name strings) and
 * ID entries (with numeric identifiers).
 *
 * Leaf nodes contain resource data entries with RVAs pointing
 * to the actual resource data within a section.
 *
 * Reference: Microsoft PE/COFF Specification §6.9
 */

#include "internal.h"

/* Standard resource type name lookup */
const char *pe_get_resource_type_name(uint32_t type_id)
{
    switch (type_id) {
    case PE_RT_CURSOR:       return "CURSOR";
    case PE_RT_BITMAP:       return "BITMAP";
    case PE_RT_ICON:         return "ICON";
    case PE_RT_MENU:         return "MENU";
    case PE_RT_DIALOG:       return "DIALOG";
    case PE_RT_STRING:       return "STRING";
    case PE_RT_FONTDIR:      return "FONTDIR";
    case PE_RT_FONT:         return "FONT";
    case PE_RT_ACCELERATOR:  return "ACCELERATOR";
    case PE_RT_RCDATA:       return "RCDATA";
    case PE_RT_MESSAGETABLE: return "MESSAGETABLE";
    case PE_RT_GROUP_CURSOR: return "GROUP_CURSOR";
    case PE_RT_GROUP_ICON:   return "GROUP_ICON";
    case PE_RT_VERSION:      return "VERSION";
    case PE_RT_MANIFEST:     return "MANIFEST";
    default:                 return "UNKNOWN";
    }
}

/*
 * Read a resource name string.
 * Resource names are stored as counted Unicode strings:
 * 2-byte length followed by UTF-16LE characters.
 * Returns an allocated UTF-8 copy.
 */
static char *pe_read_resource_name(pe_ctx_t *ctx, uint32_t base_offset,
                                    uint32_t name_offset)
{
    uint32_t abs_offset = base_offset + name_offset;
    if (!PE_CHECK_OFFSET(ctx, abs_offset, 2)) {
        return NULL;
    }

    uint16_t char_count = PE_READ_U16(ctx->data + abs_offset);
    if (char_count == 0 || char_count > 256) {
        return NULL;
    }

    uint32_t str_size = (uint32_t)char_count * 2;
    if (!PE_CHECK_OFFSET(ctx, abs_offset + 2, str_size)) {
        return NULL;
    }

    /* Simple UTF-16LE to ASCII conversion (BMP only) */
    char *name = (char *)malloc(char_count + 1);
    if (!name) {
        return NULL;
    }

    const uint8_t *src = ctx->data + abs_offset + 2;
    for (uint16_t i = 0; i < char_count; i++) {
        uint16_t ch = PE_READ_U16(src + i * 2);
        if (ch < 128) {
            name[i] = (char)ch;
        } else {
            name[i] = '?';
        }
    }
    name[char_count] = '\0';

    return name;
}

/*
 * Parse a resource data entry (leaf node).
 * Offset from the resource directory base.
 */
static pe_error_t pe_parse_resource_data_entry(pe_ctx_t *ctx,
                                                uint32_t base_offset,
                                                uint32_t entry_offset,
                                                pe_resource_node_t *node)
{
    uint32_t abs_offset = base_offset + entry_offset;
    if (!PE_CHECK_OFFSET(ctx, abs_offset, 16)) {
        return PE_ERR_TRUNCATED;
    }

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, abs_offset)) {
        return PE_ERR_TRUNCATED;
    }

    if (!pe_reader_read_u32(&r, &node->data_rva)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &node->data_size)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(&r, &node->codepage)) {
        return PE_ERR_TRUNCATED;
    }

    /* Skip reserved field */
    pe_reader_skip(&r, 4);

    /* Resolve data pointer into section */
    if (node->data_rva != 0 && node->data_size > 0) {
        uint32_t sec_idx = pe_find_section_index_by_rva(ctx, node->data_rva);
        if (sec_idx != UINT32_MAX) {
            node->data_ptr = pe_section_rva_to_ptr(ctx, sec_idx,
                                                    node->data_rva,
                                                    PE_MIN(node->data_size, 1));
        }
    }

    return PE_OK;
}

/*
 * Recursively parse a resource directory node.
 * Each directory has a 16-byte header followed by entries.
 */
pe_error_t pe_parse_resource_directory(pe_ctx_t *ctx, pe_reader_t *r,
                                        pe_resource_node_t *parent,
                                        uint32_t base_offset, uint32_t depth)
{
    if (depth > PE_MAX_RESOURCE_DEPTH) {
        pe_ctx_add_warning(ctx,
            "resource tree too deep (depth %u)", depth);
        return PE_OK;
    }

    size_t saved_pos = pe_reader_tell(r);

    /* Read directory header */
    uint32_t characteristics, timestamp;
    uint16_t major_ver, minor_ver;
    uint16_t num_named, num_id;

    if (!pe_reader_read_u32(r, &characteristics)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u32(r, &timestamp)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &major_ver)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &minor_ver)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &num_named)) {
        return PE_ERR_TRUNCATED;
    }
    if (!pe_reader_read_u16(r, &num_id)) {
        return PE_ERR_TRUNCATED;
    }

    uint32_t total_entries = (uint32_t)num_named + (uint32_t)num_id;

    if (total_entries == 0) {
        return PE_OK;
    }

    if (total_entries > PE_MAX_RESOURCE_NODES) {
        pe_ctx_add_warning(ctx,
            "resource directory has %u entries, clamping", total_entries);
        total_entries = PE_MAX_RESOURCE_NODES;
    }

    parent->children = (pe_resource_node_t *)calloc(total_entries,
                                                     sizeof(pe_resource_node_t));
    if (!parent->children) {
        return PE_ERR_ALLOC;
    }
    parent->children_capacity = total_entries;

    /* Parse directory entries: each is 8 bytes (name/ID + offset) */
    uint32_t actual = 0;
    for (uint32_t i = 0; i < total_entries && actual < total_entries; i++) {
        uint32_t name_or_id;
        uint32_t data_or_subdir;

        if (!pe_reader_read_u32(r, &name_or_id)) {
            break;
        }
        if (!pe_reader_read_u32(r, &data_or_subdir)) {
            break;
        }

        pe_resource_node_t *child = &parent->children[actual];
        child->depth = depth;

        /* High bit of name_or_id: 1 = named entry, 0 = ID entry */
        if (name_or_id & 0x80000000) {
            child->is_named = 1;
            uint32_t name_off = name_or_id & 0x7FFFFFFF;
            child->name = pe_read_resource_name(ctx, base_offset, name_off);
            child->id = 0;
        } else {
            child->is_named = 0;
            child->id = name_or_id;
            child->name = NULL;
        }

        /* High bit of data_or_subdir: 1 = subdirectory, 0 = data entry */
        if (data_or_subdir & 0x80000000) {
            child->is_directory = 1;
            uint32_t subdir_offset = data_or_subdir & 0x7FFFFFFF;

            /* Save position, recurse into subdirectory, restore */
            size_t cur_pos = pe_reader_tell(r);

            uint32_t abs_subdir = base_offset + subdir_offset;
            if (pe_reader_seek(r, abs_subdir)) {
                pe_error_t err = pe_parse_resource_directory(ctx, r, child,
                                                              base_offset,
                                                              depth + 1);
                if (err != PE_OK) {
                    pe_ctx_add_warning(ctx,
                        "resource subdirectory at offset 0x%X: parse error",
                        subdir_offset);
                }
            }

            pe_reader_seek(r, cur_pos);
        } else {
            child->is_directory = 0;
            pe_error_t err = pe_parse_resource_data_entry(ctx, base_offset,
                                                           data_or_subdir,
                                                           child);
            if (err != PE_OK) {
                pe_ctx_add_warning(ctx,
                    "resource data entry at offset 0x%X: parse error",
                    data_or_subdir);
            }
        }

        actual++;
    }

    parent->num_children = actual;
    PE_UNUSED(saved_pos);

    return PE_OK;
}

/*
 * Flatten the resource tree into a linear array of leaf entries.
 * Collects all non-directory nodes for easier enumeration.
 */
pe_error_t pe_flatten_resource_tree(pe_ctx_t *ctx, pe_resource_node_t *node)
{
    if (!node) {
        return PE_OK;
    }

    if (!node->is_directory) {
        /* Leaf node — add to flat list */
        pe_resource_tree_t *rt = &ctx->resources;

        if (rt->flat_count >= PE_MAX_RESOURCE_NODES) {
            return PE_OK;
        }

        if (rt->flat_count >= rt->flat_capacity) {
            uint32_t newcap = rt->flat_capacity == 0 ? 64 : rt->flat_capacity * 2;
            if (newcap > PE_MAX_RESOURCE_NODES) {
                newcap = PE_MAX_RESOURCE_NODES;
            }
            pe_resource_node_t **tmp = (pe_resource_node_t **)realloc(
                rt->flat_entries, newcap * sizeof(pe_resource_node_t *));
            if (!tmp) {
                return PE_ERR_ALLOC;
            }
            rt->flat_entries = tmp;
            rt->flat_capacity = newcap;
        }

        rt->flat_entries[rt->flat_count] = node;
        rt->flat_count++;
        return PE_OK;
    }

    /* Recurse into children */
    for (uint32_t i = 0; i < node->num_children; i++) {
        pe_error_t err = pe_flatten_resource_tree(ctx, &node->children[i]);
        if (err != PE_OK) {
            return err;
        }
    }

    return PE_OK;
}

/*
 * Parse the complete resource tree from the resource directory RVA.
 */
pe_error_t pe_parse_resource_tree(pe_ctx_t *ctx)
{
    if (!ctx || !ctx->data) {
        return PE_ERR_NULLARG;
    }

    pe_data_dir_t *rsrc_dir = &ctx->optional.data_dirs[PE_DIR_RESOURCE];
    if (rsrc_dir->rva == 0 || rsrc_dir->size == 0) {
        return PE_OK;
    }

    uint32_t dir_offset = pe_rva_to_offset(ctx, rsrc_dir->rva);
    if (dir_offset == 0) {
        pe_ctx_set_error(ctx, PE_ERR_INVALID_RESOURCE,
                         "resource directory RVA 0x%X does not resolve",
                         rsrc_dir->rva);
        return PE_ERR_INVALID_RESOURCE;
    }

    pe_resource_tree_t *rt = &ctx->resources;

    /* Allocate root node */
    rt->root = (pe_resource_node_t *)calloc(1, sizeof(pe_resource_node_t));
    if (!rt->root) {
        return PE_ERR_ALLOC;
    }
    rt->root->is_directory = 1;
    rt->root->depth = 0;

    pe_reader_t r;
    pe_reader_init(&r, ctx->data, ctx->size);
    if (!pe_reader_seek(&r, dir_offset)) {
        return PE_ERR_TRUNCATED;
    }

    pe_error_t err = pe_parse_resource_directory(ctx, &r, rt->root,
                                                  dir_offset, 0);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "resource tree parse incomplete");
    }

    /* Build flat entry list */
    err = pe_flatten_resource_tree(ctx, rt->root);
    if (err != PE_OK) {
        pe_ctx_add_warning(ctx, "resource tree flattening incomplete");
    }

    return PE_OK;
}

/* Recursively free a resource tree node */
void pe_free_resource_node(pe_resource_node_t *node)
{
    if (!node) {
        return;
    }

    free(node->name);
    node->name = NULL;

    if (node->children) {
        for (uint32_t i = 0; i < node->num_children; i++) {
            pe_free_resource_node(&node->children[i]);
        }
        free(node->children);
        node->children = NULL;
    }
}

/* Free the resource tree */
void pe_free_resource_tree(pe_resource_tree_t *rt)
{
    if (!rt) {
        return;
    }

    if (rt->root) {
        pe_free_resource_node(rt->root);
        free(rt->root);
        rt->root = NULL;
    }

    free(rt->flat_entries);
    rt->flat_entries = NULL;
    rt->flat_count = 0;
    rt->flat_capacity = 0;
}

/* Public API: resource root */
const pe_resource_node_t *pe_get_resource_root(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return ctx->resources.root;
}

/* Public API: flat resource count */
uint32_t pe_get_resource_count(const pe_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->resources.flat_count;
}

/* Public API: get resource by flat index */
const pe_resource_node_t *pe_get_resource_entry(const pe_ctx_t *ctx,
                                                  uint32_t flat_index)
{
    if (!ctx || flat_index >= ctx->resources.flat_count) {
        return NULL;
    }
    return ctx->resources.flat_entries[flat_index];
}
