/*
 * pectra.h — PE/COFF Binary Format Analysis Library
 *
 * Public API for parsing and inspecting Portable Executable files.
 * Supports PE32 and PE32+ (64-bit) formats with full coverage of
 * import tables, export tables, relocations, debug info, resources,
 * and COFF symbol tables.
 *
 * Usage:
 *   pe_ctx_t *ctx = pe_open(data, size);
 *   if (!ctx) { handle error }
 *   const pe_coff_header_t *coff = pe_get_coff_header(ctx);
 *   pe_close(ctx);
 */

#ifndef PECTRA_H
#define PECTRA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------
 * Error codes
 * ---------------------------------------------------------------- */
typedef enum {
    PE_OK = 0,
    PE_ERR_NULLARG,
    PE_ERR_TRUNCATED,
    PE_ERR_INVALID_DOS,
    PE_ERR_INVALID_PE_SIG,
    PE_ERR_INVALID_COFF,
    PE_ERR_INVALID_OPTIONAL,
    PE_ERR_INVALID_SECTION,
    PE_ERR_INVALID_STRING_TABLE,
    PE_ERR_INVALID_SYMBOL,
    PE_ERR_INVALID_IMPORT,
    PE_ERR_INVALID_EXPORT,
    PE_ERR_INVALID_RELOC,
    PE_ERR_INVALID_DEBUG,
    PE_ERR_INVALID_RESOURCE,
    PE_ERR_INVALID_EXCEPTION,
    PE_ERR_VALIDATION_FAILED,
    PE_ERR_RESOLVE_FAILED,
    PE_ERR_CHECKSUM_MISMATCH,
    PE_ERR_ALLOC,
    PE_ERR_OVERFLOW,
    PE_ERR_UNSUPPORTED,
    PE_ERR_COUNT
} pe_error_t;

/* ----------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------- */
#define PE_DOS_MAGIC           0x5A4D      /* "MZ" */
#define PE_SIGNATURE           0x00004550  /* "PE\0\0" */
#define PE_OPT_MAGIC_PE32      0x010B
#define PE_OPT_MAGIC_PE32PLUS  0x020B

#define PE_NUM_DATA_DIRS       16

/* Data directory indices */
#define PE_DIR_EXPORT          0
#define PE_DIR_IMPORT          1
#define PE_DIR_RESOURCE        2
#define PE_DIR_EXCEPTION       3
#define PE_DIR_SECURITY        4
#define PE_DIR_BASERELOC       5
#define PE_DIR_DEBUG           6
#define PE_DIR_ARCHITECTURE    7
#define PE_DIR_GLOBALPTR       8
#define PE_DIR_TLS             9
#define PE_DIR_LOAD_CONFIG     10
#define PE_DIR_BOUND_IMPORT    11
#define PE_DIR_IAT             12
#define PE_DIR_DELAY_IMPORT    13
#define PE_DIR_CLR_RUNTIME     14
#define PE_DIR_RESERVED        15

/* Machine types */
#define PE_MACHINE_UNKNOWN     0x0000
#define PE_MACHINE_I386        0x014C
#define PE_MACHINE_AMD64       0x8664
#define PE_MACHINE_ARM         0x01C0
#define PE_MACHINE_ARM64       0xAA64
#define PE_MACHINE_ARMNT       0x01C4
#define PE_MACHINE_IA64        0x0200

/* Section characteristics */
#define PE_SCN_CNT_CODE        0x00000020
#define PE_SCN_CNT_INIT_DATA   0x00000040
#define PE_SCN_CNT_UNINIT_DATA 0x00000080
#define PE_SCN_MEM_EXECUTE     0x20000000
#define PE_SCN_MEM_READ        0x40000000
#define PE_SCN_MEM_WRITE       0x80000000
#define PE_SCN_MEM_DISCARDABLE 0x02000000
#define PE_SCN_MEM_SHARED      0x10000000
#define PE_SCN_ALIGN_MASK      0x00F00000

/* Relocation types */
#define PE_REL_BASED_ABSOLUTE  0
#define PE_REL_BASED_HIGH      1
#define PE_REL_BASED_LOW       2
#define PE_REL_BASED_HIGHLOW   3
#define PE_REL_BASED_HIGHADJ   4
#define PE_REL_BASED_DIR64     10

/* Debug types */
#define PE_DEBUG_TYPE_UNKNOWN   0
#define PE_DEBUG_TYPE_COFF      1
#define PE_DEBUG_TYPE_CODEVIEW  2
#define PE_DEBUG_TYPE_FPO       3
#define PE_DEBUG_TYPE_MISC      4
#define PE_DEBUG_TYPE_BORLAND   9
#define PE_DEBUG_TYPE_REPRO     16
#define PE_DEBUG_TYPE_POGO      13

/* Symbol storage classes */
#define PE_SYM_CLASS_NULL           0
#define PE_SYM_CLASS_EXTERNAL       2
#define PE_SYM_CLASS_STATIC         3
#define PE_SYM_CLASS_LABEL          6
#define PE_SYM_CLASS_FUNCTION       101
#define PE_SYM_CLASS_FILE           103
#define PE_SYM_CLASS_SECTION        104
#define PE_SYM_CLASS_WEAK_EXTERNAL  105

/* Resource types */
#define PE_RT_CURSOR       1
#define PE_RT_BITMAP       2
#define PE_RT_ICON         3
#define PE_RT_MENU         4
#define PE_RT_DIALOG       5
#define PE_RT_STRING       6
#define PE_RT_FONTDIR      7
#define PE_RT_FONT         8
#define PE_RT_ACCELERATOR  9
#define PE_RT_RCDATA       10
#define PE_RT_MESSAGETABLE 11
#define PE_RT_GROUP_CURSOR 12
#define PE_RT_GROUP_ICON   14
#define PE_RT_VERSION      16
#define PE_RT_MANIFEST     24

/* DLL characteristics */
#define PE_DLLCHAR_HIGH_ENTROPY_VA   0x0020
#define PE_DLLCHAR_DYNAMIC_BASE      0x0040
#define PE_DLLCHAR_FORCE_INTEGRITY   0x0080
#define PE_DLLCHAR_NX_COMPAT         0x0100
#define PE_DLLCHAR_NO_ISOLATION      0x0200
#define PE_DLLCHAR_NO_SEH            0x0400
#define PE_DLLCHAR_NO_BIND           0x0800
#define PE_DLLCHAR_APPCONTAINER      0x1000
#define PE_DLLCHAR_WDM_DRIVER        0x2000
#define PE_DLLCHAR_GUARD_CF          0x4000
#define PE_DLLCHAR_TERMINAL_SERVER   0x8000

/* Subsystem values */
#define PE_SUBSYS_UNKNOWN      0
#define PE_SUBSYS_NATIVE       1
#define PE_SUBSYS_WINDOWS_GUI  2
#define PE_SUBSYS_WINDOWS_CUI  3
#define PE_SUBSYS_POSIX_CUI    7
#define PE_SUBSYS_WINDOWS_CE   9
#define PE_SUBSYS_EFI_APP      10

/* ----------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------- */

/* DOS stub header */
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} pe_dos_header_t;

/* COFF file header */
typedef struct {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symbol_table_offset;
    uint32_t num_symbols;
    uint16_t optional_header_size;
    uint16_t characteristics;
} pe_coff_header_t;

/* Data directory entry */
typedef struct {
    uint32_t rva;
    uint32_t size;
} pe_data_dir_t;

/* Optional header (unified PE32/PE32+) */
typedef struct {
    uint16_t magic;
    uint8_t  major_linker;
    uint8_t  minor_linker;
    uint32_t size_of_code;
    uint32_t size_of_init_data;
    uint32_t size_of_uninit_data;
    uint32_t entry_point_rva;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserve;
    uint64_t stack_commit;
    uint64_t heap_reserve;
    uint64_t heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
    pe_data_dir_t data_dirs[PE_NUM_DATA_DIRS];
    int      is_pe32plus;
} pe_optional_header_t;

/* Section header */
typedef struct {
    char     short_name[9];
    char    *resolved_name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_data_size;
    uint32_t raw_data_offset;
    uint32_t reloc_offset;
    uint32_t linenum_offset;
    uint16_t num_relocs;
    uint16_t num_linenums;
    uint32_t characteristics;
    uint8_t *data;
    size_t   data_size;
    int      data_owned;
} pe_section_t;

/* Section table */
typedef struct {
    pe_section_t *entries;
    uint32_t      count;
    uint32_t      capacity;
} pe_section_table_t;

/* String table (COFF string table after symbol table) */
typedef struct {
    uint8_t  *data;
    uint32_t  size;
    char    **entries;
    uint32_t  num_entries;
    uint32_t  entries_capacity;
} pe_string_table_t;

/* COFF symbol */
typedef struct {
    char     short_name[9];
    char    *resolved_name;
    uint32_t value;
    int16_t  section_number;
    uint16_t type;
    uint8_t  storage_class;
    uint8_t  aux_count;
    uint32_t index;
} pe_symbol_t;

/* Symbol table */
typedef struct {
    pe_symbol_t *entries;
    uint32_t     count;
    uint32_t     capacity;
} pe_symbol_table_t;

/* Import thunk entry */
typedef struct {
    int      is_ordinal;
    uint16_t ordinal;
    uint16_t hint;
    char    *name;
    uint32_t thunk_rva;
} pe_import_thunk_t;

/* Import descriptor */
typedef struct {
    uint32_t           ilt_rva;
    uint32_t           timestamp;
    uint32_t           forwarder_chain;
    uint32_t           name_rva;
    char              *dll_name;
    uint32_t           iat_rva;
    pe_import_thunk_t *thunks;
    uint32_t           num_thunks;
    uint32_t           thunks_capacity;
} pe_import_descriptor_t;

/* Import table */
typedef struct {
    pe_import_descriptor_t *descriptors;
    uint32_t                count;
    uint32_t                capacity;
} pe_import_table_t;

/* Export entry */
typedef struct {
    uint32_t function_rva;
    char    *name;
    uint16_t ordinal;
    uint16_t name_ordinal;
    char    *forwarder;
    int      is_forwarder;
    int      has_name;
} pe_export_entry_t;

/* Export table */
typedef struct {
    uint32_t          characteristics;
    uint32_t          timestamp;
    uint16_t          major_version;
    uint16_t          minor_version;
    char             *dll_name;
    uint32_t          ordinal_base;
    pe_export_entry_t *entries;
    uint32_t          num_functions;
    uint32_t          num_names;
    uint32_t          entries_capacity;
} pe_export_table_t;

/* Relocation entry */
typedef struct {
    uint16_t type;
    uint16_t offset;
    uint32_t target_rva;
    uint8_t *target_ptr;
    int      resolved;
} pe_reloc_entry_t;

/* Relocation block */
typedef struct {
    uint32_t         page_rva;
    uint32_t         block_size;
    pe_reloc_entry_t *entries;
    uint32_t         count;
    uint32_t         capacity;
} pe_reloc_block_t;

/* Relocation table */
typedef struct {
    pe_reloc_block_t *blocks;
    uint32_t          count;
    uint32_t          capacity;
} pe_reloc_table_t;

/* CodeView debug info (type 2) */
typedef struct {
    uint32_t cv_signature;
    uint8_t  guid[16];
    uint32_t age;
    char    *pdb_path;
} pe_codeview_info_t;

/* Debug directory entry */
typedef struct {
    uint32_t          characteristics;
    uint32_t          timestamp;
    uint16_t          major_version;
    uint16_t          minor_version;
    uint32_t          type;
    uint32_t          data_size;
    uint32_t          address_rva;
    uint32_t          raw_data_offset;
    pe_codeview_info_t *codeview;
    int               section_index;
} pe_debug_entry_t;

/* Debug table */
typedef struct {
    pe_debug_entry_t *entries;
    uint32_t          count;
    uint32_t          capacity;
} pe_debug_table_t;

/* Forward declaration for recursive resource tree */
typedef struct pe_resource_node pe_resource_node_t;

/* Resource directory node */
struct pe_resource_node {
    int                  is_named;
    uint32_t             id;
    char                *name;
    int                  is_directory;
    pe_resource_node_t  *children;
    uint32_t             num_children;
    uint32_t             children_capacity;
    uint32_t             data_rva;
    uint32_t             data_size;
    uint32_t             codepage;
    uint8_t             *data_ptr;
    uint32_t             depth;
};

/* Resource tree */
typedef struct {
    pe_resource_node_t  *root;
    pe_resource_node_t **flat_entries;
    uint32_t             flat_count;
    uint32_t             flat_capacity;
} pe_resource_tree_t;

/* Delay import thunk */
typedef struct {
    int      is_ordinal;
    uint16_t ordinal;
    uint16_t hint;
    char    *name;
} pe_delay_thunk_t;

/* Delay import descriptor */
typedef struct {
    uint32_t           attributes;
    uint32_t           name_rva;
    uint32_t           module_handle_rva;
    uint32_t           iat_rva;
    uint32_t           int_rva;
    uint32_t           bound_iat_rva;
    uint32_t           unload_iat_rva;
    uint32_t           timestamp;
    char              *dll_name;
    pe_delay_thunk_t  *thunks;
    uint32_t           num_thunks;
    uint32_t           thunks_capacity;
    uint32_t           name_section;
    uint32_t           iat_section;
} pe_delay_import_desc_t;

/* Delay import table */
typedef struct {
    pe_delay_import_desc_t *descriptors;
    uint32_t                count;
    uint32_t                capacity;
} pe_delay_import_table_t;

/* Unwind code (x64 exception handling) */
typedef struct {
    uint8_t  offset_in_prolog;
    uint8_t  operation;
    uint8_t  op_info;
    uint32_t extra_value;
} pe_unwind_code_t;

/* Unwind info (x64 UNWIND_INFO structure) */
typedef struct {
    uint8_t           version;
    uint8_t           flags;
    uint8_t           prolog_size;
    uint8_t           code_count;
    uint8_t           frame_register;
    uint8_t           frame_offset;
    pe_unwind_code_t *codes;
    uint32_t          parsed_code_count;
    uint32_t          codes_capacity;
    uint32_t          handler_rva;
    int               has_handler;
    uint32_t          chained_begin;
    uint32_t          chained_end;
    uint32_t          chained_unwind;
    int               is_chained;
} pe_unwind_info_t;

/* Exception table entry (RUNTIME_FUNCTION on x64) */
typedef struct {
    uint32_t         begin_rva;
    uint32_t         end_rva;
    uint32_t         unwind_rva;
    pe_unwind_info_t unwind;
    uint32_t         code_section;
    uint32_t         handler_section;
} pe_exception_entry_t;

/* Exception table */
typedef struct {
    pe_exception_entry_t *entries;
    uint32_t              count;
    uint32_t              capacity;
    int                   is_sorted;
    uint32_t              total_code_size;
    uint32_t              max_function_size;
    uint32_t              min_function_size;
    uint32_t              handler_count;
    uint32_t              chained_count;
} pe_exception_table_t;

/* Import name cache entry */
typedef struct {
    uint32_t descriptor_index;
    uint32_t thunk_index;
    char    *name_ptr;
    char    *dll_name_ptr;
} pe_import_cache_entry_t;

/* Export name cache entry */
typedef struct {
    uint32_t export_index;
    char    *name_ptr;
    char    *forwarder_ptr;
    uint16_t ordinal;
} pe_export_cache_entry_t;

/* Relocation target cache entry */
typedef struct {
    uint32_t block_index;
    uint32_t entry_index;
    uint8_t *target_ptr;
    uint32_t section_index;
} pe_reloc_cache_entry_t;

/* Debug mapping cache entry */
typedef struct {
    uint32_t section_index;
    pe_debug_entry_t *debug_entry;
    char    *pdb_path_ptr;
} pe_debug_cache_entry_t;

/* Symbol name cache entry */
typedef struct {
    uint32_t symbol_index;
    char    *name_ptr;
    int16_t  section_number;
} pe_symbol_cache_entry_t;

/* Resource name cache entry */
typedef struct {
    uint32_t flat_index;
    char    *name_ptr;
    uint32_t type_id;
    uint32_t data_size;
} pe_resource_cache_entry_t;

/* Unified cache */
typedef struct {
    pe_import_cache_entry_t   *import_entries;
    uint32_t                   import_count;
    uint32_t                   import_capacity;

    pe_export_cache_entry_t   *export_entries;
    uint32_t                   export_count;
    uint32_t                   export_capacity;

    pe_reloc_cache_entry_t    *reloc_entries;
    uint32_t                   reloc_count;
    uint32_t                   reloc_capacity;

    pe_debug_cache_entry_t    *debug_entries;
    uint32_t                   debug_count;
    uint32_t                   debug_capacity;

    pe_symbol_cache_entry_t   *symbol_entries;
    uint32_t                   symbol_count;
    uint32_t                   symbol_capacity;

    pe_resource_cache_entry_t *resource_entries;
    uint32_t                   resource_count;
    uint32_t                   resource_capacity;

    char **section_names;
    uint32_t section_name_count;

    int built;
} pe_cache_t;

/* Cross-reference resolution state */
typedef struct {
    int imports_resolved;
    int exports_resolved;
    int relocs_applied;
    int debug_mapped;
    int symbols_resolved;
    int resources_resolved;
    int cross_refs_done;
    uint32_t resolved_import_count;
    uint32_t resolved_export_count;
    uint32_t applied_reloc_count;
    uint32_t mapped_debug_count;
    uint32_t resolved_symbol_count;
    uint32_t resolved_resource_count;
} pe_resolve_state_t;

/* Validation report entry */
typedef struct {
    int      severity;
    uint32_t section_index;
    char     message[128];
} pe_validation_issue_t;

/* Main library context */
typedef struct {
    const uint8_t        *data;
    size_t                size;

    pe_error_t            last_error;
    char                  error_msg[256];
    int                   error_count;
    int                   warning_count;
    int                   nonfatal_errors;

    pe_dos_header_t       dos;
    pe_coff_header_t      coff;
    pe_optional_header_t  optional;
    pe_section_table_t    sections;
    pe_string_table_t     strings;
    pe_symbol_table_t     symbols;
    pe_import_table_t     imports;
    pe_export_table_t     exports;
    pe_reloc_table_t      relocs;
    pe_debug_table_t      debug;
    pe_resource_tree_t    resources;
    pe_exception_table_t  exceptions;
    pe_delay_import_table_t delay_imports;
    pe_cache_t            cache;
    pe_resolve_state_t    resolve_state;

    pe_validation_issue_t *issues;
    uint32_t              issue_count;
    uint32_t              issue_capacity;

    int parsed;
    int validated;
    int resolved;
} pe_ctx_t;

/* ----------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------- */

/* Core lifecycle */
pe_ctx_t   *pe_open(const uint8_t *data, size_t size);
void        pe_close(pe_ctx_t *ctx);
pe_error_t  pe_get_error(const pe_ctx_t *ctx);
const char *pe_get_error_message(const pe_ctx_t *ctx);
const char *pe_error_string(pe_error_t err);

/* Header access */
const pe_dos_header_t      *pe_get_dos_header(const pe_ctx_t *ctx);
const pe_coff_header_t     *pe_get_coff_header(const pe_ctx_t *ctx);
const pe_optional_header_t *pe_get_optional_header(const pe_ctx_t *ctx);
const char *pe_get_machine_name(uint16_t machine);
const char *pe_get_subsystem_name(uint16_t subsystem);

/* Section access */
uint32_t              pe_get_section_count(const pe_ctx_t *ctx);
const pe_section_t   *pe_get_section(const pe_ctx_t *ctx, uint32_t index);
const char           *pe_get_section_name(const pe_ctx_t *ctx, uint32_t index);
const pe_section_t   *pe_find_section_by_name(const pe_ctx_t *ctx, const char *name);
const pe_section_t   *pe_find_section_by_rva(const pe_ctx_t *ctx, uint32_t rva);
uint32_t              pe_rva_to_offset(const pe_ctx_t *ctx, uint32_t rva);
const uint8_t        *pe_rva_to_ptr(const pe_ctx_t *ctx, uint32_t rva, size_t min_size);

/* String table access */
const char *pe_get_string(const pe_ctx_t *ctx, uint32_t offset);

/* Symbol access */
uint32_t             pe_get_symbol_count(const pe_ctx_t *ctx);
const pe_symbol_t   *pe_get_symbol(const pe_ctx_t *ctx, uint32_t index);
const char          *pe_get_symbol_name(const pe_ctx_t *ctx, uint32_t index);
const char          *pe_get_symbol_class_name(uint8_t storage_class);

/* Import access */
uint32_t                      pe_get_import_descriptor_count(const pe_ctx_t *ctx);
const pe_import_descriptor_t *pe_get_import_descriptor(const pe_ctx_t *ctx, uint32_t index);
const char                   *pe_get_import_dll_name(const pe_ctx_t *ctx, uint32_t desc_index);
uint32_t                      pe_get_import_thunk_count(const pe_ctx_t *ctx, uint32_t desc_index);
const pe_import_thunk_t      *pe_get_import_thunk(const pe_ctx_t *ctx, uint32_t desc_index,
                                                   uint32_t thunk_index);

/* Export access */
uint32_t                pe_get_export_count(const pe_ctx_t *ctx);
const pe_export_entry_t *pe_get_export(const pe_ctx_t *ctx, uint32_t index);
const pe_export_entry_t *pe_find_export_by_name(const pe_ctx_t *ctx, const char *name);
const pe_export_entry_t *pe_find_export_by_ordinal(const pe_ctx_t *ctx, uint16_t ordinal);
const char              *pe_get_export_dll_name(const pe_ctx_t *ctx);

/* Relocation access */
uint32_t                pe_get_reloc_block_count(const pe_ctx_t *ctx);
const pe_reloc_block_t *pe_get_reloc_block(const pe_ctx_t *ctx, uint32_t index);

/* Debug access */
uint32_t                pe_get_debug_entry_count(const pe_ctx_t *ctx);
const pe_debug_entry_t *pe_get_debug_entry(const pe_ctx_t *ctx, uint32_t index);
const char             *pe_get_debug_type_name(uint32_t type);
const char             *pe_get_pdb_path(const pe_ctx_t *ctx, uint32_t index);

/* Resource access */
const pe_resource_node_t *pe_get_resource_root(const pe_ctx_t *ctx);
uint32_t                  pe_get_resource_count(const pe_ctx_t *ctx);
const pe_resource_node_t *pe_get_resource_entry(const pe_ctx_t *ctx, uint32_t flat_index);
const char               *pe_get_resource_type_name(uint32_t type_id);
const char               *pe_query_resource_name(const pe_ctx_t *ctx, uint32_t flat_index);

/* Validation and resolution access */
uint32_t pe_get_issue_count(const pe_ctx_t *ctx);
const pe_validation_issue_t *pe_get_issue(const pe_ctx_t *ctx, uint32_t index);

/* Formatting utilities */
int  pe_format_characteristics(uint32_t chars, char *buf, size_t bufsz);
int  pe_format_section_flags(uint32_t chars, char *buf, size_t bufsz);
int  pe_format_dll_characteristics(uint16_t chars, char *buf, size_t bufsz);
int  pe_format_timestamp(uint32_t timestamp, char *buf, size_t bufsz);
int  pe_format_guid(const uint8_t *guid, char *buf, size_t bufsz);
int  pe_format_machine(uint16_t machine, char *buf, size_t bufsz);
int  pe_format_data_dir_name(uint32_t index, char *buf, size_t bufsz);
int  pe_format_hex_dump(const uint8_t *data, size_t len, char *buf, size_t bufsz);

/* Delay imports */
uint32_t pe_get_delay_import_count(const pe_ctx_t *ctx);
const pe_delay_import_desc_t *pe_get_delay_import(const pe_ctx_t *ctx, uint32_t index);
const char *pe_get_delay_import_dll_name(const pe_ctx_t *ctx, uint32_t index);
uint32_t pe_get_delay_thunk_count(const pe_ctx_t *ctx, uint32_t desc_index);
const pe_delay_thunk_t *pe_get_delay_thunk(const pe_ctx_t *ctx, uint32_t d, uint32_t t);

/* Exception table */
uint32_t pe_get_exception_count(const pe_ctx_t *ctx);
const pe_exception_entry_t *pe_get_exception_entry(const pe_ctx_t *ctx, uint32_t index);
const pe_exception_entry_t *pe_find_exception_by_rva(const pe_ctx_t *ctx, uint32_t rva);
const char *pe_get_x64_register_name(uint8_t reg);
const char *pe_get_unwind_op_name(uint8_t opcode);

/* Checksum */
uint32_t pe_compute_checksum(const uint8_t *data, size_t size, uint32_t checksum_offset);
int      pe_verify_checksum(const pe_ctx_t *ctx);

/* Iterator helpers */
typedef int (*pe_section_callback_t)(const pe_ctx_t *ctx, uint32_t index,
                                      const pe_section_t *section, void *user);
typedef int (*pe_import_callback_t)(const pe_ctx_t *ctx, uint32_t desc_index,
                                     uint32_t thunk_index,
                                     const pe_import_thunk_t *thunk, void *user);
typedef int (*pe_export_callback_t)(const pe_ctx_t *ctx, uint32_t index,
                                     const pe_export_entry_t *entry, void *user);
typedef int (*pe_resource_callback_t)(const pe_ctx_t *ctx, uint32_t flat_index,
                                      const pe_resource_node_t *node, void *user);

int pe_iterate_sections(const pe_ctx_t *ctx, pe_section_callback_t cb, void *user);
int pe_iterate_imports(const pe_ctx_t *ctx, pe_import_callback_t cb, void *user);
int pe_iterate_exports(const pe_ctx_t *ctx, pe_export_callback_t cb, void *user);
int pe_iterate_resources(const pe_ctx_t *ctx, pe_resource_callback_t cb, void *user);

/* Statistics */
typedef struct {
    uint32_t total_sections;
    uint32_t code_sections;
    uint32_t data_sections;
    uint64_t total_raw_size;
    uint64_t total_virtual_size;
    uint32_t total_imports;
    uint32_t total_import_dlls;
    uint32_t total_exports;
    uint32_t total_forwarders;
    uint32_t total_reloc_entries;
    uint32_t total_symbols;
    uint32_t total_resources;
    uint32_t total_debug_entries;
    uint32_t validation_issues;
    uint32_t validation_warnings;
    uint32_t validation_errors;
} pe_stats_t;

int pe_compute_stats(const pe_ctx_t *ctx, pe_stats_t *stats);

/* Section property queries */
int      pe_section_is_executable(const pe_section_t *sec);
int      pe_section_is_writable(const pe_section_t *sec);
int      pe_section_is_readable(const pe_section_t *sec);
int      pe_section_contains_code(const pe_section_t *sec);
int      pe_section_contains_data(const pe_section_t *sec);
uint32_t pe_section_get_alignment(const pe_section_t *sec);

/* Image property queries */
int      pe_is_dll(const pe_ctx_t *ctx);
int      pe_is_executable(const pe_ctx_t *ctx);
int      pe_is_64bit(const pe_ctx_t *ctx);
int      pe_has_aslr(const pe_ctx_t *ctx);
int      pe_has_dep(const pe_ctx_t *ctx);
int      pe_has_cfg(const pe_ctx_t *ctx);
int      pe_has_seh(const pe_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* PECTRA_H */
