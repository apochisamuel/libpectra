/*
 * format.c — Formatting Utilities
 *
 * Provides human-readable string formatting for PE characteristics
 * flags, section flags, DLL characteristics, timestamps, GUIDs,
 * machine types, data directory names, and hex dumps.
 */

#include "internal.h"
#include <time.h>

/* Append a flag name to a buffer with '|' separator */
static int pe_append_flag(char *buf, size_t bufsz, size_t *pos,
                           const char *name)
{
    size_t len = strlen(name);
    if (*pos > 0) {
        if (*pos + 3 > bufsz) {
            return 0;
        }
        buf[*pos] = ' ';
        buf[*pos + 1] = '|';
        buf[*pos + 2] = ' ';
        *pos += 3;
    }
    if (*pos + len >= bufsz) {
        return 0;
    }
    memcpy(buf + *pos, name, len);
    *pos += len;
    buf[*pos] = '\0';
    return 1;
}

/*
 * Format COFF file characteristics into a human-readable string.
 */
int pe_format_characteristics(uint32_t chars, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return -1;
    }
    buf[0] = '\0';
    size_t pos = 0;

    if (chars & 0x0001) pe_append_flag(buf, bufsz, &pos, "RELOCS_STRIPPED");
    if (chars & 0x0002) pe_append_flag(buf, bufsz, &pos, "EXECUTABLE");
    if (chars & 0x0004) pe_append_flag(buf, bufsz, &pos, "LINE_NUMS_STRIPPED");
    if (chars & 0x0008) pe_append_flag(buf, bufsz, &pos, "LOCAL_SYMS_STRIPPED");
    if (chars & 0x0010) pe_append_flag(buf, bufsz, &pos, "AGGRESSIVE_WS_TRIM");
    if (chars & 0x0020) pe_append_flag(buf, bufsz, &pos, "LARGE_ADDRESS_AWARE");
    if (chars & 0x0080) pe_append_flag(buf, bufsz, &pos, "BYTES_REVERSED_LO");
    if (chars & 0x0100) pe_append_flag(buf, bufsz, &pos, "32BIT_MACHINE");
    if (chars & 0x0200) pe_append_flag(buf, bufsz, &pos, "DEBUG_STRIPPED");
    if (chars & 0x0400) pe_append_flag(buf, bufsz, &pos, "REMOVABLE_RUN_FROM_SWAP");
    if (chars & 0x0800) pe_append_flag(buf, bufsz, &pos, "NET_RUN_FROM_SWAP");
    if (chars & 0x1000) pe_append_flag(buf, bufsz, &pos, "SYSTEM");
    if (chars & 0x2000) pe_append_flag(buf, bufsz, &pos, "DLL");
    if (chars & 0x4000) pe_append_flag(buf, bufsz, &pos, "UP_SYSTEM_ONLY");
    if (chars & 0x8000) pe_append_flag(buf, bufsz, &pos, "BYTES_REVERSED_HI");

    if (pos == 0) {
        snprintf(buf, bufsz, "(none)");
    }

    return (int)pos;
}

/*
 * Format section characteristics into a human-readable string.
 */
int pe_format_section_flags(uint32_t chars, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return -1;
    }
    buf[0] = '\0';
    size_t pos = 0;

    if (chars & PE_SCN_CNT_CODE)
        pe_append_flag(buf, bufsz, &pos, "CODE");
    if (chars & PE_SCN_CNT_INIT_DATA)
        pe_append_flag(buf, bufsz, &pos, "INITIALIZED_DATA");
    if (chars & PE_SCN_CNT_UNINIT_DATA)
        pe_append_flag(buf, bufsz, &pos, "UNINITIALIZED_DATA");
    if (chars & PE_SCN_MEM_EXECUTE)
        pe_append_flag(buf, bufsz, &pos, "EXECUTE");
    if (chars & PE_SCN_MEM_READ)
        pe_append_flag(buf, bufsz, &pos, "READ");
    if (chars & PE_SCN_MEM_WRITE)
        pe_append_flag(buf, bufsz, &pos, "WRITE");
    if (chars & PE_SCN_MEM_DISCARDABLE)
        pe_append_flag(buf, bufsz, &pos, "DISCARDABLE");
    if (chars & PE_SCN_MEM_SHARED)
        pe_append_flag(buf, bufsz, &pos, "SHARED");

    /* Section alignment */
    uint32_t align = (chars & PE_SCN_ALIGN_MASK) >> 20;
    if (align > 0) {
        char align_str[32];
        snprintf(align_str, sizeof(align_str), "ALIGN_%u", 1u << (align - 1));
        pe_append_flag(buf, bufsz, &pos, align_str);
    }

    if (pos == 0) {
        snprintf(buf, bufsz, "(none)");
    }

    return (int)pos;
}

/*
 * Format DLL characteristics into a human-readable string.
 */
int pe_format_dll_characteristics(uint16_t chars, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return -1;
    }
    buf[0] = '\0';
    size_t pos = 0;

    if (chars & PE_DLLCHAR_HIGH_ENTROPY_VA)
        pe_append_flag(buf, bufsz, &pos, "HIGH_ENTROPY_VA");
    if (chars & PE_DLLCHAR_DYNAMIC_BASE)
        pe_append_flag(buf, bufsz, &pos, "DYNAMIC_BASE");
    if (chars & PE_DLLCHAR_FORCE_INTEGRITY)
        pe_append_flag(buf, bufsz, &pos, "FORCE_INTEGRITY");
    if (chars & PE_DLLCHAR_NX_COMPAT)
        pe_append_flag(buf, bufsz, &pos, "NX_COMPAT");
    if (chars & PE_DLLCHAR_NO_ISOLATION)
        pe_append_flag(buf, bufsz, &pos, "NO_ISOLATION");
    if (chars & PE_DLLCHAR_NO_SEH)
        pe_append_flag(buf, bufsz, &pos, "NO_SEH");
    if (chars & PE_DLLCHAR_NO_BIND)
        pe_append_flag(buf, bufsz, &pos, "NO_BIND");
    if (chars & PE_DLLCHAR_APPCONTAINER)
        pe_append_flag(buf, bufsz, &pos, "APPCONTAINER");
    if (chars & PE_DLLCHAR_WDM_DRIVER)
        pe_append_flag(buf, bufsz, &pos, "WDM_DRIVER");
    if (chars & PE_DLLCHAR_GUARD_CF)
        pe_append_flag(buf, bufsz, &pos, "GUARD_CF");
    if (chars & PE_DLLCHAR_TERMINAL_SERVER)
        pe_append_flag(buf, bufsz, &pos, "TERMINAL_SERVER_AWARE");

    if (pos == 0) {
        snprintf(buf, bufsz, "(none)");
    }

    return (int)pos;
}

/*
 * Format a COFF/PE timestamp to ISO 8601 string.
 */
int pe_format_timestamp(uint32_t timestamp, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return -1;
    }

    if (timestamp == 0 || timestamp == 0xFFFFFFFF) {
        snprintf(buf, bufsz, "(not set)");
        return (int)strlen(buf);
    }

    time_t t = (time_t)timestamp;
    struct tm *tm = gmtime(&t);
    if (!tm) {
        snprintf(buf, bufsz, "0x%08X", timestamp);
        return (int)strlen(buf);
    }

    int len = snprintf(buf, bufsz, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);

    return len;
}

/*
 * Format a 16-byte GUID to standard string representation.
 * Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
 */
int pe_format_guid(const uint8_t *guid, char *buf, size_t bufsz)
{
    if (!guid || !buf || bufsz == 0) {
        return -1;
    }

    /* GUID is stored in mixed-endian format per Microsoft convention */
    uint32_t data1 = PE_READ_U32(guid);
    uint16_t data2 = PE_READ_U16(guid + 4);
    uint16_t data3 = PE_READ_U16(guid + 6);

    int len = snprintf(buf, bufsz,
                       "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                       data1, data2, data3,
                       guid[8], guid[9],
                       guid[10], guid[11], guid[12],
                       guid[13], guid[14], guid[15]);

    return len;
}

/*
 * Format machine type to string.
 */
int pe_format_machine(uint16_t machine, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return -1;
    }
    const char *name = pe_get_machine_name(machine);
    int len = snprintf(buf, bufsz, "%s (0x%04X)", name, machine);
    return len;
}

/*
 * Format a data directory index to its standard name.
 */
int pe_format_data_dir_name(uint32_t index, char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return -1;
    }

    const char *name;
    switch (index) {
    case PE_DIR_EXPORT:       name = "Export Table"; break;
    case PE_DIR_IMPORT:       name = "Import Table"; break;
    case PE_DIR_RESOURCE:     name = "Resource Table"; break;
    case PE_DIR_EXCEPTION:    name = "Exception Table"; break;
    case PE_DIR_SECURITY:     name = "Certificate Table"; break;
    case PE_DIR_BASERELOC:    name = "Base Relocation Table"; break;
    case PE_DIR_DEBUG:        name = "Debug"; break;
    case PE_DIR_ARCHITECTURE: name = "Architecture"; break;
    case PE_DIR_GLOBALPTR:    name = "Global Ptr"; break;
    case PE_DIR_TLS:          name = "TLS Table"; break;
    case PE_DIR_LOAD_CONFIG:  name = "Load Config Table"; break;
    case PE_DIR_BOUND_IMPORT: name = "Bound Import"; break;
    case PE_DIR_IAT:          name = "Import Address Table"; break;
    case PE_DIR_DELAY_IMPORT: name = "Delay Import Descriptor"; break;
    case PE_DIR_CLR_RUNTIME:  name = "CLR Runtime Header"; break;
    case PE_DIR_RESERVED:     name = "Reserved"; break;
    default:                  name = "Unknown"; break;
    }

    int len = snprintf(buf, bufsz, "%s", name);
    return len;
}

/*
 * Format a hex dump of binary data.
 * Produces output like: "4D 5A 90 00 03 00 00 00"
 */
int pe_format_hex_dump(const uint8_t *data, size_t len, char *buf, size_t bufsz)
{
    if (!data || !buf || bufsz == 0) {
        return -1;
    }

    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        if (pos + 4 > bufsz) {
            break;
        }
        if (i > 0) {
            buf[pos++] = ' ';
        }
        int written = snprintf(buf + pos, bufsz - pos, "%02X", data[i]);
        if (written > 0) {
            pos += (size_t)written;
        }
    }

    buf[pos] = '\0';
    return (int)pos;
}
