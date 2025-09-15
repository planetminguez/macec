#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#include <mach/vm_prot.h>
#include <libkern/OSByteOrder.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof((x)[0]))

// ANSI colors
#define COL_RED     "\x1b[31m"
#define COL_GREEN   "\x1b[32m"
#define COL_CYAN    "\x1b[36m"
#define COL_RESET   "\x1b[0m"

// Column widths for pretty table
#define W_ARCH     6
#define W_LINK     4
#define W_PIE      3
#define W_CANARY   6
#define W_NX       3
#define W_RPATH    5
#define W_CODESIG  7
#define W_ENC      3
#define W_LIBS     24

typedef struct {
    bool is_pie;
    bool has_canary;
    bool nx_enabled;           // true if no W+X segments
    bool has_rpath;
    bool code_signature;
    bool encrypted;
    bool is_dynamic;           // true if any LC_LOAD_*_DYLIB
    uint32_t filetype;         // MH_EXECUTE, MH_DYLIB, etc.
    // Linked shared libraries (install names)
    char **libs;
    size_t libs_count;
} sec_report_t;

typedef struct {
    bool force_pretty;
    bool force_plain;
    bool force_color;
    bool no_color;
} options_t;

typedef struct {
    char arch[16];
    sec_report_t rep;
} entry_t;

// Simple dynamic string list for collecting dylib names
typedef struct {
    char **items;
    size_t count;
    size_t cap;
} strlist_t;

static void strlist_push(strlist_t *l, const char *s) {
    if (!l) return;
    if (l->count == l->cap) {
        size_t new_cap = l->cap ? l->cap * 2 : 8;
        char **n = (char **)realloc(l->items, new_cap * sizeof(char*));
        if (!n) return; // out of memory; silently drop
        l->items = n;
        l->cap = new_cap;
    }
    l->items[l->count++] = s ? strdup(s) : strdup("");
}


static void free_report(sec_report_t *r) {
    if (!r) return;
    if (r->libs) {
        for (size_t i = 0; i < r->libs_count; i++) free(r->libs[i]);
        free(r->libs);
    }
    r->libs = NULL;
    r->libs_count = 0;
}

static const char *arch_name(cpu_type_t cputype, cpu_subtype_t cpusubtype) {
    (void)cpusubtype;
    switch (cputype) {
        case CPU_TYPE_X86: return "i386";
        case CPU_TYPE_X86_64: return "x86_64";
#ifdef CPU_TYPE_ARM
        case CPU_TYPE_ARM: return "arm";
#endif
#ifdef CPU_TYPE_ARM64
        case CPU_TYPE_ARM64: return "arm64";
#endif
        default: return "unknown";
    }
}

static void print_kv_plain(const char *path, const char *arch, const sec_report_t *r) {
    printf("File: %s (arch: %s)\n", path, arch);
    printf("  Type: %s\n", r->filetype == MH_EXECUTE ? "executable" : (r->filetype == MH_DYLIB ? "dylib" : (r->filetype == MH_BUNDLE ? "bundle" : "other")));
    printf("  Linkage: %s\n", r->is_dynamic ? "dynamic" : "static/none");
    printf("  PIE: %s\n", r->is_pie ? "enabled" : "disabled");
    printf("  Canary: %s\n", r->has_canary ? "enabled" : "absent/unknown");
    printf("  NX (no W+X): %s\n", r->nx_enabled ? "enabled" : "disabled (W+X segment present)");
    printf("  RPATH: %s\n", r->has_rpath ? "present" : "absent");
    printf("  Code Signed: %s\n", r->code_signature ? "present" : "absent");
    printf("  Encrypted: %s\n", r->encrypted ? "yes" : "no");
    printf("  Shared Libs: ");
    if (!r->libs_count) {
        printf("-\n");
    } else {
        for (size_t i = 0; i < r->libs_count; i++) {
            printf("%s%s", i ? ", " : "", r->libs[i]);
        }
        putchar('\n');
    }
}

static void print_border(bool use_color) {
    (void)use_color;
    printf("+-%-*s-+-%-*s-+-%-*s-+-%-*s-+-%-*s-+-%-*s-+-%-*s-+-%-*s-+-%-*s-+\n",
           W_ARCH, "", W_LINK, "", W_PIE, "", W_CANARY, "", W_NX, "", W_RPATH, "", W_CODESIG, "", W_ENC, "", W_LIBS, "");
}

static void summarize_libs(const sec_report_t *r, char *out, size_t outsz) {
    if (outsz == 0) return;
    out[0] = '\0';
    if (!r || r->libs_count == 0) {
        snprintf(out, outsz, "-");
        return;
    }
    size_t used = 0;
    for (size_t i = 0; i < r->libs_count; i++) {
        const char *s = r->libs[i];
        size_t need = (i ? 2 : 0) + strlen(s);
        if (used + need >= outsz) {
            if (used + 3 < outsz) {
                strcpy(out + used, "...");
            }
            return;
        }
        if (i) { out[used++] = ','; out[used++] = ' '; }
        strcpy(out + used, s);
        used += strlen(s);
    }
}

static void render_pretty_table(const char *path, const entry_t *entries, size_t count, bool use_color) {
    const char *hdr = use_color ? COL_RED : "";
    const char *row = use_color ? COL_GREEN : "";
    const char *rs  = use_color ? COL_RESET : "";
    const char *b   = ""; // uncolored borders (reverted)

    // Plain File label (reverted)
    printf("File: %s\n", path);

    print_border(use_color);
    // Header row with cyan borders and red text (compact labels)
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_ARCH, "Arch"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_LINK, "Link"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_PIE, "PIE"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_CANARY, "Canary"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_NX, "NX"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_RPATH, "RPATH"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_CODESIG, "CodeSig"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_ENC, "Enc"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
    fputc(' ', stdout); fputs(hdr, stdout); printf("%-*s", W_LIBS, "Shared Libs"); fputs(rs, stdout); fputc(' ', stdout);
    fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout); fputc('\n', stdout);
    print_border(use_color);
    for (size_t i = 0; i < count; i++) {
        const sec_report_t *r = &entries[i].rep;
        // Compact values to keep table skinny
        const char *pie_s = r->is_pie ? "on" : "off";
        const char *can_s = r->has_canary ? "on" : "no";
        const char *nx_s = r->nx_enabled ? "on" : "off";
        const char *rp_s = r->has_rpath ? "yes" : "no";
        const char *cs_s = r->code_signature ? "yes" : "no";
        const char *en_s = r->encrypted ? "yes" : "no";
        char libs_buf[W_LIBS * 2];
        summarize_libs(r, libs_buf, sizeof(libs_buf));

        // Data row with cyan borders and green text
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_ARCH, entries[i].arch); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        const char *link_s = entries[i].rep.is_dynamic ? "dyn" : "stat";
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_LINK, link_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_PIE, pie_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_CANARY, can_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_NX, nx_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_RPATH, rp_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_CODESIG, cs_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_ENC, en_s); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout);
        fputc(' ', stdout); fputs(row, stdout); printf("%-*s", W_LIBS, libs_buf); fputs(rs, stdout); fputc(' ', stdout);
        fputs(b, stdout); fputc('|', stdout); fputs(rs, stdout); fputc('\n', stdout);
    }
    print_border(use_color);
}

static bool check_canary_symbols_64(const uint8_t *base, size_t sz, const struct mach_header_64 *mh, const struct load_command *lc) {
    (void)sz;
    const struct symtab_command *sc = (const struct symtab_command *)lc;
    if (sc->symoff + sc->nsyms * sizeof(struct nlist_64) > sz || sc->stroff >= sz) return false;
    const struct nlist_64 *syms = (const struct nlist_64 *)(base + sc->symoff);
    const char *strtab = (const char *)(base + sc->stroff);
    // strsize bounds will be implicitly checked by non-zero and strcmp guarded by < strsize, but we’ll perform basic sanity.
    for (uint32_t i = 0; i < sc->nsyms; i++) {
        uint32_t strx = syms[i].n_un.n_strx;
        if (strx == 0) continue;
        if ((uint64_t)sc->stroff + strx >= sz) continue;
        const char *name = strtab + strx;
        // Undefined symbols have type N_UNDF (0x0), but also check external bit; still, presence is indicative.
        // Mach-O symbols are prefixed with '_'. Look for "___stack_chk_fail" or "___stack_chk_guard".
        if (name && (strcmp(name, "___stack_chk_fail") == 0 || strcmp(name, "___stack_chk_guard") == 0)) {
            (void)mh;
            return true;
        }
    }
    return false;
}

static bool check_canary_symbols_32(const uint8_t *base, size_t sz, const struct mach_header *mh, const struct load_command *lc) {
    (void)sz;
    const struct symtab_command *sc = (const struct symtab_command *)lc;
    if (sc->symoff + sc->nsyms * sizeof(struct nlist) > sz || sc->stroff >= sz) return false;
    const struct nlist *syms = (const struct nlist *)(base + sc->symoff);
    const char *strtab = (const char *)(base + sc->stroff);
    for (uint32_t i = 0; i < sc->nsyms; i++) {
        uint32_t strx = syms[i].n_un.n_strx;
        if (strx == 0) continue;
        if ((uint64_t)sc->stroff + strx >= sz) continue;
        const char *name = strtab + strx;
        if (name && (strcmp(name, "___stack_chk_fail") == 0 || strcmp(name, "___stack_chk_guard") == 0)) {
            (void)mh;
            return true;
        }
    }
    return false;
}

static int analyze_thin_64(const uint8_t *base, size_t sz, const char *display_path, sec_report_t *out) {
    if (sz < sizeof(struct mach_header_64)) return -1;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)base;
    if (mh->magic != MH_MAGIC_64) return -1;

    bool w_x_found = false;
    bool has_rpath = false;
    bool is_pie = (mh->flags & MH_PIE) != 0;
    bool code_sig = false;
    bool encrypted = false;
    bool has_canary = false;

    strlist_t libs = {0};

    const struct load_command *lc = (const struct load_command *)(base + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((const uint8_t *)lc + sizeof(struct load_command) > base + sz) break;
        switch (lc->cmd) {
            case LC_SEGMENT_64: {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                // Check for W+X in segment protections
                if ((seg->initprot & VM_PROT_EXECUTE) && (seg->initprot & VM_PROT_WRITE)) {
                    w_x_found = true;
                }
                break;
            }
            case LC_RPATH:
                has_rpath = true;
                break;
            case LC_CODE_SIGNATURE:
                code_sig = true;
                break;
            case LC_ENCRYPTION_INFO_64: {
                const struct encryption_info_command_64 *e = (const struct encryption_info_command_64 *)lc;
                if (e->cryptid != 0) encrypted = true;
                break;
            }
            case LC_SYMTAB:
                if (!has_canary) {
                    has_canary = check_canary_symbols_64(base, sz, mh, lc);
                }
                break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LAZY_LOAD_DYLIB: {
                const struct dylib_command *dc = (const struct dylib_command *)lc;
                uint32_t name_off = dc->dylib.name.offset;
                const uint8_t *p = (const uint8_t *)dc + name_off;
                if (p >= base && p < base + sz) {
                    const char *name = (const char *)p;
                    strlist_push(&libs, name);
                }
                break;
            }
            default:
                break;
        }
        if (lc->cmdsize == 0) break; // avoid infinite loop on malformed
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
        if ((const uint8_t *)lc > base + sz) break;
    }

    out->is_pie = is_pie;
    out->has_canary = has_canary;
    out->nx_enabled = !w_x_found;
    out->has_rpath = has_rpath;
    out->code_signature = code_sig;
    out->encrypted = encrypted;
    out->libs_count = libs.count;
    out->libs = libs.items;
    out->is_dynamic = libs.count > 0;
    out->filetype = mh->filetype;

    (void)display_path;
    return 0;

    (void)display_path;
    return 0;

    (void)display_path;
    return 0;
}

static int analyze_thin_32(const uint8_t *base, size_t sz, const char *display_path, sec_report_t *out) {
    if (sz < sizeof(struct mach_header)) return -1;
    const struct mach_header *mh = (const struct mach_header *)base;
    if (mh->magic != MH_MAGIC) return -1;

    bool w_x_found = false;
    bool has_rpath = false;
    bool is_pie = (mh->flags & MH_PIE) != 0;
    bool code_sig = false;
    bool encrypted = false;
    bool has_canary = false;

    strlist_t libs = {0};

    const struct load_command *lc = (const struct load_command *)(base + sizeof(struct mach_header));
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((const uint8_t *)lc + sizeof(struct load_command) > base + sz) break;
        switch (lc->cmd) {
            case LC_SEGMENT: {
                const struct segment_command *seg = (const struct segment_command *)lc;
                if ((seg->initprot & VM_PROT_EXECUTE) && (seg->initprot & VM_PROT_WRITE)) {
                    w_x_found = true;
                }
                break;
            }
            case LC_RPATH:
                has_rpath = true;
                break;
            case LC_CODE_SIGNATURE:
                code_sig = true;
                break;
            case LC_ENCRYPTION_INFO: {
                const struct encryption_info_command *e = (const struct encryption_info_command *)lc;
                if (e->cryptid != 0) encrypted = true;
                break;
            }
            case LC_SYMTAB:
                if (!has_canary) {
                    has_canary = check_canary_symbols_32(base, sz, mh, lc);
                }
                break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LAZY_LOAD_DYLIB: {
                const struct dylib_command *dc = (const struct dylib_command *)lc;
                uint32_t name_off = dc->dylib.name.offset;
                const uint8_t *p = (const uint8_t *)dc + name_off;
                if (p >= base && p < base + sz) {
                    const char *name = (const char *)p;
                    strlist_push(&libs, name);
                }
                break;
            }
            default:
                break;
        }
        if (lc->cmdsize == 0) break;
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
        if ((const uint8_t *)lc > base + sz) break;
    }

    out->is_pie = is_pie;
    out->has_canary = has_canary;
    out->nx_enabled = !w_x_found;
    out->has_rpath = has_rpath;
    out->code_signature = code_sig;
    out->encrypted = encrypted;

    (void)display_path;
    return 0;
}

static int analyze_thin(const uint8_t *base, size_t sz, const char *display_path, const char *arch, sec_report_t *out) {
    (void)arch;
    if (sz < sizeof(uint32_t)) return -1;
    uint32_t magic = *(const uint32_t *)base;
    if (magic == MH_MAGIC_64) {
        return analyze_thin_64(base, sz, display_path, out);
    } else if (magic == MH_MAGIC) {
        return analyze_thin_32(base, sz, display_path, out);
    } else {
        return -1;
    }
}

static int analyze_path_with_opts(const char *path, const options_t *opt) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening %s: %s\n", path, strerror(errno));
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Error fstat %s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }
    if (st.st_size < 4) {
        fprintf(stderr, "File too small: %s\n", path);
        close(fd);
        return 1;
    }

    size_t sz = (size_t)st.st_size;
    void *map = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        fprintf(stderr, "mmap failed for %s: %s\n", path, strerror(errno));
        return 1;
    }

    const uint8_t *base = (const uint8_t *)map;
    uint32_t magic = *(const uint32_t *)base;

    bool use_color = opt->force_color || (!opt->no_color && isatty(STDOUT_FILENO));
    bool pretty = opt->force_pretty || (!opt->force_plain && isatty(STDOUT_FILENO));

    if (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        bool swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
            if (sz < sizeof(struct fat_header)) { munmap(map, sz); return 1; }
            const struct fat_header *fh = (const struct fat_header *)base;
            uint32_t nfat = swap ? OSSwapBigToHostInt32(fh->nfat_arch) : fh->nfat_arch;
            size_t off = sizeof(struct fat_header);
            if (sz < off + nfat * sizeof(struct fat_arch)) { munmap(map, sz); return 1; }
            const struct fat_arch *fa = (const struct fat_arch *)(base + off);
            entry_t *entries = (entry_t *)calloc(nfat, sizeof(entry_t));
            size_t count = 0;
            for (uint32_t i = 0; i < nfat; i++) {
                cpu_type_t cputype = swap ? OSSwapBigToHostInt32(fa[i].cputype) : fa[i].cputype;
                uint32_t offset = swap ? OSSwapBigToHostInt32(fa[i].offset) : fa[i].offset;
                uint32_t size = swap ? OSSwapBigToHostInt32(fa[i].size) : fa[i].size;
                if ((uint64_t)offset + size > sz) continue;
                sec_report_t rep = {0};
                if (analyze_thin(base + offset, size, path, arch_name(cputype, 0), &rep) == 0) {
                    snprintf(entries[count].arch, sizeof(entries[count].arch), "%s", arch_name(cputype, 0));
                    entries[count].rep = rep;
                    count++;
                }
            }
            if (pretty && count > 0) {
                render_pretty_table(path, entries, count, use_color);
            } else {
                for (size_t i = 0; i < count; i++) {
                    print_kv_plain(path, entries[i].arch, &entries[i].rep);
                }
            }
            // free per-entry libs
            for (size_t i = 0; i < count; i++) {
                free_report(&entries[i].rep);
            }
            free(entries);
        } else {
            // FAT_64
            if (sz < sizeof(struct fat_header)) { munmap(map, sz); return 1; }
            const struct fat_header *fh = (const struct fat_header *)base;
            uint32_t nfat = swap ? OSSwapBigToHostInt32(fh->nfat_arch) : fh->nfat_arch;
            size_t off = sizeof(struct fat_header);
            if (sz < off + nfat * sizeof(struct fat_arch_64)) { munmap(map, sz); return 1; }
            const struct fat_arch_64 *fa = (const struct fat_arch_64 *)(base + off);
            entry_t *entries = (entry_t *)calloc(nfat, sizeof(entry_t));
            size_t count = 0;
            for (uint32_t i = 0; i < nfat; i++) {
                cpu_type_t cputype = swap ? OSSwapBigToHostInt32(fa[i].cputype) : fa[i].cputype;
                uint64_t offset = swap ? OSSwapBigToHostInt64(fa[i].offset) : fa[i].offset;
                uint64_t size = swap ? OSSwapBigToHostInt64(fa[i].size) : fa[i].size;
                if (offset + size > sz) continue;
                sec_report_t rep = {0};
                if (analyze_thin(base + offset, (size_t)size, path, arch_name(cputype, 0), &rep) == 0) {
                    snprintf(entries[count].arch, sizeof(entries[count].arch), "%s", arch_name(cputype, 0));
                    entries[count].rep = rep;
                    count++;
                }
            }
            if (pretty && count > 0) {
                render_pretty_table(path, entries, count, use_color);
            } else {
                for (size_t i = 0; i < count; i++) {
                    print_kv_plain(path, entries[i].arch, &entries[i].rep);
                }
            }
            // free per-entry libs
            for (size_t i = 0; i < count; i++) {
                free_report(&entries[i].rep);
            }
            free(entries);
        }
    } else if (magic == MH_MAGIC || magic == MH_MAGIC_64) {
        // Thin Mach-O
        const char *arch = "unknown";
        if (magic == MH_MAGIC) {
            const struct mach_header *mh = (const struct mach_header *)base;
            arch = arch_name(mh->cputype, mh->cpusubtype);
        } else {
            const struct mach_header_64 *mh = (const struct mach_header_64 *)base;
            arch = arch_name(mh->cputype, mh->cpusubtype);
        }
        sec_report_t rep = {0};
        if (analyze_thin(base, sz, path, arch, &rep) == 0) {
            entry_t e = {0};
            snprintf(e.arch, sizeof(e.arch), "%s", arch);
            e.rep = rep;
            if (pretty) {
                render_pretty_table(path, &e, 1, use_color);
            } else {
                print_kv_plain(path, arch, &rep);
            }
            free_report(&e.rep);
        } else {
            fprintf(stderr, "Unsupported or malformed Mach-O: %s\n", path);
            munmap(map, sz);
            return 1;
        }
    } else {
        fprintf(stderr, "Not a Mach-O or universal binary: %s\n", path);
        munmap(map, sz);
        return 1;
    }

    munmap(map, sz);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "macsec - macOS checksec-like tool by @planetminguez\n"
            "Usage: %s [--pretty|--plain] [--color|--no-color] <mach-o-file> [more files...]\n",
            argv0);
}

static int term_width(void) {
    if (!isatty(STDOUT_FILENO)) return 0;
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) return 0;
    return (int)ws.ws_col;
}

static void print_banner(bool use_color) {
    printf("\n");
    printf("\n");
    printf("\n");
    printf("\n");
    const char *l1 = "Program: macsec - macOS checksec-like tool";
const char *l2 = "Author: @planetminguez <https://github.com/planetminguez/macec>";
    int w = (int)strlen(l1);
    int l2w = (int)strlen(l2);
    if (l2w > w) w = l2w;

    int box_w = w + 4; // "+-" + content + "-+" equals w+4
    int cols = term_width();
    int pad = 0;
    if (cols > box_w) pad = (cols - box_w) / 2;

    const char *cy = use_color ? COL_CYAN : "";
    const char *rs = use_color ? COL_RESET : "";

    // Top border
    for (int i = 0; i < pad; i++) putchar(' ');
    fputs(cy, stdout); fputs("+", stdout);
    for (int i = 0; i < w + 2; i++) putchar('-');
    fputs("+", stdout); fputs(rs, stdout); fputc('\n', stdout);

    // First line
    for (int i = 0; i < pad; i++) putchar(' ');
    fputs(cy, stdout); fputs("|", stdout); fputs(rs, stdout);
    fputc(' ', stdout);
    fputs(cy, stdout); fputs(l1, stdout); fputs(rs, stdout);
    for (int i = (int)strlen(l1); i < w; i++) putchar(' ');
    fputc(' ', stdout);
    fputs(cy, stdout); fputs("|", stdout); fputs(rs, stdout);
    fputc('\n', stdout);

    // Second line
    for (int i = 0; i < pad; i++) putchar(' ');
    fputs(cy, stdout); fputs("|", stdout); fputs(rs, stdout);
    fputc(' ', stdout);
    fputs(cy, stdout); fputs(l2, stdout); fputs(rs, stdout);
    for (int i = (int)strlen(l2); i < w; i++) putchar(' ');
    fputc(' ', stdout);
    fputs(cy, stdout); fputs("|", stdout); fputs(rs, stdout);
    fputc('\n', stdout);

    // Bottom border
    for (int i = 0; i < pad; i++) putchar(' ');
    fputs(cy, stdout); fputs("+", stdout);
    for (int i = 0; i < w + 2; i++) putchar('-');
    fputs("+", stdout); fputs(rs, stdout); fputc('\n', stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    options_t opt = {0};

    int idx = 1;
    for (; idx < argc; idx++) {
        const char *a = argv[idx];
        if (a[0] != '-') break;
        if (strcmp(a, "--pretty") == 0) opt.force_pretty = true;
        else if (strcmp(a, "--plain") == 0) opt.force_plain = true;
        else if (strcmp(a, "--color") == 0) opt.force_color = true;
        else if (strcmp(a, "--no-color") == 0) opt.no_color = true;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown option: %s\n", a); usage(argv[0]); return 2; }
    }

    if (idx >= argc) { usage(argv[0]); return 2; }

    bool use_color = opt.force_color || (!opt.no_color && isatty(STDOUT_FILENO));
    print_banner(use_color);

    int exit_code = 0;
    for (; idx < argc; idx++) {
        int rc = analyze_path_with_opts(argv[idx], &opt);
        if (rc != 0) exit_code = rc;
    }
    return exit_code;
}
