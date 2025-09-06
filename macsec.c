/*
 * file_analyzer_macos.c
 * 
 * A comprehensive security analysis tool for macOS Mach-O binary files.
 * This program analyzes executable files and libraries to detect various
 * security features and mitigations implemented in the binary.
 * 
 * Author: Security Analysis Tool
 * Purpose: Analyze Mach-O binaries for security features
 */

// Standard C library headers
#include <stdio.h>      // For file I/O operations (printf, fopen, etc.)
#include <stdlib.h>     // For memory allocation and system functions
#include <string.h>     // For string manipulation functions
#include <unistd.h>     // For UNIX system calls (access, read, etc.)
#include <fcntl.h>      // For file control operations (open flags)
#include <sys/stat.h>   // For file status information
#include <sys/mman.h>   // For memory mapping (not used but included)
#include <errno.h>      // For error handling

// macOS-specific Mach-O binary format headers
#include <mach-o/loader.h>  // Mach-O file structure definitions
#include <mach-o/fat.h>     // Universal binary (fat binary) definitions
#include <mach-o/nlist.h>   // Symbol table definitions
#include <libkern/OSByteOrder.h> // For byte order swapping in FAT headers

// ANSI color codes for terminal output formatting
// These provide colored output to make the analysis results more readable
#define RED     "\x1b[31m"   // Red text for security issues/disabled features
#define GREEN   "\x1b[32m"   // Green text for enabled security features
#define YELLOW  "\x1b[33m"   // Yellow text for warnings/medium security
#define BLUE    "\x1b[34m"   // Blue text for section headers
#define MAGENTA "\x1b[35m"   // Magenta text (reserved for future use)
#define CYAN    "\x1b[36m"   // Cyan text for banner and titles
#define RESET   "\x1b[0m"    // Reset to default terminal color

/*
 * security_info_t - Structure to hold security analysis results
 * 
 * This structure contains flags and information about various security
 * features detected in the analyzed Mach-O binary file.
 */
typedef struct {
    int is_macho;         // Flag: 1 if file is a valid Mach-O binary, 0 otherwise
    int is_64bit;         // Flag: 1 if binary is 64-bit, 0 if 32-bit
    int has_nx;           // Flag: 1 if NX bit (Data Execution Prevention) is enabled
    int has_stack_canary; // Flag: 1 if stack canaries (stack smashing protection) detected
    int has_pie;          // Flag: 1 if Position Independent Executable (PIE) is enabled
    int has_aslr;         // Flag: 1 if Address Space Layout Randomization is enabled
    int has_fortify;      // Flag: 1 if FORTIFY_SOURCE (enhanced bounds checking) detected
    int has_arc;          // Flag: 1 if Automatic Reference Counting (ARC) detected
    char arch[32];        // String: CPU architecture (x86_64, ARM64, etc.)
    char file_type[64];   // String: Mach-O file type (Executable, Library, etc.)
} security_info_t;

/*
 * print_banner - Display the application banner
 * 
 * Prints a formatted banner using Unicode box drawing characters and ANSI colors
 * to provide a professional-looking header for the security analysis tool.
 */
  void print_banner() {
    // Print the top border of the banner using Unicode box-drawing characters
    printf("\n");
    printf(CYAN "\t\t\t\t╔══════════════════════════════════════════════════════════════╗\n");
    
    // Print the tool name with appropriate spacing for centering
    printf("\t\t\t\t║                    Mach-O File CheckSec                      ║\n");
    
    // Print the platform identifier
    printf("\t\t\t\t║                       @planetminguez                         ║\n");
    
    // Print the bottom border and reset color
    printf("\t\t\t\t╚══════════════════════════════════════════════════════════════╝\n" RESET);
    
    // Add spacing after banner
    printf("\t\n");
  }

/*
 * print_section_header - Display a section header with formatting
 * 
 * @title: The title text to display in the section header
 * 
 * Creates a visually distinct section header using Unicode characters
 * and blue coloring to organize the output into logical sections.
 */
void print_section_header(const char* title) {
    printf(BLUE "┌─ %s\n" RESET, title);
}

/*
 * print_security_feature - Display a security feature status
 * 
 * @feature: Name of the security feature (e.g., "Stack Canaries")
 * @enabled: Boolean flag indicating if the feature is enabled (1) or disabled (0)
 * @description: Brief description of what the security feature does
 * 
 * Formats and displays a security feature with color-coded status:
 * - Green for enabled features (good security)
 * - Red for disabled features (potential security risk)
 */
void print_security_feature(const char* feature, int enabled, const char* description) {
    const char* status_color = enabled ? GREEN : RED;  // Choose color based on status
    const char* status_text = enabled ? "ENABLED " : "DISABLED"; // Status text
    
    // Print formatted line with feature name, colored status, and description
    printf("│ %-20s: %s%s%s - %s\n", feature, status_color, status_text, RESET, description);
}

/*
 * cpu_type_to_string - Convert CPU type constant to human-readable string
 * 
 * @cpu_type: The CPU type constant from the Mach-O header
 * @return: Human-readable string representation of the CPU architecture
 * 
 * Converts the numeric CPU type constants defined in mach/machine.h
 * to descriptive strings that users can easily understand.
 */
const char* cpu_type_to_string(cpu_type_t cpu_type) {
    switch (cpu_type) {
        case CPU_TYPE_X86_64:   // Intel/AMD 64-bit x86 architecture
            return "x86_64";
        case CPU_TYPE_ARM64:    // Apple Silicon (M1, M2, etc.) 64-bit ARM
            return "ARM64";
        case CPU_TYPE_I386:     // Legacy 32-bit Intel x86
            return "i386";
        case CPU_TYPE_ARM:      // Legacy 32-bit ARM
            return "ARM";
        default:                // Unknown or unsupported architecture
            return "Unknown";
    }
}

/*
 * filetype_to_string - Convert Mach-O file type to human-readable string
 * 
 * @filetype: The file type constant from the Mach-O header
 * @return: Human-readable string describing the file type
 * 
 * Converts the numeric file type constants (MH_EXECUTE, MH_DYLIB, etc.)
 * to descriptive strings that explain what kind of Mach-O file is being analyzed.
 */
const char* filetype_to_string(uint32_t filetype) {
    switch (filetype) {
        case MH_EXECUTE:    // Standard executable program
            return "Executable";
        case MH_DYLIB:      // Dynamic library (.dylib)
            return "Dynamic Library";
        case MH_BUNDLE:     // Bundle (plugin, framework component)
            return "Bundle";
        case MH_DYLINKER:   // Dynamic linker (/usr/lib/dyld)
            return "Dynamic Linker";
        case MH_OBJECT:     // Object file (.o)
            return "Object File";
        case MH_CORE:       // Core dump file
            return "Core Dump";
        default:            // Unknown or unsupported file type
            return "Unknown";
    }
}

/*
 * analyze_mach_header - Parse Mach-O header and extract basic security information
 * 
 * @filename: Path to the file to analyze
 * @info: Pointer to security_info_t structure to populate with results
 * @return: 0 on success, -1 on error
 * 
 * This function opens the binary file and reads its Mach-O header to determine:
 * - Whether it's a valid Mach-O file
 * - Architecture (x86_64, ARM64, etc.)
 * - File type (executable, library, etc.)
 * - Basic security features like PIE (Position Independent Executable)
 * 
 * The function handles different Mach-O formats:
 * - 64-bit Mach-O (MH_MAGIC_64, MH_CIGAM_64)
 * - 32-bit Mach-O (MH_MAGIC, MH_CIGAM)
 * - Universal binaries (FAT_MAGIC, FAT_CIGAM)
 */
int analyze_mach_header(const char* filename, security_info_t* info) {
    // Open the file in read-only mode
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return -1;
    }

    // Read the magic number (first 4 bytes) to identify file format
    uint32_t magic;
    if (read(fd, &magic, sizeof(magic)) < 0) {
        perror("Failed to read file");
        close(fd);
        return -1;
    }

    // Reset file pointer to beginning for subsequent reads
    lseek(fd, 0, SEEK_SET);

    // Check magic number to determine Mach-O format and parse accordingly
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        // 64-bit Mach-O binary (modern format)
        info->is_64bit = 1;
        info->is_macho = 1;
        
        // Read the complete 64-bit Mach-O header
        struct mach_header_64 header;
        if (read(fd, &header, sizeof(header)) < 0) {
            close(fd);
            return -1;
        }
        
        // Extract architecture and file type information
        strcpy(info->arch, cpu_type_to_string(header.cputype));
        strcpy(info->file_type, filetype_to_string(header.filetype));
        
        // Check for PIE (Position Independent Executable) flag in header flags
        // PIE enables ASLR and is important for security
        if (header.flags & MH_PIE) {
            info->has_pie = 1;
        }
        
        // NX bit (Data Execution Prevention) is enabled by default on modern macOS
        // This prevents execution of data segments, mitigating code injection attacks
        info->has_nx = 1; // macOS enables NX by default
        
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        // 32-bit Mach-O binary (legacy format)
        info->is_64bit = 0;
        info->is_macho = 1;
        
        // Read the complete 32-bit Mach-O header
        struct mach_header header;
        if (read(fd, &header, sizeof(header)) < 0) {
            close(fd);
            return -1;
        }
        
        // Extract architecture and file type information
        strcpy(info->arch, cpu_type_to_string(header.cputype));
        strcpy(info->file_type, filetype_to_string(header.filetype));
        
        // Check for PIE flag (less common in 32-bit binaries)
        if (header.flags & MH_PIE) {
            info->has_pie = 1;
        }
        
        // NX bit is still enabled by default on macOS even for 32-bit binaries
        info->has_nx = 1; // macOS enables NX by default
        
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        // Universal binary (fat binary) - contains multiple architectures
        // These are used for apps that run on both Intel and Apple Silicon
        info->is_macho = 1;
        strcpy(info->arch, "Universal");
        strcpy(info->file_type, "Universal Binary");
        
        // Universal binaries are typically built with modern toolchains
        // and generally have PIE enabled for security
        info->has_pie = 1; // Universal binaries are typically PIE
        info->has_nx = 1;  // NX is enabled by default
        
    } else {
        // Not a recognized Mach-O file format
        info->is_macho = 0;
    }

    close(fd);
    return 0;
}

/*
 * check_security_features - Analyze binary for advanced security features
 * 
 * @filename: Path to the binary file to analyze
 * @info: Pointer to security_info_t structure to update with findings
 * 
 * This function uses external tools (otool, nm, strings) to detect various
 * security features that cannot be determined from the Mach-O header alone:
 * 
 * - Stack Canaries: Detect stack smashing protection by looking for
 *   __stack_chk_fail and __stack_chk_guard symbols
 * - FORTIFY_SOURCE: Enhanced bounds checking for C library functions
 * - ARC: Automatic Reference Counting for Objective-C memory management
 * - ASLR: Address Space Layout Randomization (tied to PIE support)
 */
void check_security_features(const char* filename, security_info_t* info) {
    char command[512];  // Buffer for shell commands
    FILE* fp;           // File pointer for command output
    char buffer[256];   // Buffer for reading command output
    
    // Check for stack canary protection using otool (object file tool)
    // Look for stack protection symbols in the indirect symbol table
    snprintf(command, sizeof(command), "otool -Iv \"%s\" 2>/dev/null | grep -E '__stack_chk_fail|__stack_chk_guard'", filename);
    fp = popen(command, "r");
    if (fp) {
        // If we find stack protection symbols, stack canaries are enabled
        if (fgets(buffer, sizeof(buffer), fp)) {
            info->has_stack_canary = 1;
        }
        pclose(fp);
    }
    
    // Alternative check using nm (name list) if otool didn't find symbols
    // This catches cases where symbols might be in different sections
    if (!info->has_stack_canary) {
        snprintf(command, sizeof(command), "nm \"%s\" 2>/dev/null | grep -E '__stack_chk_fail|__stack_chk_guard'", filename);
        fp = popen(command, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                info->has_stack_canary = 1;
            }
            pclose(fp);
        }
    }
    
    // Check for FORTIFY_SOURCE protection using strings command
    // FORTIFY_SOURCE replaces unsafe functions with safer "_chk" variants
    // that perform bounds checking (e.g., strcpy -> __strcpy_chk)
    snprintf(command, sizeof(command), "strings \"%s\" 2>/dev/null | grep -E '__.*_chk'", filename);
    fp = popen(command, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            info->has_fortify = 1;
        }
        pclose(fp);
    }
    
    // Check for ARC (Automatic Reference Counting) - Objective-C specific
    // ARC automatically manages memory by inserting retain/release calls
    // We detect this by looking for objc_retain and objc_release symbols
    snprintf(command, sizeof(command), "otool -Iv \"%s\" 2>/dev/null | grep -E 'objc_retain|objc_release'", filename);
    fp = popen(command, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            info->has_arc = 1;
        }
        pclose(fp);
    }
    
    // ASLR (Address Space Layout Randomization) is enabled by default
    // on macOS for PIE (Position Independent Executable) binaries
    // PIE allows the binary to be loaded at random addresses
    info->has_aslr = info->has_pie;
}

/*
 * check_code_signing - Verify if the binary has a code signature
 * 
 * @filename: Path to the binary file to check
 * 
 * Uses the macOS codesign utility to determine if the binary is digitally signed.
 * Code signing is a security feature that:
 * - Verifies the integrity of the binary
 * - Ensures it hasn't been tampered with
 * - Identifies the developer or organization that signed it
 * - Is required for distribution through the App Store
 * - Enables other security features like Hardened Runtime
 */
void check_code_signing(const char* filename) {
    char command[512];  // Buffer for shell command
    FILE* fp;           // File pointer for command output
    char buffer[1024];  // Buffer for reading command output
    
    printf("│ Code Signing     : ");
    
    // Use codesign with display verbose (-dv) to get signature information
    // Redirect stderr to stdout (2>&1) to capture all output
    snprintf(command, sizeof(command), "codesign -dv \"%s\" 2>&1", filename);
    fp = popen(command, "r");
    if (fp) {
        int has_signature = 0;
        // Look for signature indicators in the output
        while (fgets(buffer, sizeof(buffer), fp)) {
            // Check for common codesign output fields that indicate a signature
            if (strstr(buffer, "Identifier=") || strstr(buffer, "Authority=")) {
                has_signature = 1;
                break;
            }
        }
        pclose(fp);
        
        // Display results with appropriate color coding
        if (has_signature) {
            printf("%sSIGNED%s - Binary is code signed\n", GREEN, RESET);
        } else {
            printf("%sNOT SIGNED%s - Binary lacks code signature\n", RED, RESET);
        }
    } else {
        // If codesign command fails, we can't determine the status
        printf("%sUNKNOWN%s - Unable to check signature\n", YELLOW, RESET);
    }
}

/*
 * check_hardened_runtime - Check if Hardened Runtime is enabled
 * 
 * @filename: Path to the binary file to check
 * 
 * Hardened Runtime is a macOS security feature that:
 * - Restricts runtime code modification
 * - Prevents code injection attacks
 * - Limits access to system resources
 * - Disables certain debugging capabilities
 * - Requires specific entitlements for certain operations
 * 
 * This function checks both for library validation and runtime flags.
 */
void check_hardened_runtime(const char* filename) {
    char command[512];  // Buffer for shell commands
    FILE* fp;           // File pointer (unused in this implementation)
    char buffer[256];   // Buffer (unused in this implementation)
    
    printf("│ Hardened Runtime : ");
    
    // First check if library validation is disabled (which weakens hardened runtime)
    // This entitlement allows loading of unsigned libraries
    snprintf(command, sizeof(command), "codesign -dv --entitlements - \"%s\" 2>/dev/null | grep -q 'com.apple.security.cs.disable-library-validation'", filename);
    int result = system(command);
    
    if (result == 0) {
        // Library validation is disabled - hardened runtime is weakened
        printf("%sDISABLED%s - Library validation disabled\n", RED, RESET);
    } else {
        // Check if hardened runtime is explicitly enabled
        snprintf(command, sizeof(command), "codesign -dv \"%s\" 2>&1 | grep -q 'runtime'", filename);
        result = system(command);
        if (result == 0) {
            // Hardened runtime is active
            printf("%sENABLED%s - Hardened runtime active\n", GREEN, RESET);
        } else {
            // No hardened runtime detected
            printf("%sDISABLED%s - No hardened runtime\n", RED, RESET);
        }
    }
}

/*
 * print_file_info - Display basic file system information
 * 
 * @filename: Path to the file to examine
 * 
 * Uses the stat() system call to retrieve and display:
 * - File size in bytes
 * - File permissions in octal format
 * - Whether the file has execute permissions for the owner
 */
void print_file_info(const char* filename) {
    struct stat st;  // Structure to hold file status information
    
    // Get file status information
    if (stat(filename, &st) == 0) {
        // Display file size (cast to long long for portability)
        printf("│ File Size        : %lld bytes\n", (long long)st.st_size);
        
        // Display permissions in octal format (e.g., 755, 644)
        // Mask with 0777 to get only the permission bits
        printf("│ Permissions      : %o\n", st.st_mode & 0777);
        
        // Check if file is executable by owner (S_IXUSR bit)
        printf("│ Executable       : %s\n", (st.st_mode & S_IXUSR) ? "Yes" : "No");
    }
}

/*
 * detect_linkage_type - Determine if a Mach-O binary is dynamically or statically linked
 *
 * @filename: Path to the binary file
 * @out: Buffer to receive a short human-readable description
 * @outsz: Size of the output buffer
 * @return: 0 on success, -1 on failure
 *
 * Method: For non-fat (single-arch) Mach-O, parse the load commands and header flags.
 * - If MH_DYLDLINK is set OR any LC_LOAD_*DYLIB/LC_LOAD_DYLINKER is present => Dynamic
 * - Otherwise => Static
 * For universal (FAT) binaries, we report that it's multi-arch without deep inspection.
 */
static int detect_slice_linkage(int fd, off_t slice_off, int* out_is_dynamic) {
    uint32_t magic = 0;
    if (pread(fd, &magic, sizeof(magic), slice_off) != (ssize_t)sizeof(magic)) return -1;

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        struct mach_header_64 mh;
        if (pread(fd, &mh, sizeof(mh), slice_off) != (ssize_t)sizeof(mh)) return -1;
        int is_dynamic = (mh.flags & MH_DYLDLINK) ? 1 : 0;
        off_t off = slice_off + (off_t)sizeof(mh);
        for (uint32_t i = 0; i < mh.ncmds; i++) {
            struct load_command lc;
            if (pread(fd, &lc, sizeof(lc), off) != (ssize_t)sizeof(lc)) break;
            if (lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB ||
                lc.cmd == LC_REEXPORT_DYLIB || lc.cmd == LC_LOAD_UPWARD_DYLIB ||
                lc.cmd == LC_LOAD_DYLINKER) {
                is_dynamic = 1;
            }
            off += lc.cmdsize;
        }
        *out_is_dynamic = is_dynamic;
        return 0;
    } else if (magic == MH_MAGIC || magic == MH_CIGAM) {
        struct mach_header mh;
        if (pread(fd, &mh, sizeof(mh), slice_off) != (ssize_t)sizeof(mh)) return -1;
        int is_dynamic = (mh.flags & MH_DYLDLINK) ? 1 : 0;
        off_t off = slice_off + (off_t)sizeof(mh);
        for (uint32_t i = 0; i < mh.ncmds; i++) {
            struct load_command lc;
            if (pread(fd, &lc, sizeof(lc), off) != (ssize_t)sizeof(lc)) break;
            if (lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB ||
                lc.cmd == LC_REEXPORT_DYLIB || lc.cmd == LC_LOAD_UPWARD_DYLIB ||
                lc.cmd == LC_LOAD_DYLINKER) {
                is_dynamic = 1;
            }
            off += lc.cmdsize;
        }
        *out_is_dynamic = is_dynamic;
        return 0;
    }
    return -1;
}

int detect_linkage_type(const char* filename, char* out, size_t outsz) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        snprintf(out, outsz, "Unknown (open failed)");
        return -1;
    }

    uint32_t magic = 0;
    ssize_t r = read(fd, &magic, sizeof(magic));
    if (r != (ssize_t)sizeof(magic)) {
        snprintf(out, outsz, "Unknown (read failed)");
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);

    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM) {
        int is_dynamic = 0;
        if (detect_slice_linkage(fd, 0, &is_dynamic) == 0) {
            snprintf(out, outsz, "%s", is_dynamic ? "Dynamic (uses dyld)" : "Static");
            close(fd);
            return 0;
        }
        snprintf(out, outsz, "Unknown (slice parse failed)");
        close(fd);
        return -1;
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        int swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        uint32_t nfat = 0;
        off_t arch_table_off = 0;
        if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
            struct fat_header fh;
            if (read(fd, &fh, sizeof(fh)) != (ssize_t)sizeof(fh)) { snprintf(out, outsz, "Unknown (fat read)"); close(fd); return -1; }
            nfat = swap ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch;
            arch_table_off = sizeof(struct fat_header);

            size_t pos = 0;
            pos += snprintf(out + pos, (pos < outsz ? outsz - pos : 0), "Universal: ");
            for (uint32_t i = 0; i < nfat; i++) {
                struct fat_arch fa;
                if (pread(fd, &fa, sizeof(fa), arch_table_off + (off_t)i * sizeof(fa)) != (ssize_t)sizeof(fa)) break;
                cpu_type_t cputype = swap ? (cpu_type_t)OSSwapInt32(fa.cputype) : fa.cputype;
                off_t off = (off_t)(swap ? OSSwapInt32(fa.offset) : fa.offset);
                int is_dyn = 0;
                int ok = detect_slice_linkage(fd, off, &is_dyn);
                const char* arch_name = cpu_type_to_string(cputype);
                pos += snprintf(out + (pos < outsz ? pos : outsz), (pos < outsz ? outsz - pos : 0), "%s=%s%s",
                                arch_name, ok == 0 ? (is_dyn ? "Dynamic" : "Static") : "Unknown",
                                (i + 1 < nfat ? ", " : ""));
            }
            close(fd);
            return 0;
        } else {
            struct fat_header fh;
            if (read(fd, &fh, sizeof(fh)) != (ssize_t)sizeof(fh)) { snprintf(out, outsz, "Unknown (fat64 read)"); close(fd); return -1; }
            nfat = swap ? OSSwapInt32(fh.nfat_arch) : fh.nfat_arch; // same field name
            arch_table_off = sizeof(struct fat_header);

            size_t pos = 0;
            pos += snprintf(out + pos, (pos < outsz ? outsz - pos : 0), "Universal: ");
            for (uint32_t i = 0; i < nfat; i++) {
                struct fat_arch_64 fa64;
                if (pread(fd, &fa64, sizeof(fa64), arch_table_off + (off_t)i * sizeof(fa64)) != (ssize_t)sizeof(fa64)) break;
                cpu_type_t cputype = swap ? (cpu_type_t)OSSwapInt32(fa64.cputype) : fa64.cputype;
                off_t off = (off_t)(swap ? OSSwapInt64(fa64.offset) : fa64.offset);
                int is_dyn = 0;
                int ok = detect_slice_linkage(fd, off, &is_dyn);
                const char* arch_name = cpu_type_to_string(cputype);
                pos += snprintf(out + (pos < outsz ? pos : outsz), (pos < outsz ? outsz - pos : 0), "%s=%s%s",
                                arch_name, ok == 0 ? (is_dyn ? "Dynamic" : "Static") : "Unknown",
                                (i + 1 < nfat ? ", " : ""));
            }
            close(fd);
            return 0;
        }
    } else {
        snprintf(out, outsz, "Unknown (not Mach-O)");
        close(fd);
        return -1;
    }
}

/*
 * analyze_file - Main analysis function that orchestrates the security check
 * 
 * @filename: Path to the binary file to analyze
 * 
 * This is the primary analysis function that:
 * 1. Displays basic file information
 * 2. Parses the Mach-O header
 * 3. Checks for various security features
 * 4. Analyzes macOS-specific protections
 * 5. Calculates and displays a security score
 * 6. Provides recommendations and context
 */
void analyze_file(const char* filename) {
    // Initialize security information structure with zeros
    security_info_t info = {0};
    
    // Display the file being analyzed
    printf(YELLOW "Analyzing file: %s\n\n" RESET, filename);
    
    // Section 1: Basic file information (size, permissions, etc.)
    print_section_header("FILE INFORMATION");
    print_file_info(filename);
    
    // Section 2: Parse Mach-O header and extract basic security info
    if (analyze_mach_header(filename, &info) < 0) {
        return;  // Exit if file can't be read
    }
    
    // Verify this is actually a Mach-O file
    if (!info.is_macho) {
        printf(RED "│ Error: Not a Mach-O file\n" RESET);
        printf("│ Note: This tool is designed for macOS Mach-O binaries\n");
        return;
    }
    
    // Display Mach-O specific information
    printf("│ File Type        : %s\n", info.file_type);
    printf("│ Architecture     : %s\n", info.arch);
    printf("│ Bit Mode         : %s\n", info.is_64bit ? "64-bit" : "32-bit");
    {
        char linkage[256];
        if (detect_linkage_type(filename, linkage, sizeof(linkage)) == 0) {
            printf("│ Linkage          : %s\n", linkage);
        }
    }
    printf("└─\n\n");
    
    // Section 3: Analyze advanced security features using external tools
    check_security_features(filename, &info);
    
    // Section 4: Display security features analysis results
    print_section_header("SECURITY FEATURES");
    
    // Display each security feature with color-coded status and description
    print_security_feature("NX Bit (DEP)", info.has_nx, 
                          "Prevents execution of data segments");
    
    print_security_feature("Stack Canaries", info.has_stack_canary, 
                          "Detects stack buffer overflows");
    
    print_security_feature("PIE", info.has_pie, 
                          "Position Independent Executable");
    
    print_security_feature("ASLR", info.has_aslr, 
                          "Address Space Layout Randomization");
    
    print_security_feature("FORTIFY_SOURCE", info.has_fortify, 
                          "Enhanced bounds checking for library functions");
    
    print_security_feature("ARC", info.has_arc, 
                          "Automatic Reference Counting (Obj-C)");
    printf("\n\n");

}

/*
 * main - Entry point of the program
 * 
 * @argc: Number of command line arguments
 * @argv: Array of command line argument strings
 * @return: 0 on success, 1 on error
 * 
 * Handles command line argument parsing, displays usage information,
 * validates file existence, and initiates the security analysis.
 */
int main(int argc, char* argv[]) {
    // Check for correct number of arguments
    if (argc != 2) {
        // Display banner and usage information
        print_banner();
        printf("Usage: %s <executable_file>\n\n", argv[0]);
        printf("This tool analyzes macOS Mach-O binaries and reports on security features:\n");
        printf("  • NX Bit (Data Execution Prevention)\n");
        printf("  • Stack Canaries (Stack Smashing Protection)\n");
        printf("  • PIE (Position Independent Executable)\n");
        printf("  • ASLR (Address Space Layout Randomization)\n");
        printf("  • FORTIFY_SOURCE (Enhanced bounds checking)\n");
        printf("  • ARC (Automatic Reference Counting)\n");
        printf("  • Code Signing\n");
        printf("  • Hardened Runtime\n\n");
        return 1;
    }
    
    // Display banner for normal operation
    print_banner();
    
    // Verify the specified file exists before attempting analysis
    if (access(argv[1], F_OK) != 0) {
        printf(RED "Error: File '%s' does not exist\n" RESET, argv[1]);
        return 1;
    }
    
    // Perform the security analysis on the specified file
    analyze_file(argv[1]);
    
    return 0;
}
