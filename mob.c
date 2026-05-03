/*
 * mdb.c – minimal debugger for 64-bit, no-pie elf binaries on linux
 *
 * commands: b, l, d, r, c, si, disas, q
 *
 * build:
 * gcc -Wall -Wextra -g -O0 -o mdb mdb.c -lelf -lcapstone
 * gcc test.c -o test -no-pie
 *
 * requires: libelf-dev, libcapstone-dev
 *
 * execute:
 * ./mdb test
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <ctype.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

// fixed limits for symbols, breakpoints, and disassembly size
#define MAX_BPS 256
#define MAX_SYM 16384
#define MAX_RANGES 512
#define DISASM_N 11 // number of instructions to show when stopped
#define PATH_MAX 4096

// helper macro for fatal errors
#define die(...)                              \
    do                                        \
    {                                         \
        fprintf(stderr, "mdb: " __VA_ARGS__); \
        fputc('\n', stderr);                  \
        exit(EXIT_FAILURE);                   \
    } while (0)

// executable address range
typedef struct
{
    unsigned long start;
    unsigned long end;
} Range;

static Range static_exec_ranges[MAX_RANGES];
static int nstatic_exec_ranges = 0;

static Range runtime_exec_ranges[MAX_RANGES];
static int nruntime_exec_ranges = 0;

// symbol entry: stores a name and its address
typedef struct
{
    char name[256];
    unsigned long addr;
    int runtime; // 0 means main binary / plt, 1 means loaded from runtime shared library
} Sym;

static Sym syms[MAX_SYM];
static int nsyms = 0;
static int nstatic_syms = 0;

// checks whether an address is inside a range list
static int addr_in_ranges(Range *ranges, int nranges, unsigned long addr)
{
    for (int i = 0; i < nranges; i++)
    {
        if (addr >= ranges[i].start && addr < ranges[i].end)
            return 1;
    }
    return 0;
}

// checks whether an address belongs to executable code in the main binary
static int is_static_exec_addr(unsigned long addr)
{
    return addr_in_ranges(static_exec_ranges, nstatic_exec_ranges, addr);
}

// checks whether an address belongs to executable memory in the running process
static int is_runtime_exec_addr(unsigned long addr)
{
    return addr_in_ranges(runtime_exec_ranges, nruntime_exec_ranges, addr);
}

// adds a static executable range from the main binary
static void add_static_exec_range(unsigned long start, unsigned long end)
{
    if (!start || end <= start)
        return;

    if (nstatic_exec_ranges >= MAX_RANGES)
        return;

    static_exec_ranges[nstatic_exec_ranges].start = start;
    static_exec_ranges[nstatic_exec_ranges].end = end;
    nstatic_exec_ranges++;
}

// adds a runtime executable range from /proc/<pid>/maps
static void add_runtime_exec_range(unsigned long start, unsigned long end)
{
    if (!start || end <= start)
        return;

    if (nruntime_exec_ranges >= MAX_RANGES)
        return;

    runtime_exec_ranges[nruntime_exec_ranges].start = start;
    runtime_exec_ranges[nruntime_exec_ranges].end = end;
    nruntime_exec_ranges++;
}

// adds a symbol to the table, or updates it if it already exists
static void add_symbol_ex(const char *name, unsigned long addr, int runtime)
{
    if (!name || !*name || !addr)
        return;

    for (int i = 0; i < nsyms; i++)
    {
        if (!strcmp(syms[i].name, name))
        {
            // do not let runtime symbols overwrite main binary symbols
            if (!syms[i].runtime && runtime)
                return;

            syms[i].addr = addr;
            syms[i].runtime = runtime;
            return;
        }
    }

    if (nsyms >= MAX_SYM)
        return;

    strncpy(syms[nsyms].name, name, sizeof(syms[nsyms].name) - 1);
    syms[nsyms].name[sizeof(syms[nsyms].name) - 1] = '\0';
    syms[nsyms].addr = addr;
    syms[nsyms].runtime = runtime;
    nsyms++;
}

// adds a normal static symbol
static void add_symbol(const char *name, unsigned long addr)
{
    add_symbol_ex(name, addr, 0);
}

// removes glibc-style symbol versions from names like puts@@glibc_2.2.5
static void clean_symbol_name(char *dst, size_t dstsz, const char *src)
{
    if (!dst || dstsz == 0)
        return;

    strncpy(dst, src, dstsz - 1);
    dst[dstsz - 1] = '\0';

    char *at = strchr(dst, '@');
    if (at)
        *at = '\0';
}

// adds plt aliases like puts@plt instead of plain puts
// this keeps puts itself available for real runtime libc resolution
static void add_plt_symbol(const char *name, unsigned long addr)
{
    if (!name || !*name || !addr)
        return;

    char clean[256];
    char pltname[300];

    clean_symbol_name(clean, sizeof(clean), name);
    if (!clean[0])
        return;

    snprintf(pltname, sizeof(pltname), "%s@plt", clean);
    add_symbol_ex(pltname, addr, 0);
}

// loads plt entries from relocation sections
static void load_plt_symbols(Elf *e, size_t shstrndx)
{
    Elf_Scn *scn = NULL;
    Elf_Scn *plt_scn = NULL;
    Elf_Scn *pltsec_scn = NULL;

    // find .plt and .plt.sec if they exist
    while ((scn = elf_nextscn(e, scn)) != NULL)
    {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;

        const char *secname = elf_strptr(e, shstrndx, shdr.sh_name);
        if (!secname)
            continue;

        if (!strcmp(secname, ".plt"))
            plt_scn = scn;
        else if (!strcmp(secname, ".plt.sec"))
            pltsec_scn = scn;
    }

    scn = NULL;

    // find relocation sections that describe plt imports
    while ((scn = elf_nextscn(e, scn)) != NULL)
    {
        GElf_Shdr relshdr;
        if (!gelf_getshdr(scn, &relshdr))
            continue;

        if (relshdr.sh_type != SHT_RELA && relshdr.sh_type != SHT_REL)
            continue;

        const char *secname = elf_strptr(e, shstrndx, relshdr.sh_name);
        if (!secname)
            continue;

        if (!strstr(secname, ".rel.plt") && !strstr(secname, ".rela.plt"))
            continue;

        Elf_Scn *sym_scn = elf_getscn(e, relshdr.sh_link);
        if (!sym_scn)
            continue;

        GElf_Shdr symshdr;
        if (!gelf_getshdr(sym_scn, &symshdr))
            continue;

        Elf_Data *rel_data = elf_getdata(scn, NULL);
        Elf_Data *sym_data = elf_getdata(sym_scn, NULL);
        if (!rel_data || !sym_data || relshdr.sh_entsize == 0)
            continue;

        GElf_Shdr pltshdr;
        unsigned long plt_base = 0;
        unsigned long plt_entsz = 16;
        int skip_first = 1;

        if (pltsec_scn && gelf_getshdr(pltsec_scn, &pltshdr))
        {
            plt_base = (unsigned long)pltshdr.sh_addr;
            plt_entsz = pltshdr.sh_entsize ? (unsigned long)pltshdr.sh_entsize : 16;
            skip_first = 0;
        }
        else if (plt_scn && gelf_getshdr(plt_scn, &pltshdr))
        {
            plt_base = (unsigned long)pltshdr.sh_addr;
            plt_entsz = pltshdr.sh_entsize ? (unsigned long)pltshdr.sh_entsize : 16;
            skip_first = 1;
        }
        else
        {
            continue;
        }

        int rel_count = (int)(relshdr.sh_size / relshdr.sh_entsize);

        for (int i = 0; i < rel_count; i++)
        {
            size_t sym_index = 0;

            if (relshdr.sh_type == SHT_RELA)
            {
                GElf_Rela rela;
                if (!gelf_getrela(rel_data, i, &rela))
                    continue;
                sym_index = GELF_R_SYM(rela.r_info);
            }
            else
            {
                GElf_Rel rel;
                if (!gelf_getrel(rel_data, i, &rel))
                    continue;
                sym_index = GELF_R_SYM(rel.r_info);
            }

            GElf_Sym sym;
            if (!gelf_getsym(sym_data, (int)sym_index, &sym))
                continue;

            const char *name = elf_strptr(e, symshdr.sh_link, sym.st_name);
            if (!name || !name[0])
                continue;

            unsigned long addr = plt_base + (unsigned long)(i + skip_first) * plt_entsz;
            add_plt_symbol(name, addr);
        }
    }
}

// loads symbols from the main binary
// only symbols with real addresses are kept
static void load_symbols(const char *path)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("libelf init: %s", elf_errmsg(-1));

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die("open %s: %s", path, strerror(errno));

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e)
    {
        close(fd);
        die("elf_begin: %s", elf_errmsg(-1));
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(e, &shstrndx) != 0)
    {
        elf_end(e);
        close(fd);
        die("elf_getshdrstrndx: %s", elf_errmsg(-1));
    }

    nsyms = 0;
    nstatic_syms = 0;
    nstatic_exec_ranges = 0;

    Elf_Scn *scn = NULL;

    // walk through all sections and collect symbols
    while ((scn = elf_nextscn(e, scn)) != NULL)
    {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;

        // remember executable sections so raw addresses can be checked
        if ((shdr.sh_flags & SHF_EXECINSTR) && shdr.sh_addr && shdr.sh_size)
            add_static_exec_range((unsigned long)shdr.sh_addr,
                                  (unsigned long)(shdr.sh_addr + shdr.sh_size));

        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data || shdr.sh_entsize == 0)
            continue;

        int count = (int)(shdr.sh_size / shdr.sh_entsize);
        for (int i = 0; i < count; i++)
        {
            GElf_Sym s;
            if (!gelf_getsym(data, i, &s))
                continue;

            if (s.st_value == 0)
                continue;

            if (s.st_shndx == SHN_UNDEF)
                continue;

            const char *name = elf_strptr(e, shdr.sh_link, s.st_name);
            if (!name || !name[0])
                continue;

            add_symbol(name, (unsigned long)s.st_value);
        }
    }

    // also load plt aliases like puts@plt
    load_plt_symbols(e, shstrndx);

    nstatic_syms = nsyms;

    elf_end(e);
    close(fd);
    printf("[mdb] Loaded '%s' (%d symbols found)\n", path, nsyms);
}

// returns the address of a symbol name, or 0 if not found
static unsigned long sym_to_addr(const char *name)
{
    for (int i = 0; i < nsyms; i++)
        if (!strcmp(syms[i].name, name))
            return syms[i].addr;
    return 0;
}

// checks whether a symbol came from runtime shared libraries
static int sym_is_runtime(const char *name)
{
    for (int i = 0; i < nsyms; i++)
        if (!strcmp(syms[i].name, name))
            return syms[i].runtime;
    return 0;
}

// returns the symbol name for an exact address, or null if not found
static const char *addr_to_sym(unsigned long addr)
{
    for (int i = 0; i < nsyms; i++)
        if (syms[i].addr == addr)
            return syms[i].name;
    return NULL;
}

// returns the closest symbol if the address is inside or after a known symbol
static const char *addr_to_sym_best(unsigned long addr, unsigned long *offset)
{
    const char *best = NULL;
    unsigned long best_addr = 0;

    for (int i = 0; i < nsyms; i++)
    {
        if (syms[i].addr <= addr && syms[i].addr >= best_addr)
        {
            best = syms[i].name;
            best_addr = syms[i].addr;
        }
    }

    if (best && offset)
        *offset = addr - best_addr;

    return best;
}

// clears old runtime symbols because shared library addresses change every run
static void reset_runtime_symbols(void)
{
    nsyms = nstatic_syms;
}

// updates executable mappings from /proc/<pid>/maps
static void update_runtime_exec_ranges(pid_t pid)
{
    nruntime_exec_ranges = 0;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return;

    char line[1024];

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        char perms[8];
        char dev[32];
        unsigned long inode = 0;
        char path[PATH_MAX];

        path[0] = '\0';

        int fields = sscanf(line, "%lx-%lx %7s %lx %31s %lu %s",
                            &start, &end, perms, &offset, dev, &inode, path);

        if (fields < 6)
            continue;

        if (strchr(perms, 'x'))
            add_runtime_exec_range(start, end);
    }

    fclose(fp);
}

// loads dynamic symbols from one shared library using its runtime base address
static void load_runtime_symbols_from_object(const char *path, unsigned long base)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return;

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e)
    {
        close(fd);
        return;
    }

    Elf_Scn *scn = NULL;

    // scan the shared object's symbol tables
    while ((scn = elf_nextscn(e, scn)) != NULL)
    {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;

        if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data || shdr.sh_entsize == 0)
            continue;

        int count = (int)(shdr.sh_size / shdr.sh_entsize);
        for (int i = 0; i < count; i++)
        {
            GElf_Sym s;
            if (!gelf_getsym(data, i, &s))
                continue;

            if (s.st_value == 0)
                continue;

            if (s.st_shndx == SHN_UNDEF)
                continue;

            const char *name = elf_strptr(e, shdr.sh_link, s.st_name);
            if (!name || !name[0])
                continue;

            char clean[256];
            clean_symbol_name(clean, sizeof(clean), name);
            if (!clean[0])
                continue;

            // for shared libraries, runtime address is base + symbol offset
            add_symbol_ex(clean, base + (unsigned long)s.st_value, 1);
        }
    }

    elf_end(e);
    close(fd);
}

// scans /proc/<pid>/maps and loads symbols from shared libraries already mapped
static void resolve_dynamic_symbols(pid_t pid)
{
    update_runtime_exec_ranges(pid);

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return;

    char line[1024];
    char seen[256][PATH_MAX];
    int nseen = 0;

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        char perms[8];
        char dev[32];
        unsigned long inode = 0;
        char path[PATH_MAX];

        path[0] = '\0';

        int fields = sscanf(line, "%lx-%lx %7s %lx %31s %lu %s",
                            &start, &end, perms, &offset, dev, &inode, path);

        if (fields < 7)
            continue;

        if (path[0] != '/')
            continue;

        if (!strstr(path, ".so"))
            continue;

        // avoid loading the same shared library more than once per scan
        int already_seen = 0;
        for (int i = 0; i < nseen; i++)
        {
            if (!strcmp(seen[i], path))
            {
                already_seen = 1;
                break;
            }
        }

        if (already_seen)
            continue;

        if (nseen < 256)
        {
            strncpy(seen[nseen], path, PATH_MAX - 1);
            seen[nseen][PATH_MAX - 1] = '\0';
            nseen++;
        }

        // base is the mapped start minus the file offset from /proc/<pid>/maps
        unsigned long base = start - offset;
        load_runtime_symbols_from_object(path, base);
    }

    fclose(fp);
}

// one breakpoint entry
typedef struct
{
    int id;
    unsigned long addr;
    long saved;       // original 8-byte word before int3 was written
    int active;       // whether int3 is currently installed in the child
    int enabled;      // whether this breakpoint still exists logically
    int pending;      // whether the symbol is not resolved yet
    int runtime_sym;  // whether this breakpoint must be re-resolved on every run
    int run_specific; // whether this was a raw runtime address from one run only
    char label[256];
    char requested[256];
} BP;

static BP bps[MAX_BPS];
static int nbps = 0;
static int next_id = 1;

// pending breakpoints for unresolved symbols
static int ndeferred = 0;

// finds a breakpoint by address
static BP *bp_by_addr(unsigned long addr)
{
    for (int i = 0; i < nbps; i++)
        if (bps[i].enabled && !bps[i].pending && bps[i].addr == addr)
            return &bps[i];
    return NULL;
}

// finds a breakpoint by numeric id
static BP *bp_by_id(int id)
{
    for (int i = 0; i < nbps; i++)
        if (bps[i].id == id)
            return &bps[i];
    return NULL;
}

// checks if there is already a breakpoint for this requested name
static BP *bp_by_request(const char *name)
{
    for (int i = 0; i < nbps; i++)
    {
        if (bps[i].enabled && !strcmp(bps[i].requested, name))
            return &bps[i];
    }
    return NULL;
}

// adds a breakpoint to the internal table
static void bp_add(unsigned long addr, const char *label, int runtime_sym, int run_specific)
{
    if (nbps >= MAX_BPS)
    {
        puts("Breakpoint table full.");
        return;
    }
    if (bp_by_addr(addr))
    {
        printf("Already have a BP at 0x%lx.\n", addr);
        return;
    }

    BP *b = &bps[nbps++];
    b->id = next_id++;
    b->addr = addr;
    b->saved = 0;
    b->active = 0;
    b->enabled = 1;
    b->pending = 0;
    b->runtime_sym = runtime_sym;
    b->run_specific = run_specific;

    if (label && label[0])
    {
        strncpy(b->label, label, 255);
        b->label[255] = '\0';

        strncpy(b->requested, label, 255);
        b->requested[255] = '\0';
    }
    else
    {
        const char *s = addr_to_sym(addr);
        if (s)
        {
            strncpy(b->label, s, 255);
            b->label[255] = '\0';
        }
        else
        {
            snprintf(b->label, sizeof(b->label), "0x%lx", addr);
        }

        snprintf(b->requested, sizeof(b->requested), "0x%lx", addr);
    }

    printf("Breakpoint %d set at %s (0x%lx)\n", b->id, b->label, b->addr);
}

// adds a pending breakpoint with its own id
static void bp_add_pending(const char *name)
{
    if (nbps >= MAX_BPS)
    {
        puts("Breakpoint table full.");
        return;
    }

    if (bp_by_request(name))
    {
        printf("Already have a BP for %s.\n", name);
        return;
    }

    BP *b = &bps[nbps++];
    b->id = next_id++;
    b->addr = 0;
    b->saved = 0;
    b->active = 0;
    b->enabled = 1;
    b->pending = 1;
    b->runtime_sym = 1;
    b->run_specific = 0;

    strncpy(b->label, name, 255);
    b->label[255] = '\0';

    strncpy(b->requested, name, 255);
    b->requested[255] = '\0';

    printf("Pending breakpoint %d queued for '%s'.\n", b->id, b->requested);
}

// installs a software breakpoint by writing int3 at the target address
static void bp_install(pid_t pid, BP *b)
{
    if (b->active || !b->enabled || b->pending)
        return;

    update_runtime_exec_ranges(pid);

    if (!is_runtime_exec_addr(b->addr))
        return;

    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, pid, (void *)b->addr, 0);
    if (w == -1 && errno)
    {
        perror("peekdata");
        return;
    }
    b->saved = w;
    long trap = (w & ~0xFFL) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)b->addr, (void *)trap) == -1)
        perror("pokedata");
    else
        b->active = 1;
}

// removes a software breakpoint by restoring the saved bytes
static void bp_remove(pid_t pid, BP *b)
{
    if (!b->active)
        return;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)b->addr, (void *)b->saved) == -1)
        perror("pokedata");
    else
        b->active = 0;
}

// installs all enabled breakpoints into the child process
static void bp_install_all(pid_t pid)
{
    for (int i = 0; i < nbps; i++)
        if (bps[i].enabled && !bps[i].pending)
            bp_install(pid, &bps[i]);
}

// resets runtime breakpoints before every new run
static void bp_reset_for_new_run(void)
{
    for (int i = 0; i < nbps; i++)
    {
        bps[i].active = 0;
        bps[i].saved = 0;

        if (!bps[i].enabled)
            continue;

        // raw runtime addresses are only valid for the old run, because aslr may change them
        if (bps[i].run_specific)
        {
            bps[i].enabled = 0;
            continue;
        }

        // dynamic symbols must be resolved again because shared libraries may move
        if (bps[i].runtime_sym)
        {
            bps[i].addr = 0;
            bps[i].pending = 1;
        }
    }
}

// tries to convert pending breakpoint names into real breakpoints
static void resolve_pending_breakpoints(pid_t pid)
{
    for (int i = 0; i < nbps; i++)
    {
        BP *b = &bps[i];

        if (!b->enabled || !b->pending)
            continue;

        unsigned long addr = sym_to_addr(b->requested);
        if (!addr)
            continue;

        update_runtime_exec_ranges(pid);

        if (!is_runtime_exec_addr(addr))
            continue;

        b->addr = addr;
        b->pending = 0;
        b->runtime_sym = sym_is_runtime(b->requested);
        b->run_specific = 0;
        b->active = 0;
        b->saved = 0;

        printf("Pending breakpoint %d resolved at %s (0x%lx)\n",
               b->id, b->requested, b->addr);

        bp_install(pid, b);
    }

    // keep the old deferred variables in sync as empty because pending is now stored in bps
    ndeferred = 0;
}

// global debugger state
static char *g_binary = NULL;
static char g_run_args[512] = ""; // arguments used when running the target
static pid_t g_child = -1;
static int g_alive = 0;              // child exists and is under debugger control
static unsigned long g_cur_addr = 0; // current rip when stopped

static int g_hidden_main_active = 0;
static unsigned long g_hidden_main_addr = 0;
static long g_hidden_main_saved = 0;

// installs a hidden breakpoint at main so the dynamic loader has time to map libc
static void hidden_main_install(pid_t pid)
{
    int has_pending = 0;

    for (int i = 0; i < nbps; i++)
    {
        if (bps[i].enabled && bps[i].pending)
        {
            has_pending = 1;
            break;
        }
    }

    if (g_hidden_main_active || !has_pending)
        return;

    unsigned long addr = sym_to_addr("main");
    if (!addr)
        return;

    if (bp_by_addr(addr))
        return;

    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (w == -1 && errno)
        return;

    g_hidden_main_addr = addr;
    g_hidden_main_saved = w;

    long trap = (w & ~0xFFL) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        return;

    g_hidden_main_active = 1;
}

// removes the hidden main breakpoint when it is hit
static void hidden_main_remove(pid_t pid)
{
    if (!g_hidden_main_active)
        return;

    ptrace(PTRACE_POKEDATA, pid, (void *)g_hidden_main_addr, (void *)g_hidden_main_saved);
    g_hidden_main_active = 0;
}

// reads memory from the child process
// if an active breakpoint is inside this range, restore its original byte in the local buffer
static void read_child_mem(pid_t pid, unsigned long addr,
                           uint8_t *buf, size_t sz)
{
    size_t done = 0;
    while (done < sz)
    {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid,
                        (void *)(addr + done), 0);
        if (w == -1 && errno)
        {
            memset(buf + done, 0x90, sz - done);
            break;
        }
        size_t chunk = sz - done < 8 ? sz - done : 8;
        memcpy(buf + done, &w, chunk);
        done += chunk;
    }

    // patch back original bytes for display so disassembly looks correct
    for (int i = 0; i < nbps; i++)
    {
        BP *b = &bps[i];
        if (!b->active)
            continue;
        if (b->addr >= addr && b->addr < addr + sz)
            buf[b->addr - addr] = (uint8_t)(b->saved & 0xFF);
    }
}

// replaces address-looking operands with symbol names when possible
static void symbolize_operands(const char *in, char *out, size_t outsz)
{
    size_t oi = 0;

    for (size_t i = 0; in && in[i] && oi + 1 < outsz;)
    {
        if (in[i] == '0' && in[i + 1] == 'x')
        {
            char *end = NULL;
            unsigned long value = strtoull(&in[i], &end, 16);

            if (end && end != &in[i])
            {
                unsigned long off = 0;
                const char *sym = addr_to_sym_best(value, &off);

                if (sym)
                {
                    int n;

                    if (off == 0)
                        n = snprintf(out + oi, outsz - oi, "<%s>", sym);
                    else
                        n = snprintf(out + oi, outsz - oi, "<%s+0x%lx>", sym, off);

                    if (n < 0)
                        break;

                    oi += (size_t)n;
                    i = (size_t)(end - in);
                    continue;
                }
            }
        }

        out[oi++] = in[i++];
    }

    out[oi] = '\0';
}

// disassembles instructions starting from a given address
static void disas(pid_t pid, unsigned long addr, int max_n)
{
    uint8_t buf[256];
    read_child_mem(pid, addr, buf, sizeof(buf));

    csh cs;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK)
    {
        puts("[capstone: failed to open handle]");
        return;
    }

    // use at&t syntax to match gdb-style output
    cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    cs_insn *ins;
    size_t cnt = cs_disasm(cs, buf, sizeof(buf), addr, (size_t)(max_n + 1), &ins);

    int printed = 0;
    for (size_t i = 0; i < cnt && printed < max_n; i++, printed++)
    {
        unsigned long iaddr = (unsigned long)ins[i].address;

        // print symbol name if this address matches one
        const char *sym = addr_to_sym(iaddr);
        if (sym)
            printf("<%s>:\n", sym);

        char opbuf[512];
        symbolize_operands(ins[i].op_str, opbuf, sizeof(opbuf));

        // mark the current instruction with =>
        printf(" %s 0x%lx:\t%-8s %s\n",
               (iaddr == addr) ? "=>" : " ",
               iaddr, ins[i].mnemonic, opbuf);

        // stop early if we hit a return
        if (!strncmp(ins[i].mnemonic, "ret", 3))
            break;
    }

    cs_free(ins, cnt);
    cs_close(&cs);
}

// resets runtime-only information after the child exits
static void cleanup_after_run(void)
{
    reset_runtime_symbols();
    nruntime_exec_ranges = 0;
    g_hidden_main_active = 0;

    for (int i = 0; i < nbps; i++)
    {
        bps[i].active = 0;
        bps[i].saved = 0;

        if (!bps[i].enabled)
            continue;

        // raw runtime addresses are no longer valid after exit
        if (bps[i].run_specific)
        {
            bps[i].enabled = 0;
            continue;
        }

        // dynamic library breakpoints must be resolved again next run
        if (bps[i].runtime_sym)
        {
            bps[i].addr = 0;
            bps[i].pending = 1;
        }
    }
}

// handles child exit or signal termination and resets debugger state
static void child_died(int code, int by_signal)
{
    if (by_signal)
        printf("\n[mdb] Program terminated by signal %d.\n", code);
    else
        printf("\n[mdb] Program exited with code %d.\n", code);

    g_child = -1;
    g_alive = 0;

    cleanup_after_run();
}

// kills the current child process if there is one
static void kill_child(void)
{
    if (g_child > 0)
    {
        kill(g_child, SIGKILL);
        waitpid(g_child, NULL, 0);
        g_child = -1;
        g_alive = 0;
        cleanup_after_run();
    }
}

// builds argv for execv using the binary name and the arguments from r
static void build_child_argv(char *storage, char **argv, int max_args)
{
    int argc = 0;

    argv[argc++] = g_binary;

    if (g_run_args[0])
    {
        strncpy(storage, g_run_args, 511);
        storage[511] = '\0';

        char *tok = strtok(storage, " \t");
        while (tok && argc < max_args - 1)
        {
            argv[argc++] = tok;
            tok = strtok(NULL, " \t");
        }
    }

    argv[argc] = NULL;
}

// starts the target program under ptrace
// child calls ptrace(traceme), parent waits for the first stop after exec
static void start_child(void)
{
    kill_child();

    // reset dynamic addresses because shared libraries can move every run
    reset_runtime_symbols();
    bp_reset_for_new_run();

    pid_t pid = fork();
    if (pid < 0)
        die("fork: %s", strerror(errno));

    if (pid == 0)
    {
        // child says "my parent will debug me"
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            die("traceme: %s", strerror(errno));

        char arg_storage[512];
        char *argv[64];

        build_child_argv(arg_storage, argv, 64);

        execv(g_binary, argv);
        die("execv %s: %s", g_binary, strerror(errno));
    }

    // parent side
    g_child = pid;

    int status;
    waitpid(pid, &status, 0); // first stop after exec
    if (!WIFSTOPPED(status))
        die("unexpected child state after exec");

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    // first try to load symbols from anything already mapped
    resolve_dynamic_symbols(pid);

    // try to resolve pending breakpoints using the symbols we have now
    resolve_pending_breakpoints(pid);

    // install normal breakpoints from the breakpoint table
    bp_install_all(pid);

    // if some pending breakpoints still exist, stop once at main and retry there
    hidden_main_install(pid);

    g_alive = 1;
}

// continues the child until:
// 1. it hits one of our breakpoints
// 2. it exits
// when a breakpoint is hit, restore original byte and move rip back by 1
static int cont_and_wait(BP **hit)
{
    *hit = NULL;
    for (;;)
    {
        if (ptrace(PTRACE_CONT, g_child, 0, 0) == -1)
        {
            perror("ptrace CONT");
            return 0;
        }

        int status;
        waitpid(g_child, &status, 0);

        if (WIFEXITED(status))
        {
            child_died(WEXITSTATUS(status), 0);
            return 0;
        }
        if (WIFSIGNALED(status))
        {
            child_died(WTERMSIG(status), 1);
            return 0;
        }
        if (!WIFSTOPPED(status))
            continue;

        // every stop is a chance to discover newly mapped shared libraries
        resolve_dynamic_symbols(g_child);
        resolve_pending_breakpoints(g_child);

        int sig = WSTOPSIG(status);
        if (sig != SIGTRAP)
        {
            // pass non-trap signals back to the child and keep going
            ptrace(PTRACE_CONT, g_child, 0, (void *)(long)sig);
            continue;
        }

        // if we got sigtrap, check whether this was one of our breakpoints
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, g_child, 0, &regs);
        unsigned long hit_addr = (unsigned long)regs.rip - 1;

        if (g_hidden_main_active && hit_addr == g_hidden_main_addr)
        {
            // hidden main stop: restore main, resolve dynamic symbols, then keep running
            hidden_main_remove(g_child);
            regs.rip = hit_addr;
            ptrace(PTRACE_SETREGS, g_child, 0, &regs);

            resolve_dynamic_symbols(g_child);
            resolve_pending_breakpoints(g_child);

            if (ptrace(PTRACE_SINGLESTEP, g_child, 0, 0) == -1)
            {
                perror("singlestep");
                return 0;
            }

            waitpid(g_child, &status, 0);
            if (WIFEXITED(status))
            {
                child_died(WEXITSTATUS(status), 0);
                return 0;
            }
            if (WIFSIGNALED(status))
            {
                child_died(WTERMSIG(status), 1);
                return 0;
            }

            continue;
        }

        BP *b = bp_by_addr(hit_addr);
        if (!b)
        {
            continue;
        }

        // restore original instruction and rewind rip to the real instruction address
        bp_remove(g_child, b);
        regs.rip = hit_addr;
        ptrace(PTRACE_SETREGS, g_child, 0, &regs);

        g_cur_addr = hit_addr;
        *hit = b;
        return 1;
    }
}

// helper for validating raw address breakpoints before the program runs
static int is_known_binary_addr(unsigned long addr)
{
    return is_static_exec_addr(addr);
}

// checks if a command argument has extra whitespace
static int has_extra_words(const char *arg)
{
    if (!arg)
        return 0;

    for (int i = 0; arg[i]; i++)
    {
        if (arg[i] == ' ' || arg[i] == '\t')
            return 1;
    }

    return 0;
}

// handles: b <symbol> or b *<hex_addr>
static void cmd_b(const char *arg)
{
    if (!arg || !*arg)
    {
        puts("Usage: b <symbol> or b *<hex_addr>");
        return;
    }

    if (has_extra_words(arg))
    {
        puts("Usage: b <symbol> or b *<hex_addr>");
        return;
    }

    unsigned long addr = 0;
    if (arg[0] == '*')
    {
        char *end = NULL;
        addr = strtoull(arg + 1, &end, 16);
        if (*(arg + 1) == '\0' || *end != '\0')
        {
            printf("Invalid address: %s\n", arg);
            return;
        }

        if (!g_alive)
        {
            if (!is_known_binary_addr(addr))
            {
                printf("Address 0x%lx is not a valid executable address in the binary.\n", addr);
                return;
            }

            bp_add(addr, NULL, 0, 0);
        }
        else
        {
            resolve_dynamic_symbols(g_child);

            if (!is_runtime_exec_addr(addr))
            {
                printf("Address 0x%lx is not executable in the running process.\n", addr);
                return;
            }

            int run_specific = !is_static_exec_addr(addr);
            bp_add(addr, NULL, 0, run_specific);
        }
    }
    else
    {
        addr = sym_to_addr(arg);
        if (!addr)
        {
            printf("Symbol '%s' not found in binary.\n", arg);
            printf("Set pending breakpoint (enable when symbol resolves)? [y/N] ");
            fflush(stdout);
            char ans[8];
            if (fgets(ans, sizeof(ans), stdin) && (ans[0] == 'y' || ans[0] == 'Y'))
            {
                bp_add_pending(arg);
            }
            return;
        }

        if (!g_alive)
        {
            if (!is_static_exec_addr(addr) && !sym_is_runtime(arg))
            {
                printf("Symbol '%s' is not in executable code.\n", arg);
                return;
            }

            if (sym_is_runtime(arg))
            {
                bp_add_pending(arg);
                return;
            }

            bp_add(addr, arg, 0, 0);
        }
        else
        {
            resolve_dynamic_symbols(g_child);

            if (!is_runtime_exec_addr(addr))
            {
                printf("Symbol '%s' is not in executable memory.\n", arg);
                return;
            }

            bp_add(addr, arg, sym_is_runtime(arg), 0);
        }
    }

    // if the child is already stopped, install the breakpoint immediately
    if (g_alive && g_child > 0)
    {
        BP *b = bp_by_addr(addr);
        if (b && !b->active)
            bp_install(g_child, b);
    }
}

// lists enabled breakpoints and also unresolved pending ones
static void cmd_l(const char *arg)
{
    if (arg)
    {
        puts("Usage: l");
        return;
    }

    int any = 0;
    for (int i = 0; i < nbps; i++)
    {
        if (!bps[i].enabled)
            continue;

        if (!any)
            printf("%-4s %-20s %-10s %s\n", "Num", "Address", "State", "Symbol / Location");

        if (bps[i].pending)
        {
            printf("%-4d %-20s %-10s %s\n",
                   bps[i].id,
                   "<pending>",
                   "pending",
                   bps[i].requested);
        }
        else
        {
            const char *sym = addr_to_sym(bps[i].addr);
            printf("%-4d 0x%-18lx %-10s %s\n",
                   bps[i].id,
                   bps[i].addr,
                   bps[i].active ? "active" : "set",
                   sym ? sym : bps[i].label);
        }

        any = 1;
    }

    if (!any)
        puts("No breakpoints.");
}

// deletes a breakpoint by its number
static void cmd_d(const char *arg)
{
    if (!arg || !*arg)
    {
        puts("Usage: d <num>");
        return;
    }

    if (has_extra_words(arg))
    {
        puts("Usage: d <breakpoint_number>");
        return;
    }

    char *end = NULL;
    long id_long = strtol(arg, &end, 10);

    if (!arg || !*arg || *end != '\0' || id_long <= 0)
    {
        puts("Usage: d <breakpoint_number>");
        return;
    }

    int id = (int)id_long;

    BP *b = bp_by_id(id);
    if (!b || !b->enabled)
    {
        printf("No breakpoint %d.\n", id);
        return;
    }

    if (b->active && g_child > 0)
        bp_remove(g_child, b);

    b->enabled = 0;
    b->active = 0;
    b->pending = 0;

    printf("Deleted breakpoint %d.\n", id);
}

// starts or restarts the target and runs until first breakpoint or exit
static void cmd_r(const char *arg)
{
    if (arg)
    {
        strncpy(g_run_args, arg, sizeof(g_run_args) - 1);
        g_run_args[sizeof(g_run_args) - 1] = '\0';
    }
    else
    {
        g_run_args[0] = '\0';
    }

    if (g_alive)
    {
        printf("Program is already running. Kill and restart? [y/N] ");
        fflush(stdout);
        char ans[8];
        if (!fgets(ans, sizeof(ans), stdin) || (ans[0] != 'y' && ans[0] != 'Y'))
            return;
    }

    printf("[mdb] Starting %s\n", g_binary);
    start_child();
    g_cur_addr = 0;

    BP *hit;
    int stopped = cont_and_wait(&hit);
    if (stopped && hit)
    {
        g_cur_addr = hit->addr;

        printf("\nBreakpoint %d hit: %s (0x%lx)\n",
               hit->id, hit->label, hit->addr);
        disas(g_child, hit->addr, DISASM_N);
    }
}

// continues execution until next breakpoint or program exit
static void cmd_c(const char *arg)
{
    if (arg)
    {
        puts("Usage: c");
        return;
    }
    if (!g_alive)
    {
        puts("No program running. Use 'r' to start.");
        return;
    }

    // if we stopped exactly on a breakpoint, int3 has already been removed
    // so we single-step the real instruction once, then re-install the breakpoint
    BP *cur = bp_by_addr(g_cur_addr);
    if (cur && cur->enabled && !cur->active)
    {
        if (ptrace(PTRACE_SINGLESTEP, g_child, 0, 0) == -1)
        {
            perror("singlestep");
            return;
        }

        int status;
        waitpid(g_child, &status, 0);

        if (WIFEXITED(status))
        {
            child_died(WEXITSTATUS(status), 0);
            return;
        }
        if (WIFSIGNALED(status))
        {
            child_died(WTERMSIG(status), 1);
            return;
        }

        resolve_dynamic_symbols(g_child);
        resolve_pending_breakpoints(g_child);

        bp_install(g_child, cur);
    }

    BP *hit;
    int stopped = cont_and_wait(&hit);
    if (stopped && hit)
    {
        printf("\nBreakpoint %d hit: %s (0x%lx)\n",
               hit->id, hit->label, hit->addr);
        disas(g_child, hit->addr, DISASM_N);
    }
}

// single-steps exactly one instruction
static void cmd_si(const char *arg)
{
    if (arg)
    {
        puts("Usage: si");
        return;
    }
    if (!g_alive)
    {
        puts("No program running. Use 'r' to start.");
        return;
    }

    if (ptrace(PTRACE_SINGLESTEP, g_child, 0, 0) == -1)
    {
        perror("singlestep");
        return;
    }

    int status;
    waitpid(g_child, &status, 0);
    if (WIFEXITED(status))
    {
        child_died(WEXITSTATUS(status), 0);
        return;
    }
    if (WIFSIGNALED(status))
    {
        child_died(WTERMSIG(status), 1);
        return;
    }

    resolve_dynamic_symbols(g_child);
    resolve_pending_breakpoints(g_child);

    // if we just stepped over a breakpoint location, re-arm it
    BP *old = bp_by_addr(g_cur_addr);
    if (old && old->enabled && !old->active)
        bp_install(g_child, old);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, g_child, 0, &regs);
    g_cur_addr = (unsigned long)regs.rip;

    unsigned long off = 0;
    const char *sym = addr_to_sym_best(g_cur_addr, &off);

    if (sym && off == 0)
        printf("=> 0x%lx <%s>\n", g_cur_addr, sym);
    else if (sym)
        printf("=> 0x%lx <%s+0x%lx>\n", g_cur_addr, sym, off);
    else
        printf("=> 0x%lx\n", g_cur_addr);
}

// disassembles from the current address
static void cmd_disas(const char *arg)
{
    if (arg)
    {
        puts("Usage: disas");
        return;
    }
    if (!g_alive)
    {
        puts("No program running.");
        return;
    }
    disas(g_child, g_cur_addr, DISASM_N);
}

// prints available commands
static void help(void)
{
    puts("Commands:");
    puts(" b <sym> | b *<hex> Set software breakpoint");
    puts(" l List breakpoints");
    puts(" d <num> Delete breakpoint");
    puts(" r [args...] Run (or restart) the program");
    puts(" c Continue until next breakpoint");
    puts(" si Single-step one instruction");
    puts(" disas Disassemble at current position");
    puts(" q / quit Exit mdb");
}

// parses one input line and calls the matching command handler
static void dispatch(char *line)
{
    // remove newline and skip leading spaces
    line[strcspn(line, "\n")] = 0;
    while (*line == ' ' || *line == '\t')
        line++;
    if (!*line)
        return;

    char *cmd = strtok(line, " \t");
    if (!cmd)
        return;

    char *arg = strtok(NULL, "");
    if (arg)
    {
        while (*arg == ' ' || *arg == '\t')
            arg++;
        if (!*arg)
            arg = NULL;
    }

    if (!strcmp(cmd, "b"))
        cmd_b(arg);
    else if (!strcmp(cmd, "l"))
        cmd_l(arg);
    else if (!strcmp(cmd, "d"))
        cmd_d(arg);
    else if (!strcmp(cmd, "r"))
        cmd_r(arg);
    else if (!strcmp(cmd, "c"))
        cmd_c(arg);
    else if (!strcmp(cmd, "si"))
        cmd_si(arg);
    else if (!strcmp(cmd, "disas"))
        cmd_disas(arg);
    else if (!strcmp(cmd, "help") || !strcmp(cmd, "h"))
        help();
    else if (!strcmp(cmd, "q") || !strcmp(cmd, "quit"))
    {
        kill_child();
        exit(0);
    }
    else
        printf("Unknown command '%s'. Type 'help' for a list.\n", cmd);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: mdb <binary>\n");
        return 1;
    }

    g_binary = argv[1];
    load_symbols(g_binary);
    help();
    putchar('\n');

    char line[512];
    for (;;)
    {
        printf("(mdb) ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin))
            break;
        dispatch(line);
    }

    kill_child();
    return 0;
}
