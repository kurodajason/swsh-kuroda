// NSO loading, relocation, and symbol resolution.
#include <stdlib.h>
#include <string.h>

#include "rt.h"

Module g_modules[4];
int g_nmodules;

enum { DT_NULL = 0, DT_PLTRELSZ = 2, DT_HASH = 4, DT_STRTAB = 5, DT_SYMTAB = 6, DT_RELA = 7, DT_RELASZ = 8,
       DT_JMPREL = 23, DT_INIT_ARRAY = 25, DT_FINI_ARRAY = 26, DT_INIT_ARRAYSZ = 27, DT_FINI_ARRAYSZ = 28 };
enum { R_ABS64 = 257, R_GLOB_DAT = 1025, R_JUMP_SLOT = 1026, R_RELATIVE = 1027 };

typedef struct { uint32_t name; uint8_t info, other; uint16_t shndx; uint64_t value, size; } Elf64Sym;
typedef struct { uint64_t off, info; int64_t addend; } Elf64Rela;

static size_t lz4_decompress(const uint8_t *src, size_t srclen, uint8_t *dst, size_t dstlen) {
    const uint8_t *s = src, *se = src + srclen;
    uint8_t *d = dst, *de = dst + dstlen;
    while (s < se) {
        uint8_t tok = *s++;
        size_t lit = tok >> 4;
        if (lit == 15) { uint8_t b; do { b = *s++; lit += b; } while (b == 255); }
        if (d + lit > de || s + lit > se) break;
        memcpy(d, s, lit);
        d += lit; s += lit;
        if (s >= se) break;
        size_t off = s[0] | (s[1] << 8);
        s += 2;
        size_t ml = tok & 15;
        if (ml == 15) { uint8_t b; do { b = *s++; ml += b; } while (b == 255); }
        ml += 4;
        uint8_t *m = d - off;
        if (m < dst || d + ml > de) break;
        while (ml--) *d++ = *m++;
    }
    return d - dst;
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *p = malloc(*len);
    fread(p, 1, *len, f);
    fclose(f);
    return p;
}

static void load_nso(Module *m, const char *path, uint64_t base) {
    size_t len;
    uint8_t *raw = read_file(path, &len);
    if (!raw || memcmp(raw, "NSO0", 4)) FATAL("cannot load %s\n", path);
    uint32_t flags = *(uint32_t *)(raw + 0xC);
    uint32_t seg[3][3];  // file_off, mem_off, size
    for (int i = 0; i < 3; i++) memcpy(seg[i], raw + 0x10 + i * 0x10, 12);
    uint32_t bss = *(uint32_t *)(raw + 0x3C);
    uint64_t size = (seg[2][1] + seg[2][2] + bss + 0x3FFF) & ~0x3FFFull;
    plat_commit(base, size);  // inside the guest window: zero-filled, read/write
    for (int i = 0; i < 3; i++) {
        uint32_t csize = *(uint32_t *)(raw + 0x60 + i * 4);
        uint8_t *dst = (uint8_t *)base + seg[i][1];
        if (flags & (1 << i)) {
            size_t got = lz4_decompress(raw + seg[i][0], csize, dst, seg[i][2]);
            if (got != seg[i][2]) FATAL("lz4 %s seg %d: %zu != %u\n", path, i, got, seg[i][2]);
        } else {
            memcpy(dst, raw + seg[i][0], seg[i][2]);
        }
    }
    free(raw);
    m->base = base;
    m->size = size;
    m->text_off = seg[0][1]; m->text_size = seg[0][2];
    m->ro_off = seg[1][1];   m->ro_size = seg[1][2];
    m->data_off = seg[2][1]; m->data_size = seg[2][2] + bss;

    uint32_t mod0 = *(uint32_t *)(base + 4);
    uint64_t mod = base + mod0;
    m->dynamic = mod + *(int32_t *)(mod + 4);
    for (uint64_t *d = (uint64_t *)m->dynamic; d[0] != DT_NULL; d += 2) {
        switch (d[0]) {
        case DT_SYMTAB: m->symtab = base + d[1]; break;
        case DT_STRTAB: m->strtab = base + d[1]; break;
        case DT_HASH: m->nsyms = *(uint32_t *)(base + d[1] + 4); break;
        case 12: m->init = base + d[1]; break;  // DT_INIT
        case 13: m->fini = base + d[1]; break;  // DT_FINI
        case DT_INIT_ARRAY: m->init_array = base + d[1]; break;
        case DT_INIT_ARRAYSZ: m->init_array_sz = d[1]; break;
        case DT_FINI_ARRAY: m->fini_array = base + d[1]; break;
        case DT_FINI_ARRAYSZ: m->fini_array_sz = d[1]; break;
        }
    }
    LOG("loaded %-5s at %llx size %llx syms %llu\n", m->name, base, size, m->nsyms);
}

static Elf64Sym *sym(Module *m, uint64_t i) { return (Elf64Sym *)m->symtab + i; }
static const char *symname(Module *m, Elf64Sym *s) { return (const char *)(m->strtab + s->name); }

static uint64_t find_exact(const char *name) {
    for (int mi = 0; mi < g_nmodules; mi++) {
        Module *m = &g_modules[mi];
        for (uint64_t i = 1; i < m->nsyms; i++) {
            Elf64Sym *s = sym(m, i);
            if (s->shndx && !strcmp(symname(m, s), name)) return m->base + s->value;
        }
    }
    return 0;
}

// (diagnostics) the defined symbols whose names contain `needle`, at most `max`
static void log_symbols(const char *needle, int max) {
    int n = 0;
    for (int mi = 0; mi < g_nmodules && n < max; mi++) {
        Module *m = &g_modules[mi];
        for (uint64_t i = 1; i < m->nsyms && n < max; i++) {
            Elf64Sym *s = sym(m, i);
            if (s->shndx && strstr(symname(m, s), needle)) {
                LOG("  [%s] %llx %s\n", m->name, (unsigned long long)(m->base + s->value), symname(m, s));
                n++;
            }
        }
    }
    if (!n) LOG("  (none)\n");
}

uint64_t loader_find_symbol(const char *name) {
    uint64_t a = find_exact(name);
    static const char start_prefix[] = "_ZN2nn4init5Start";
    if (a || strncmp(name, start_prefix, sizeof start_prefix - 1)) return a;
    // Scarlet/Violet's SDK may spell nn::init::Start with another signature, or not export it: take any overload
    // (same arguments as before), and log what is there either way.
    LOG("[loader] %s is not in the game: other nn::init::Start spellings:\n", name);
    log_symbols(start_prefix, 20);
    for (int mi = 0; mi < g_nmodules; mi++) {
        Module *m = &g_modules[mi];
        for (uint64_t i = 1; i < m->nsyms; i++) {
            Elf64Sym *s = sym(m, i);
            if (s->shndx && !strncmp(symname(m, s), start_prefix, sizeof start_prefix - 1)) {
                LOG("[loader] using %s\n", symname(m, s));
                return m->base + s->value;
            }
        }
    }
    LOG("[loader] no nn::init::Start at all. Symbols with nn4init / nnMain / nninitStartup:\n");
    log_symbols("nn4init", 100);
    log_symbols("nnMain", 10);
    log_symbols("nninitStartup", 10);
    return 0;
}

const char *loader_symbol_at(uint64_t addr, uint64_t *offset) {
    const char *best = NULL;
    uint64_t best_addr = 0;
    for (int mi = 0; mi < g_nmodules; mi++) {
        Module *m = &g_modules[mi];
        if (addr < m->base || addr >= m->base + m->size) continue;
        for (uint64_t i = 1; i < m->nsyms; i++) {
            Elf64Sym *s = sym(m, i);
            uint64_t a = m->base + s->value;
            if (s->shndx && (s->info & 0xF) == 2 && a <= addr && a > best_addr) {
                best = symname(m, s);
                best_addr = a;
            }
        }
    }
    if (offset) *offset = addr - best_addr;
    return best;
}

// (diagnostics, Violet bring-up) names and code words of the addresses a crash report pointed at
static int in_module(uint64_t a) {
    for (int i = 0; i < g_nmodules; i++)
        if (a >= g_modules[i].base && a < g_modules[i].base + g_modules[i].size) return 1;
    return 0;
}
static void diag_name(uint64_t a) {
    uint64_t off = 0;
    const char *n = in_module(a) ? loader_symbol_at(a, &off) : NULL;
    LOG("  %llx = %s+%llx\n", (unsigned long long)a, n ? n : "(no symbol)", (unsigned long long)off);
}
// the symbol a GOT slot is bound to (from the module's relocation tables), or NULL
static const char *got_symbol(uint64_t got) {
    for (int mi = 0; mi < g_nmodules; mi++) {
        Module *m = &g_modules[mi];
        uint64_t rela = 0, relasz = 0, jmprel = 0, pltsz = 0;
        for (uint64_t *d = (uint64_t *)m->dynamic; d[0] != DT_NULL; d += 2) {
            if (d[0] == DT_RELA) rela = m->base + d[1];
            if (d[0] == DT_RELASZ) relasz = d[1];
            if (d[0] == DT_JMPREL) jmprel = m->base + d[1];
            if (d[0] == DT_PLTRELSZ) pltsz = d[1];
        }
        for (int pass = 0; pass < 2; pass++) {
            Elf64Rela *r = (Elf64Rela *)(pass ? jmprel : rela);
            uint64_t n = (pass ? pltsz : relasz) / sizeof(Elf64Rela);
            for (uint64_t i = 0; i < n; i++)
                if (m->base + r[i].off == got) {
                    uint32_t type = (uint32_t)r[i].info, si = (uint32_t)(r[i].info >> 32);
                    return (type == R_RELATIVE || !si) ? "(local)" : symname(m, sym(m, si));
                }
        }
    }
    return NULL;
}
// a PLT stub (adrp x16 / ldr x17,[x16,#o] / add / br x17): the name of the import behind it
static const char *plt_symbol(uint64_t stub) {
    uint32_t w0 = *(uint32_t *)stub, w1 = *(uint32_t *)(stub + 4);
    if ((w0 & 0x9F00001F) != 0x90000010 || (w1 & 0xFFC003FF) != 0xF9400211) return NULL;
    int64_t imm = (int64_t)((((w0 >> 5) & 0x7FFFF) << 2) | ((w0 >> 29) & 3));
    if (imm & (1 << 20)) imm -= 1 << 21;
    uint64_t got = (stub & ~0xFFFull) + (uint64_t)(imm << 12) + (uint64_t)((w1 >> 10) & 0xFFF) * 8;
    return got_symbol(got);
}
// every `msr tpidr_el0, xN` in the modules (who sets the thread pointer)
static void diag_tp_writers(void) {
    int n = 0;
    for (int mi = 0; mi < g_nmodules && n < 40; mi++) {
        Module *m = &g_modules[mi];
        for (uint64_t o = 0; o < m->text_size && n < 40; o += 4) {
            uint32_t w = *(uint32_t *)(m->base + m->text_off + o);
            if ((w & 0xFFFFFFE0) == 0xD51BD040) {
                uint64_t a = m->base + m->text_off + o, off = 0;
                const char *nm = loader_symbol_at(a, &off);
                LOG("  [%s] %llx msr tpidr_el0 in %s+%llx\n", m->name, (unsigned long long)a, nm ? nm : "?", (unsigned long long)off);
                n++;
            }
        }
    }
    if (!n) LOG("  (none)\n");
}

static void diag_code(uint64_t a, int nwords);
static void diag_sym(const char *name, int nwords) {  // the code of an exported function, from its start
    uint64_t a = find_exact(name);
    if (!a) { LOG("  %s: not found\n", name); return; }
    LOG("  %s at %llx\n", name, (unsigned long long)a);
    diag_code(a, nwords);
}

static void diag_code(uint64_t a, int nwords) {  // the words, and the function each bl calls
    if (!in_module(a) || !in_module(a + (uint64_t)nwords * 4 - 4)) return;
    for (int i = 0; i < nwords; i++) {
        uint64_t pc = a + (uint64_t)i * 4;
        uint32_t w = *(uint32_t *)pc;
        if ((w & 0xFC000000) == 0x94000000) {  // BL
            int64_t imm = w & 0x03FFFFFF;
            if (imm & 0x02000000) imm -= 0x04000000;
            uint64_t t = pc + (uint64_t)(imm * 4), off = 0;
            const char *n = in_module(t) ? loader_symbol_at(t, &off) : NULL;
            const char *p = in_module(t) ? plt_symbol(t) : NULL;
            if (p) LOG("  %llx: %08x  bl %llx  PLT -> %s\n", (unsigned long long)pc, w, (unsigned long long)t, p);
            else LOG("  %llx: %08x  bl %llx (%s+%llx)\n", (unsigned long long)pc, w, (unsigned long long)t,
                     n ? n : "?", (unsigned long long)off);
        } else {
            LOG("  %llx: %08x\n", (unsigned long long)pc, w);
        }
    }
}

// (diagnostics, Violet bring-up) every instruction that reads, writes or takes the address of `addr`, found by the
// adrp + ldr/str/add pattern the compiler uses for globals
static void diag_find_refs(uint64_t addr) {
    uint64_t page = addr & ~0xFFFull, off = addr & 0xFFF;
    int n = 0;
    for (int mi = 0; mi < g_nmodules; mi++) {
        Module *m = &g_modules[mi];
        uint64_t t0 = m->base + m->text_off;
        for (uint64_t o = 0; o + 4 <= m->text_size && n < 60; o += 4) {
            uint32_t w = *(uint32_t *)(t0 + o);
            if ((w & 0x9F000000) != 0x90000000) continue;  // adrp
            uint64_t pc = t0 + o;
            int64_t imm = (int64_t)((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3));
            if (imm & (1 << 20)) imm -= 1 << 21;
            if (((pc & ~0xFFFull) + (uint64_t)(imm << 12)) != page) continue;
            uint32_t rd = w & 0x1F;
            for (int k = 1; k <= 32 && o + 4 * (uint64_t)k < m->text_size; k++) {
                uint32_t v = *(uint32_t *)(pc + 4 * (uint64_t)k);
                if (((v >> 5) & 0x1F) != rd) continue;
                uint32_t i12 = (v >> 10) & 0xFFF;
                const char *kind = NULL;
                if ((v & 0xFFC00000) == 0xF9000000 && i12 == off / 8) kind = "STORE (64-bit)";
                else if ((v & 0xFFC00000) == 0xB9000000 && i12 == off / 4) kind = "STORE (32-bit)";
                else if ((v & 0xFFC00000) == 0xF9400000 && i12 == off / 8) kind = "load (64-bit)";
                else if ((v & 0xFFC00000) == 0x91000000 && i12 == off) kind = "address taken (add)";
                if (!kind) continue;
                uint64_t a = pc + 4 * (uint64_t)k, so = 0;
                const char *sn = loader_symbol_at(a, &so);
                LOG("[refs] %llx %s in %s+%llx\n", (unsigned long long)a, kind, sn ? sn : "(no symbol)", (unsigned long long)so);
                n++;
                break;
            }
        }
    }
    if (!n) LOG("[refs] nothing refers to %llx\n", (unsigned long long)addr);
}

void loader_diag_code(uint64_t a, int n) { diag_code(a, n); }  // (for the crash report in dispatch.c)

// (diagnostics, Violet bring-up) at a trap / undefined instruction: the code words around it (bl targets named) and the
// guest call chain. Called from rt_udf / rt_brk (dispatch.c).
void loader_trap_report(Cpu *c, uint64_t pc) {
    LOG("[trap] pc %llx, word %08x; code from pc-0x40:\n", (unsigned long long)pc, in_module(pc) ? *(uint32_t *)pc : 0u);
    diag_code(pc - 0x40, 24);
    uint64_t fp = c->x[29];
    LOG("[trap] guest call chain (lr %llx):\n", (unsigned long long)c->x[30]);
    for (int i = 0; i < 16 && fp >= GUEST_LO && fp < GUEST_HI && !(fp & 7); i++) {
        uint64_t next = ((uint64_t *)fp)[0], ret = ((uint64_t *)fp)[1], off = 0;
        const char *n = in_module(ret) ? loader_symbol_at(ret, &off) : NULL;
        LOG("[trap]   %llx  %s+%llx\n", (unsigned long long)ret, n ? n : "(no symbol)", (unsigned long long)off);
        if (next <= fp) break;
        fp = next;
    }
}

static uint64_t resolve(Module *m, uint32_t symidx) {
    Elf64Sym *s = sym(m, symidx);
    const char *name = symname(m, s);
    if (s->shndx) return m->base + s->value;
    HostFn impl = hle_lookup_impl(name);
    if (impl) return hle_register(name, impl);  // host implementation wins over the guest SDK's
    uint64_t a = loader_find_symbol(name);
    if (a) return a;
    if ((s->info >> 4) == 2) {  // weak undefined
        static int weak_logged;  // (diagnostics, Violet bring-up: a weak import that resolves to null)
        if (weak_logged++ < 80) LOG("[loader] %s: weak undefined import %s -> null\n", m->name, name);
        return 0;
    }
    static int stubs_logged;  // (diagnostics: the imports nothing implements)
    if (stubs_logged++ < 200) LOG("[loader] %s: import %s has no host implementation\n", m->name, name);
    return hle_register(name, NULL);
}

static void relocate(Module *m) {
    uint64_t rela = 0, relasz = 0, jmprel = 0, pltsz = 0, relr = 0, relrsz = 0;
    for (uint64_t *d = (uint64_t *)m->dynamic; d[0] != DT_NULL; d += 2) {
        if (d[0] == DT_RELA) rela = m->base + d[1];
        if (d[0] == DT_RELASZ) relasz = d[1];
        if (d[0] == DT_JMPREL) jmprel = m->base + d[1];
        if (d[0] == DT_PLTRELSZ) pltsz = d[1];
        if (d[0] == 36) relr = m->base + d[1];   // DT_RELR: packed relative relocations (newer linkers)
        if (d[0] == 35) relrsz = d[1];           // DT_RELRSZ
    }
    if (relr && relrsz) {  // each even entry is an address to fix up, each odd entry a bitmap of the next 63 words
        uint64_t *e = (uint64_t *)relr, *where = NULL, count = 0;
        for (uint64_t i = 0; i < relrsz / 8; i++) {
            if (!(e[i] & 1)) {
                where = (uint64_t *)(m->base + e[i]);
                *where += m->base; count++; where++;
            } else {
                uint64_t bits = e[i] >> 1;
                for (int j = 0; bits; j++, bits >>= 1)
                    if (bits & 1) { where[j] += m->base; count++; }
                where += 63;
            }
        }
        LOG("[reloc] %s: %llu packed (RELR) relative relocations applied\n", m->name, (unsigned long long)count);
    }
    int unresolved = 0;
    for (int pass = 0; pass < 2; pass++) {
        Elf64Rela *r = (Elf64Rela *)(pass ? jmprel : rela);
        uint64_t n = (pass ? pltsz : relasz) / sizeof(Elf64Rela);
        for (uint64_t i = 0; i < n; i++) {
            uint64_t *where = (uint64_t *)(m->base + r[i].off);
            uint32_t type = (uint32_t)r[i].info, si = r[i].info >> 32;
            switch (type) {
            case R_RELATIVE: *where = m->base + r[i].addend; break;
            case R_ABS64:
            case R_GLOB_DAT:
            case R_JUMP_SLOT: {
                uint64_t s = resolve(m, si);
                if ((uint64_t)where == 0x7008cd6bc0ull)  // (diagnostics) the import the last crash went through
                    LOG("[diag] import slot %llx is the symbol %s\n", (unsigned long long)(uint64_t)where, symname(m, sym(m, si)));
                *where = s ? s + r[i].addend : 0;
                if (s >= HLE_BASE && s < HLE_BASE + HLE_SIZE) unresolved++;
                break;
            }
            default: FATAL("%s: reloc type %u\n", m->name, type);
            }
        }
    }
    LOG("relocated %-5s (%d imports bound to host stubs)\n", m->name, unresolved);
}

void loader_load(const char *exefs) {
    char path[1024];
    // The game, the SDK, glslc (runtime GLSL compiler) and multimedia (movie::): Let's Go has glslc as subsdk0,
    // Sword/Shield as subsdk1. Imports bind by name (resolve), so only the names and bases matter. Same order and
    // bases as the generated code (Makefile `gen`, tools/gamelib_entry.c).
    static const struct { const char *name; uint64_t base; } mods[] = {
        {"main", MAIN_BASE}, {"sdk", SDK_BASE}, {"subsdk0", SUBSDK0_BASE}, {"subsdk1", SUBSDK1_BASE}};
    for (unsigned i = 0; i < sizeof mods / sizeof mods[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", exefs, mods[i].name);
        FILE *probe = fopen(path, "rb");
        if (!probe && !strcmp(mods[i].name, "subsdk1")) continue;  // optional: Scarlet/Violet have only subsdk0
        if (probe) fclose(probe);
        Module *m = &g_modules[g_nmodules++];
        m->name = mods[i].name;
        load_nso(m, path, mods[i].base);
    }
    for (int i = 0; i < g_nmodules; i++) relocate(&g_modules[i]);
    // (diagnostics, Violet bring-up, round 4) the game's default allocator pointer: it is null at the first malloc
    LOG("[diag] default allocator global 7004759418 after relocation: %llx\n", (unsigned long long)*(uint64_t *)0x7004759418ull);
}
