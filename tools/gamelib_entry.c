// Entry of the game code library (runtime/gamelib.h), compiled into it with the generated code: the function
// tables, found by name when the app loads the library. Everything else in it stays hidden.
// NO_SUBSDK1 (set by runtime/gamebuild.c when the game has no subsdk1, e.g. Scarlet/Violet): three modules, not four.
#include "gamelib.h"

#define MOD(n) extern const uint64_t n##_fn_addrs[], n##_fn_count; extern const GuestFn n##_fn_ptrs[];
MOD(main) MOD(sdk) MOD(subsdk0)
#ifndef NO_SUBSDK1
MOD(subsdk1)
#endif
#undef MOD
#define TAB(n) {#n, n##_fn_addrs, n##_fn_ptrs, &n##_fn_count}

GAMELIB_EXPORT const GameLibTables *lasgame_tables(void) {
#ifdef NO_SUBSDK1
    static const GameLibTables t = {GAMELIB_ABI, GAMELIB_ID, 3, {TAB(main), TAB(sdk), TAB(subsdk0)}};
#else
    static const GameLibTables t = {GAMELIB_ABI, GAMELIB_ID, 4, {TAB(main), TAB(sdk), TAB(subsdk0), TAB(subsdk1)}};
#endif
    return &t;
}
