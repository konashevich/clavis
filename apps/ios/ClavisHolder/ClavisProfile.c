#include "ClavisProfile.h"

/*
 * Weak stand-in used until the Rust core supplies this symbol.
 * Returns -1 and writes nothing. A strong definition replaces it at link time.
 */
__attribute__((weak))
int32_t clavis_profile(uint8_t *out, size_t cap) {
    (void)out;
    (void)cap;
    return -1;
}
