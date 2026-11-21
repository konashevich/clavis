#ifndef CLAVIS_PROFILE_H
#define CLAVIS_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Writes the profile string bytes into out and returns the count. */
int32_t clavis_profile(uint8_t *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* CLAVIS_PROFILE_H */
