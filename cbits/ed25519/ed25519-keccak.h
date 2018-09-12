#ifndef ED25519_KECCAK_H
#define ED25519_KECCAK_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char ed25519_keccak_signature[64];
typedef unsigned char ed25519_keccak_public_key[32];
typedef unsigned char ed25519_keccak_secret_key[32];

// typedef unsigned char curved25519_keccak_key[32];

void cryptonite_ed25519_keccak_publickey(const ed25519_keccak_secret_key sk, ed25519_keccak_public_key pk);
int cryptonite_ed25519_keccak_sign_open(const unsigned char *m, size_t mlen, const ed25519_keccak_public_key pk, const ed25519_keccak_signature RS);
void cryptonite_ed25519_keccak_sign(const unsigned char *m, size_t mlen, const ed25519_keccak_secret_key sk, const ed25519_keccak_public_key pk, ed25519_keccak_signature RS);


#if defined(__cplusplus)
}
#endif

#endif // ED25519_KECCAK_H
