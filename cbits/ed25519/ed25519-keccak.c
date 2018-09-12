/*
	Public domain by Andrew M. <liquidsun@gmail.com>

	Ed25519 reference implementation using Ed25519-donna using sha3 hash for nem token
*/


#define ED25519_FN(fn)         cryptonite_##fn

#include "ed25519-donna.h"
#include "ed25519-keccak.h"
#include "ed25519-randombytes.h"
#include "ed25519-keccak-hash.h"
#include "ed25519-cryptonite-exts.h"

/*
	Generates a (extsk[0..31]) and aExt (extsk[32..63])
*/

DONNA_INLINE static void
ed25519_extsk(hash_512bits extsk, const ed25519_keccak_secret_key sk) {
	ed25519_keccak_hash(extsk, sk, 32);
	extsk[0] &= 248;
	extsk[31] &= 127;
	extsk[31] |= 64;
}

static void
ed25519_keccak_hram(hash_512bits hram, const ed25519_keccak_signature RS, const ed25519_keccak_public_key pk, const unsigned char *m, size_t mlen) {
	ed25519_keccak_hash_context ctx;
	ed25519_keccak_hash_init(&ctx);
	ed25519_keccak_hash_update(&ctx, RS, 32);
	ed25519_keccak_hash_update(&ctx, pk, 32);
	ed25519_keccak_hash_update(&ctx, m, mlen);
	ed25519_keccak_hash_final(&ctx, hram);
}

void
ED25519_FN(ed25519_keccak_publickey) (const ed25519_keccak_secret_key sk, ed25519_keccak_public_key pk) {
	bignum256modm a;
	ge25519 ALIGN(16) A;
	hash_512bits extsk;

	/* A = aB */
	ed25519_extsk(extsk, sk);
	expand256_modm(a, extsk, 32);
	ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
	ge25519_pack(pk, &A);
}


void
ED25519_FN(ed25519_keccak_sign) (const unsigned char *m, size_t mlen, const ed25519_keccak_secret_key sk, const ed25519_keccak_public_key pk, ed25519_keccak_signature RS) {
	ed25519_keccak_hash_context ctx;
	bignum256modm r, S, a;
	ge25519 ALIGN(16) R;
	hash_512bits extsk, hashr, hram;

	ed25519_extsk(extsk, sk);

	/* r = H(aExt[32..64], m) */
	ed25519_keccak_hash_init(&ctx);
	ed25519_keccak_hash_update(&ctx, extsk + 32, 32);
	ed25519_keccak_hash_update(&ctx, m, mlen);
	ed25519_keccak_hash_final(&ctx, hashr);
	expand256_modm(r, hashr, 64);

	/* R = rB */
	ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
	ge25519_pack(RS, &R);

	/* S = H(R,A,m).. */
	ed25519_keccak_hram(hram, RS, pk, m, mlen);
	expand256_modm(S, hram, 64);

	/* S = H(R,A,m)a */
	expand256_modm(a, extsk, 32);
	mul256_modm(S, S, a);

	/* S = (r + H(R,A,m)a) */
	add256_modm(S, S, r);

	/* S = (r + H(R,A,m)a) mod L */
	contract256_modm(RS + 32, S);
}

int
ED25519_FN(ed25519_keccak_sign_open) (const unsigned char *m, size_t mlen, const ed25519_keccak_public_key pk, const ed25519_keccak_signature RS) {
	ge25519 ALIGN(16) R, A;
	hash_512bits hash;
	bignum256modm hram, S;
	unsigned char checkR[32];

	if ((RS[63] & 224) || !ge25519_unpack_negative_vartime(&A, pk))
		return -1;

	/* hram = H(R,A,m) */
	ed25519_keccak_hram(hash, RS, pk, m, mlen);
	expand256_modm(hram, hash, 64);

	/* S */
	expand256_modm(S, RS + 32, 32);

	/* SB - H(R,A,m)A */
	ge25519_double_scalarmult_vartime(&R, &A, hram, S);
	ge25519_pack(checkR, &R);

	/* check that R = SB - H(R,A,m)A */
	return ed25519_verify(RS, checkR, 32) ? 0 : -1;
}
