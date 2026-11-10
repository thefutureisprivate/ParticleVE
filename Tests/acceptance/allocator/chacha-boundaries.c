/* Test the narrow pointer-lifetime patch against the tagged upstream source.
 * The unmodified reference is compiled separately at O0; this binary neither
 * implements ChaCha nor changes allocator configuration.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "chacha.h"

void reference_chacha_keysetup(chacha_ctx *, const u8 *);
void reference_chacha_ivsetup(chacha_ctx *, const u8 *);
void reference_chacha_keystream_bytes(chacha_ctx *, u8 *, u32);

int main(void) {
        static const u32 lengths[] = {0, 1, 2, 31, 32, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024, 1025};
        static const u32 counters[] = {0, UINT32_MAX - 1, UINT32_MAX};
        unsigned cases = 0;
        for (unsigned pattern = 0; pattern < 3; ++pattern) {
                u8 key[CHACHA_KEY_SIZE], nonce[CHACHA_IV_SIZE];
                for (unsigned i = 0; i < sizeof(key); ++i)
                        key[i] = pattern == 0 ? 0 : pattern == 1 ? (u8) i : 0xff;
                for (unsigned i = 0; i < sizeof(nonce); ++i)
                        nonce[i] = (u8) (i * pattern);
                for (unsigned c = 0; c < sizeof(counters) / sizeof(*counters); ++c) {
                        for (unsigned n = 0; n < sizeof(lengths) / sizeof(*lengths); ++n) {
                                chacha_ctx actual, reference;
                                chacha_keysetup(&actual, key);
                                chacha_ivsetup(&actual, nonce);
                                reference_chacha_keysetup(&reference, key);
                                reference_chacha_ivsetup(&reference, nonce);
                                actual.input[12] = reference.input[12] = counters[c];
                                actual.input[13] = reference.input[13] = 37;
                                u8 output[1041], expected[1041];
                                memset(output, 0xa5, sizeof(output));
                                memset(expected, 0xa5, sizeof(expected));
                                assert(lengths[n] + 2 <= sizeof(output));
                                chacha_keystream_bytes(&actual, output + 1, lengths[n]);
                                reference_chacha_keystream_bytes(&reference, expected + 1, lengths[n]);
                                assert(memcmp(output, expected, sizeof(output)) == 0);
                                assert(memcmp(&actual, &reference, sizeof(actual)) == 0);
                                assert(output[0] == 0xa5 && output[lengths[n] + 1] == 0xa5);
                                ++cases;
                        }
                }
        }
        assert(cases == 144);
        printf("ChaCha tagged-reference comparison: %u cases pass\n", cases);
        return 0;
}
