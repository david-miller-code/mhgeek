#include "jpake.h"

#include <errno.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <string.h>

/* RFC 8236 section 3 supplies the mathematics. README.md describes the
 * application's curve, role names, length encodings and SHA-256 KDF.
 * This is application-layer J-PAKE, not a TLS cipher-suite implementation.
 */
enum exchange_state {
    EXCHANGE_NEW,
    SENT_ONE,
    RECEIVED_ONE,
    SENT_TWO,
    RECEIVED_TWO,
    EXCHANGE_DONE,
    EXCHANGE_FAILED
};

struct mhg_jpake {
    EC_GROUP *group;
    BN_CTX *ctx;
    BN_MONT_CTX *mont;
    BIGNUM *order;
    BIGNUM *password;
    BIGNUM *x1;
    BIGNUM *x2;
    BIGNUM *x2s;
    EC_POINT *own1;
    EC_POINT *own2;
    EC_POINT *peer1;
    EC_POINT *peer2;
    EC_POINT *peer_round2;
    enum exchange_state state;
};

struct wire_reader {
    const unsigned char *data;
    size_t remaining;
};

static BIGNUM *private_bn(void)
{
    BIGNUM *n = BN_secure_new();
    if (n) BN_set_flags(n, BN_FLG_CONSTTIME);
    return n;
}

static void forget_private(struct mhg_jpake *p)
{
    if (p->password) BN_clear(p->password);
    if (p->x1) BN_clear(p->x1);
    if (p->x2) BN_clear(p->x2);
    if (p->x2s) BN_clear(p->x2s);
    /* OpenSSL operations may have left secret scratch BNs in this context.
     * Both callers terminate the exchange, so dispose of the scratch arena
     * immediately instead of retaining it until the object's eventual free.
     */
    BN_CTX_free(p->ctx);
    p->ctx = NULL;
}

static int fail_exchange(struct mhg_jpake *p, struct mhg_error *error,
                         int code, const char *message)
{
    if (p) {
        forget_private(p);
        p->state = EXCHANGE_FAILED;
    }
    return mhg_errorf(error, code, "%s", message);
}

static int expect_state(struct mhg_jpake *p, enum exchange_state expected,
                         struct mhg_error *error)
{
    if (!p) return mhg_errorf(error, EINVAL, "missing J-PAKE exchange");
    if (p->state != expected)
        return mhg_errorf(error, EPROTO, "J-PAKE operation out of sequence");
    return 0;
}

void mhg_jpake_free(struct mhg_jpake *p)
{
    if (!p) return;
    BN_clear_free(p->password);
    BN_clear_free(p->x1);
    BN_clear_free(p->x2);
    BN_clear_free(p->x2s);
    BN_free(p->order);
    EC_POINT_clear_free(p->own1);
    EC_POINT_clear_free(p->own2);
    EC_POINT_clear_free(p->peer1);
    EC_POINT_clear_free(p->peer2);
    EC_POINT_clear_free(p->peer_round2);
    BN_MONT_CTX_free(p->mont);
    BN_CTX_free(p->ctx);
    EC_GROUP_free(p->group);
    OPENSSL_clear_free(p, sizeof(*p));
}

struct mhg_jpake *mhg_jpake_new(const char *passcode, struct mhg_error *error)
{
    struct mhg_jpake *p;
    BIGNUM *cofactor = NULL;
    size_t length = 0;

    if (passcode) {
        while (length < 9 && passcode[length] >= '0' && passcode[length] <= '9')
            ++length;
    }
    if (!passcode || length < 6 || length > 8 || passcode[length] != '\0') {
        mhg_errorf(error, EINVAL, "J-PAKE passcode must contain 6 to 8 ASCII digits");
        return NULL;
    }
    p = OPENSSL_zalloc(sizeof(*p));
    if (!p) {
        mhg_errorf(error, ENOMEM, "J-PAKE allocation failed");
        return NULL;
    }
    p->group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    p->ctx = BN_CTX_secure_new();
    p->mont = BN_MONT_CTX_new();
    p->order = BN_new();
    p->password = private_bn();
    p->x1 = private_bn();
    p->x2 = private_bn();
    p->x2s = private_bn();
    cofactor = BN_new();
    if (!p->group || !p->ctx || !p->mont || !p->order || !p->password ||
        !p->x1 || !p->x2 || !p->x2s || !cofactor) goto failed;
    p->own1 = EC_POINT_new(p->group);
    p->own2 = EC_POINT_new(p->group);
    p->peer1 = EC_POINT_new(p->group);
    p->peer2 = EC_POINT_new(p->group);
    p->peer_round2 = EC_POINT_new(p->group);
    if (!p->own1 || !p->own2 || !p->peer1 || !p->peer2 || !p->peer_round2)
        goto failed;
    /* secp256k1 has cofactor one: a non-infinite on-curve point is in the
     * required prime-order group. Do not silently generalize to other groups.
     */
    if (!EC_GROUP_get_order(p->group, p->order, p->ctx) ||
        !EC_GROUP_get_cofactor(p->group, cofactor, p->ctx) ||
        !BN_is_one(cofactor) || !BN_MONT_CTX_set(p->mont, p->order, p->ctx) ||
        !BN_bin2bn((const unsigned char *)passcode, (int)length, p->password) ||
        BN_is_zero(p->password) || BN_cmp(p->password, p->order) >= 0)
        goto failed;
    BN_free(cofactor);
    return p;

failed:
    BN_free(cofactor);
    mhg_jpake_free(p);
    mhg_errorf(error, EIO, "J-PAKE cryptographic initialization failed");
    return NULL;
}

static int random_nonzero(struct mhg_jpake *p, BIGNUM *value)
{
    do {
        if (!BN_priv_rand_range(value, p->order)) return 0;
    } while (BN_is_zero(value));
    return 1;
}

/* Keep secret modular products in Montgomery arithmetic. Secret scalars and
 * temporaries carry CONSTTIME and use secure BNs. EC_POINT_mul is used with a
 * single bounded scalar for secret operations (OpenSSL's constant-time API
 * case). These precautions are not a claim that the whole protocol, including
 * all low-level BN operations and point serialization, has had a timing audit.
 */
static int scalar_product(struct mhg_jpake *p, BIGNUM *out,
                            const BIGNUM *a, const BIGNUM *b)
{
    BIGNUM *am, *bm, *product;
    int ok = 0;
    BN_CTX_start(p->ctx);
    am = BN_CTX_get(p->ctx);
    bm = BN_CTX_get(p->ctx);
    product = BN_CTX_get(p->ctx);
    if (!product) goto done;
    BN_set_flags(am, BN_FLG_CONSTTIME);
    BN_set_flags(bm, BN_FLG_CONSTTIME);
    BN_set_flags(product, BN_FLG_CONSTTIME);
    ok = BN_to_montgomery(am, a, p->mont, p->ctx) &&
         BN_to_montgomery(bm, b, p->mont, p->ctx) &&
         BN_mod_mul_montgomery(product, am, bm, p->mont, p->ctx) &&
         BN_from_montgomery(out, product, p->mont, p->ctx);
done:
    if (am) BN_clear(am);
    if (bm) BN_clear(bm);
    if (product) BN_clear(product);
    BN_CTX_end(p->ctx);
    return ok;
}

static int encode_point(struct mhg_jpake *p, const EC_POINT *point,
                         unsigned char out[65])
{
    return EC_POINT_point2oct(p->group, point, POINT_CONVERSION_UNCOMPRESSED,
                              out, 65, p->ctx) == 65 && out[0] == 4;
}

static int challenge(struct mhg_jpake *p, const EC_POINT *base,
                       const EC_POINT *commitment, const EC_POINT *public_key,
                       const char role[6], BIGNUM *out)
{
    const EC_POINT *points[] = {base, commitment, public_key};
    unsigned char input[3 * (4 + 65) + 4 + 6];
    unsigned char digest[32];
    size_t i, offset = 0;
    unsigned int digest_len = 0;
    int ok = 0;

    for (i = 0; i < 3; ++i) {
        input[offset++] = 0;
        input[offset++] = 0;
        input[offset++] = 0;
        input[offset++] = 65;
        if (!encode_point(p, points[i], input + offset)) goto done;
        offset += 65;
    }
    input[offset++] = 0;
    input[offset++] = 0;
    input[offset++] = 0;
    input[offset++] = 6;
    memcpy(input + offset, role, 6);
    ok = EVP_Digest(input, sizeof(input), digest, &digest_len, EVP_sha256(), NULL) &&
         digest_len == 32 && BN_bin2bn(digest, 32, out) &&
         BN_nnmod(out, out, p->order, p->ctx);
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    return ok;
}

/* Fixed-size outgoing values avoid any need for sizing or repeated proofs.
 * Peer scalars may use any nonempty unsigned representation up to 32 bytes.
 */
static int write_public_proof(struct mhg_jpake *p, const EC_POINT *base,
                               const BIGNUM *secret, const EC_POINT *public_key,
                               unsigned char out[165])
{
    BIGNUM *nonce = private_bn();
    BIGNUM *response = private_bn();
    BIGNUM *product = private_bn();
    BIGNUM *c = BN_new();
    EC_POINT *commitment = EC_POINT_new(p->group);
    int ok = 0;
    if (!nonce || !response || !product || !c || !commitment) goto done;
    if (!random_nonzero(p, nonce) ||
        !EC_POINT_mul(p->group, commitment, NULL, base, nonce, p->ctx) ||
        !challenge(p, base, commitment, public_key, "client", c) ||
        !scalar_product(p, product, c, secret) ||
        !BN_mod_sub(response, nonce, product, p->order, p->ctx)) goto done;
    out[0] = 65;
    out[66] = 65;
    out[132] = 32;
    ok = encode_point(p, public_key, out + 1) &&
         encode_point(p, commitment, out + 67) &&
         BN_bn2binpad(response, out + 133, 32) == 32;
done:
    BN_clear_free(nonce);
    BN_clear_free(response);
    BN_clear_free(product);
    BN_free(c);
    EC_POINT_clear_free(commitment);
    return ok;
}

static int read_point(struct mhg_jpake *p, struct wire_reader *reader,
                       EC_POINT *point)
{
    unsigned char canonical[65];
    if (reader->remaining < 66 || reader->data[0] != 65 || reader->data[1] != 4)
        return 0;
    if (!EC_POINT_oct2point(p->group, point, reader->data + 1, 65, p->ctx) ||
        EC_POINT_is_at_infinity(p->group, point) != 0 ||
        EC_POINT_is_on_curve(p->group, point, p->ctx) != 1 ||
        !encode_point(p, point, canonical) ||
        CRYPTO_memcmp(canonical, reader->data + 1, 65) != 0) return 0;
    reader->data += 66;
    reader->remaining -= 66;
    return 1;
}

static int read_scalar(struct mhg_jpake *p, struct wire_reader *reader,
                        BIGNUM *scalar)
{
    size_t n;
    if (!reader->remaining) return 0;
    n = reader->data[0];
    if (!n || n > 32 || reader->remaining - 1 < n) return 0;
    if (!BN_bin2bn(reader->data + 1, (int)n, scalar) ||
        BN_cmp(scalar, p->order) >= 0) return 0;
    reader->data += 1 + n;
    reader->remaining -= 1 + n;
    return 1;
}

static int read_public_proof(struct mhg_jpake *p, struct wire_reader *reader,
                              const EC_POINT *base, EC_POINT *public_key)
{
    EC_POINT *commitment = EC_POINT_new(p->group);
    EC_POINT *check = EC_POINT_new(p->group);
    EC_POINT *term = EC_POINT_new(p->group);
    BIGNUM *r = BN_new();
    BIGNUM *c = BN_new();
    int ok = 0;
    if (!commitment || !check || !term || !r || !c) goto done;
    if (!read_point(p, reader, public_key) ||
        !read_point(p, reader, commitment) || !read_scalar(p, reader, r) ||
        !challenge(p, base, commitment, public_key, "server", c)) goto done;
    /* These scalars and points are public proof data. */
    if (!EC_POINT_mul(p->group, check, NULL, base, r, p->ctx) ||
        !EC_POINT_mul(p->group, term, NULL, public_key, c, p->ctx) ||
        !EC_POINT_add(p->group, check, check, term, p->ctx)) goto done;
    ok = EC_POINT_cmp(p->group, check, commitment, p->ctx) == 0;
done:
    EC_POINT_free(commitment);
    EC_POINT_free(check);
    EC_POINT_free(term);
    BN_free(r);
    BN_free(c);
    return ok;
}

int mhg_jpake_round_one(struct mhg_jpake *p, struct mhg_buf *out,
                        struct mhg_error *error)
{
    const EC_POINT *g;
    if (expect_state(p, EXCHANGE_NEW, error) != 0) return -1;
    if (!out) return mhg_errorf(error, EINVAL, "missing J-PAKE output buffer");
    if (mhg_buf_alloc(out, 330, error) != 0) return -1;
    g = EC_GROUP_get0_generator(p->group);
    if (!random_nonzero(p, p->x1) || !random_nonzero(p, p->x2) ||
        !EC_POINT_mul(p->group, p->own1, p->x1, NULL, NULL, p->ctx) ||
        !EC_POINT_mul(p->group, p->own2, p->x2, NULL, NULL, p->ctx) ||
        !write_public_proof(p, g, p->x1, p->own1, out->data) ||
        !write_public_proof(p, g, p->x2, p->own2, out->data + 165)) {
        mhg_buf_clear(out);
        return fail_exchange(p, error, EIO, "J-PAKE round one creation failed");
    }
    BN_clear(p->x1);
    p->state = SENT_ONE;
    return 0;
}

int mhg_jpake_read_round_one(struct mhg_jpake *p, const unsigned char *data,
                             size_t length, struct mhg_error *error)
{
    struct wire_reader reader = {data, length};
    const EC_POINT *g;
    if (expect_state(p, SENT_ONE, error) != 0) return -1;
    g = EC_GROUP_get0_generator(p->group);
    if (!data || !read_public_proof(p, &reader, g, p->peer1) ||
        !read_public_proof(p, &reader, g, p->peer2) || reader.remaining)
        return fail_exchange(p, error, EPROTO, "invalid J-PAKE server round one");
    p->state = RECEIVED_ONE;
    return 0;
}

static int sum_three(struct mhg_jpake *p, EC_POINT *out,
                       const EC_POINT *a, const EC_POINT *b, const EC_POINT *c)
{
    return EC_POINT_add(p->group, out, a, b, p->ctx) &&
           EC_POINT_add(p->group, out, out, c, p->ctx) &&
           EC_POINT_is_at_infinity(p->group, out) == 0 &&
           EC_POINT_is_on_curve(p->group, out, p->ctx) == 1;
}

int mhg_jpake_round_two(struct mhg_jpake *p, struct mhg_buf *out,
                        struct mhg_error *error)
{
    EC_POINT *base = NULL, *public_key = NULL;
    int ok = 0;
    if (expect_state(p, RECEIVED_ONE, error) != 0) return -1;
    if (!out) return mhg_errorf(error, EINVAL, "missing J-PAKE output buffer");
    if (mhg_buf_alloc(out, 165, error) != 0) return -1;
    base = EC_POINT_new(p->group);
    public_key = EC_POINT_new(p->group);
    if (base && public_key &&
        sum_three(p, base, p->own1, p->peer1, p->peer2) &&
        scalar_product(p, p->x2s, p->x2, p->password) && !BN_is_zero(p->x2s) &&
        EC_POINT_mul(p->group, public_key, NULL, base, p->x2s, p->ctx))
        ok = write_public_proof(p, base, p->x2s, public_key, out->data);
    EC_POINT_free(base);
    EC_POINT_clear_free(public_key);
    if (!ok) {
        mhg_buf_clear(out);
        return fail_exchange(p, error, EIO, "J-PAKE round two creation failed");
    }
    BN_clear(p->password);
    p->state = SENT_TWO;
    return 0;
}

int mhg_jpake_read_round_two(struct mhg_jpake *p, const unsigned char *data,
                             size_t length, struct mhg_error *error)
{
    struct wire_reader reader;
    EC_POINT *base;
    int ok = 0;
    if (expect_state(p, SENT_TWO, error) != 0) return -1;
    if (!data || length < 3 || data[0] != 3 || data[1] != 0 || data[2] != 22)
        return fail_exchange(p, error, EPROTO, "invalid J-PAKE server round two prefix");
    reader.data = data + 3;
    reader.remaining = length - 3;
    base = EC_POINT_new(p->group);
    if (base && sum_three(p, base, p->peer1, p->own1, p->own2))
        ok = read_public_proof(p, &reader, base, p->peer_round2) && !reader.remaining;
    EC_POINT_free(base);
    if (!ok)
        return fail_exchange(p, error, EPROTO, "invalid J-PAKE server round two");
    p->state = RECEIVED_TWO;
    return 0;
}

int mhg_jpake_secret(struct mhg_jpake *p, unsigned char out[32],
                     struct mhg_error *error)
{
    EC_POINT *shared = NULL, *subtract = NULL;
    BIGNUM *x = NULL;
    unsigned char encoded[32] = {0};
    unsigned int digest_len = 0;
    int ok = 0;
    if (!out) return mhg_errorf(error, EINVAL, "missing J-PAKE secret output");
    OPENSSL_cleanse(out, 32);
    if (expect_state(p, RECEIVED_TWO, error) != 0) return -1;
    shared = EC_POINT_new(p->group);
    subtract = EC_POINT_new(p->group);
    x = private_bn();
    if (!shared || !subtract || !x) goto done;
    if (!EC_POINT_mul(p->group, subtract, NULL, p->peer2, p->x2s, p->ctx) ||
        !EC_POINT_invert(p->group, subtract, p->ctx) ||
        !EC_POINT_add(p->group, shared, p->peer_round2, subtract, p->ctx) ||
        EC_POINT_is_at_infinity(p->group, shared) != 0 ||
        !EC_POINT_mul(p->group, shared, NULL, shared, p->x2, p->ctx) ||
        EC_POINT_is_at_infinity(p->group, shared) != 0 ||
        !EC_POINT_get_affine_coordinates(p->group, shared, x, NULL, p->ctx) ||
        BN_bn2binpad(x, encoded, 32) != 32) goto done;
    ok = EVP_Digest(encoded, sizeof(encoded), out, &digest_len, EVP_sha256(), NULL) &&
         digest_len == 32;
done:
    OPENSSL_cleanse(encoded, sizeof(encoded));
    BN_clear_free(x);
    EC_POINT_clear_free(shared);
    EC_POINT_clear_free(subtract);
    if (!ok) {
        OPENSSL_cleanse(out, 32);
        return fail_exchange(p, error, EIO, "J-PAKE shared secret derivation failed");
    }
    forget_private(p);
    p->state = EXCHANGE_DONE;
    return 0;
}
