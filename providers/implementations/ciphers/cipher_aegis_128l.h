#include "include/crypto/aegis_128l.h"
#include "prov/ciphercommon.h"

#define AEGIS_128L_IVLEN 16
#define AEGIS_128L_RATE 32

typedef struct {
    PROV_CIPHER_CTX base; /* must be first */
    unsigned char state[128];
    unsigned char key[16];
    unsigned char tag[32];
    unsigned char buf[AEGIS_128L_RATE];
    uint64_t ad_len;
    uint64_t msg_len;
    size_t pos;
    size_t tag_len;
} PROV_AEGIS_128L_CTX;

typedef struct prov_cipher_hw_chacha_aead_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*aead_cipher)(PROV_CIPHER_CTX *dat, unsigned char *out, size_t *outl,
                       const unsigned char *in, size_t len);
    int (*initiv)(PROV_CIPHER_CTX *ctx);
    int (*tls_init)(PROV_CIPHER_CTX *ctx, unsigned char *aad, size_t alen);
    int (*tls_iv_set_fixed)(PROV_CIPHER_CTX *ctx, unsigned char *fixed,
                            size_t flen);
} PROV_CIPHER_HW_AEGIS_128L;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_aegis_128l(size_t keybits);
