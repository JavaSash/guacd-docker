/*
 * Copyright (C) 2015 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "config.h"

#include "guac_ssh_buffer.h"
#include "guac_ssh_key.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdlib.h>
#include <string.h>

guac_common_ssh_key* guac_common_ssh_key_alloc(char* data, int length,
        char* passphrase) {

    guac_common_ssh_key* key;
    BIO* key_bio;
    char* public_key;
    char* pos;

    /* Create BIO for reading key from memory */
    key_bio = BIO_new_mem_buf(data, length);
    if (key_bio == NULL) {
        return NULL;
    }

    /* If RSA key, load RSA */
    if (length > sizeof(SSH_RSA_KEY_HEADER)-1
            && memcmp(SSH_RSA_KEY_HEADER, data,
                      sizeof(SSH_RSA_KEY_HEADER)-1) == 0) {

        RSA* rsa_key;
        const BIGNUM *n, *e;

        /* Read key */
        rsa_key = PEM_read_bio_RSAPrivateKey(key_bio, NULL, NULL, passphrase);
        if (rsa_key == NULL)
            return NULL;

        /* Get key components */
        RSA_get0_key(rsa_key, &n, &e, NULL);

        /* Allocate key */
        key = malloc(sizeof(guac_common_ssh_key));
        if (key == NULL) {
            RSA_free(rsa_key);
            BIO_free(key_bio);
            return NULL;
        }
        key->rsa = rsa_key;

        /* Set type */
        key->type = SSH_KEY_RSA;

        /* Allocate space for public key */
        public_key = malloc(4096);
        if (public_key == NULL) {
            RSA_free(rsa_key);
            free(key);
            BIO_free(key_bio);
            return NULL;
        }
        pos = public_key;

        /* Derive public key */
        guac_common_ssh_buffer_write_string(&pos, "ssh-rsa", sizeof("ssh-rsa")-1);
        guac_common_ssh_buffer_write_bignum(&pos, (BIGNUM*)e); // Casting away const
        guac_common_ssh_buffer_write_bignum(&pos, (BIGNUM*)n); // Casting away const

        /* Save public key to structure */
        key->public_key = public_key;
        key->public_key_length = pos - public_key;

    }

    /* If DSA key, load DSA */
    else if (length > sizeof(SSH_DSA_KEY_HEADER)-1
            && memcmp(SSH_DSA_KEY_HEADER, data,
                      sizeof(SSH_DSA_KEY_HEADER)-1) == 0) {

        DSA* dsa_key;
        const BIGNUM *p, *q, *g, *pub_key;

        /* Read key */
        dsa_key = PEM_read_bio_DSAPrivateKey(key_bio, NULL, NULL, passphrase);
        if (dsa_key == NULL)
            return NULL;

        /* Get key components */
        DSA_get0_pqg(dsa_key, &p, &q, &g);
        DSA_get0_key(dsa_key, &pub_key, NULL);

        /* Allocate key */
        key = malloc(sizeof(guac_common_ssh_key));
        if (key == NULL) {
            DSA_free(dsa_key);
            BIO_free(key_bio);
            return NULL;
        }
        key->dsa = dsa_key;

        /* Set type */
        key->type = SSH_KEY_DSA;

        /* Allocate space for public key */
        public_key = malloc(4096);
        if (public_key == NULL) {
            DSA_free(dsa_key);
            free(key);
            BIO_free(key_bio);
            return NULL;
        }
        pos = public_key;

        /* Derive public key */
        guac_common_ssh_buffer_write_string(&pos, "ssh-dss", sizeof("ssh-dss")-1);
        guac_common_ssh_buffer_write_bignum(&pos, (BIGNUM*)p); // Casting away const
        guac_common_ssh_buffer_write_bignum(&pos, (BIGNUM*)q); // Casting away const
        guac_common_ssh_buffer_write_bignum(&pos, (BIGNUM*)g); // Casting away const
        guac_common_ssh_buffer_write_bignum(&pos, (BIGNUM*)pub_key); // Casting away const

        /* Save public key to structure */
        key->public_key = public_key;
        key->public_key_length = pos - public_key;

    }

    /* Otherwise, unsupported type */
    else {
        BIO_free(key_bio);
        return NULL;
    }

    /* Copy private key to structure */
    key->private_key_length = length;
    key->private_key = malloc(length);
    if (key->private_key == NULL) {
        free(key->public_key);
        free(key);
        BIO_free(key_bio);
        return NULL;
    }
    memcpy(key->private_key, data, length);

    BIO_free(key_bio);
    return key;
}

const char* guac_common_ssh_key_error() {
    /* Return static error string */
    return ERR_reason_error_string(ERR_get_error());
}

void guac_common_ssh_key_free(guac_common_ssh_key* key) {
    /* Free key-specific data */
    if (key->type == SSH_KEY_RSA)
        RSA_free(key->rsa);
    else if (key->type == SSH_KEY_DSA)
        DSA_free(key->dsa);

    free(key->public_key);
    free(key->private_key);
    free(key);
}

int guac_common_ssh_key_sign(guac_common_ssh_key* key, const char* data,
        int length, unsigned char* sig) {

    const EVP_MD* md;
    EVP_MD_CTX* md_ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen, len;

    /* Get SHA1 digest */
    if ((md = EVP_get_digestbynid(NID_sha1)) == NULL)
        return -1;

    /* Initialize digest context */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        return -1;

    /* Digest data */
    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    if (EVP_DigestUpdate(md_ctx, data, length) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    if (EVP_DigestFinal_ex(md_ctx, digest, &dlen) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    /* Sign with key */
    switch (key->type) {

        case SSH_KEY_RSA:
            if (RSA_sign(NID_sha1, digest, dlen, sig, &len, key->rsa) == 1) {
                EVP_MD_CTX_free(md_ctx);
                return len;
            }
            break;

        case SSH_KEY_DSA: {
            DSA_SIG* dsa_sig;
            const BIGNUM *r, *s;
            unsigned char r_bin[128], s_bin[128];
            int rlen, slen;

            if ((dsa_sig = DSA_do_sign(digest, dlen, key->dsa)) == NULL) {
                EVP_MD_CTX_free(md_ctx);
                return -1;
            }

            /* Get DSA signature components */
            DSA_SIG_get0(dsa_sig, &r, &s);

            /* Convert signature to bytes */
            rlen = BN_num_bytes(r);
            slen = BN_num_bytes(s);

            if (rlen > sizeof(r_bin) || slen > sizeof(s_bin)) {
                DSA_SIG_free(dsa_sig);
                EVP_MD_CTX_free(md_ctx);
                return -1;
            }

            BN_bn2bin(r, r_bin);
            BN_bn2bin(s, s_bin);

            memcpy(sig, r_bin, rlen);
            memcpy(sig + rlen, s_bin, slen);

            DSA_SIG_free(dsa_sig);
            EVP_MD_CTX_free(md_ctx);
            return rlen + slen;
        }

    }

    EVP_MD_CTX_free(md_ctx);
    return -1;
}
