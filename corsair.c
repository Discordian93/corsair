#include <stdio.h>
#include <string.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int main(void)
{
    BIO *key1bio = BIO_new_file("pkey1", "r");
    if(key1bio == NULL)
    {
        printf("failed to open pkey1\n");
        return 1;
    }
    BIO_set_close(key1bio, BIO_CLOSE);
    BIO *key2bio = BIO_new_file("pkey2", "r");
    if(key2bio == NULL)
    {
        printf("failed to open pkey2\n");
        BIO_free(key1bio);
        return 1;
    }
    BIO_set_close(key2bio, BIO_CLOSE);
    /*RSA *key1 = RSA_new();
    if(key1 == NULL)
    {
        BIO_free(key1bio);
        BIO_free(key2bio);
        return 1;
    }
    RSA *key2 = RSA_new();
    if(key2 == NULL)
    {
        BIO_free(key1bio);
        BIO_free(key2bio);
        RSA_free(key1);
        return 1;
    }*/
    EVP_PKEY *key1= PEM_read_bio_PUBKEY(key1bio, NULL, NULL, NULL);
    if(key1 == NULL)
    {
        printf("unable to extract public key1\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        return 1;
    }
    EVP_PKEY *key2= PEM_read_bio_PUBKEY(key2bio, NULL, NULL, NULL);
    if(key2 == NULL)
    {
        printf("unable to extract public key 2\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        //RSA_free(key1);
        EVP_PKEY_free(key1);
        return 1;
    }
    RSA *pkey1 = EVP_PKEY_get1_RSA(key1);
    if(pkey1 == NULL)
    {
        printf("unable to extract key structure of public key 1\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        //RSA_free(key1);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        return 1;
    }
    RSA *pkey2 = EVP_PKEY_get1_RSA(key2);
    if (pkey2 == NULL)
    {
        printf("unable to extract key structure of public key 2\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        RSA_free(pkey1);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        return 1;
    }
        /*BIO_free(key1bio);
        BIO_free(key2bio);
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        return 0;*/
    //PEM_read_bio_RSAPublicKey(key1bio,key1, NULL, NULL);
    BIGNUM *modulus1 = RSA_get0_n(pkey1);
    if(modulus1 == NULL)
    {
        printf("aborted at modulus\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        return 1;
    }
    BIGNUM *modulus2 = RSA_get0_n(pkey2);
    if(modulus2 == NULL)
    {
        printf("aborted at modulus 2\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        
        return 1;
    }
    BN_CTX *ctx = BN_CTX_new();
    if(ctx == NULL)
    {
        printf("error in ctx allocation \n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(modulus1);
        BN_free(modulus2);
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        return 1;
    }
    BIGNUM *comun = BN_new();
    if(comun == NULL)
    {
        printf("aborted at GCD allocation\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        
        return 1;
    }
    BN_gcd(comun, modulus1, modulus2, ctx);
    if(BN_is_one(comun))
    {
        printf("Factor común 1, no no puede extraer la clave privada\n");
        BIO_free(key1bio);
        BIO_free(key2bio);

        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_free(comun);
        BN_CTX_free(ctx);
        return 1;
    }
  
    BIGNUM *exponent1 = RSA_get0_e(pkey1);
    if(exponent1 == NULL)
    {
        printf("Error in extracting public exponent\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BIGNUM *primo = BN_new();
    if(primo == NULL)
    {
        printf("Error in allocating prime factor\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_div(primo, NULL, modulus1, comun, ctx);
    BIGNUM *pmenos1 = BN_new();
    if(pmenos1 == NULL)
    {
        printf("Error in allocating p minus one\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_copy(pmenos1, primo);
    BIGNUM *qmenos1 = BN_new();
    if(qmenos1 == NULL)
    {
        printf("Error in allocating q minus one\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_sub_word(pmenos1, 1);
    BN_sub_word(qmenos1, 1);
    BIGNUM *producto = BN_new();
    if(producto == NULL)
    {
        printf("Error in allocating product\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        BN_free(qmenos1);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_mul(producto, pmenos1, qmenos1, ctx);
    BIGNUM *d = BN_new();
    if(d == NULL)
    {
        printf("error allocating d\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }

    BN_mod_inverse(d, exponent1, producto, ctx);
    BIGNUM *alt1 = BN_new();
    if(alt1 == NULL)
    {
        printf("error allocating alt1\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
        BN_free(d);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }

    BN_mod(alt1, d, pmenos1, ctx);
    BIGNUM *alt2 = BN_new();
    if(alt2 == NULL)
    {
        printf("error allocating alt2\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
        BN_free(d);
        BN_free(alt1);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_mod(alt2, d, qmenos1, ctx);

    BIGNUM *coeff = BN_new();
    if(coeff == NULL)
    {
        printf("error allocating alt2\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
        BN_free(d);
        BN_free(alt1);
        BN_free(alt2);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_mod_inverse(coeff, comun, primo, ctx);
    RSA *priv = RSA_new();
    if(priv == NULL)
    {
        printf("error allocating private key\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(comun);
        BN_free(primo);
        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
        BN_free(d);
        BN_free(alt1);
        BN_free(alt2);
        BN_free(coeff);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    RSA_set0_factors(priv, primo, comun);
    RSA_set0_crt_params(priv, alt1, alt2, coeff);
    BIGNUM *privmod = BN_new();
    if(privmod == NULL)
    {
        printf("error allocating private key module\n");
        BIO_free(key1bio);
        BIO_free(key2bio);

        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
       
        RSA_free(priv);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BN_mul(privmod, primo, comun, ctx);
    BIGNUM *exponente = BN_new();
    BN_copy(exponente, exponent1);
    RSA_set0_key(priv,privmod, exponente, d);
    BIO *biout = BIO_new_file("priv.pem", "w");
    if(biout == NULL)
    {
        printf("error allocating private key\n");
        BIO_free(key1bio);
        BIO_free(key2bio);
        BN_free(pmenos1);
        BN_free(qmenos1);
        BN_free(producto);
        RSA_free(priv);
        //BN_free(privmod);
        //printf("\n");
        RSA_free(pkey1);
        RSA_free(pkey2);
        EVP_PKEY_free(key1);
        EVP_PKEY_free(key2);
        BN_CTX_free(ctx);
        return 1;
    }
    BIO_set_close(biout, BIO_CLOSE);
    PEM_write_bio_RSAPrivateKey(biout, priv, NULL, 0,NULL, NULL, NULL);
    BIO_free(key1bio);
    BIO_free(key2bio);
    //BN_free(comun);
    //BN_free(primo);
    BN_free(pmenos1);
    BN_free(qmenos1);
    BN_free(producto);
    //BN_free(d);
    //BN_free(alt1);
    //BN_free(alt2);
    //BN_free(coeff);
    //BN_free(privmod);
    //printf("\n");
    RSA_free(pkey1);
    RSA_free(pkey2);
    RSA_free(priv);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    BN_CTX_free(ctx);
    BIO_free(biout);
    //BN_print_fp(stdout, modulus1);
    /*printf("gets here\n");
    BN_free(comun);
    BN_free(exponent1);
    BN_free(primo);
    BN_CTX_free(ctx);
    BIO_free(key1bio);
    BIO_free(key2bio);
    RSA_free(pkey1);
    RSA_free(pkey2);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);*/
    //printf("\n");
    

}