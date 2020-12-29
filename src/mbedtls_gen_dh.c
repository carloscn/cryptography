//
// Created by carlos on 2020/12/29.
//
#include "mbedtls_gen_dh.h"
// Fisrt server slide need rsa private key.
// Second server slide need share argument.
#define DFL_BITS 2048

/*
 * Note: G = 4 is always a quadratic residue mod P,
 * so it is a generator of order Q (with P = 2*Q+1).
 */
#define GENERATOR "4"

/*
 * shows how to use the bignum (mpi) interface to generate
 * Diffie-Hellman parameters.
 * */
int mbedtls_gen_dh_prime(const char *outfile, int nbits)
{
    int ret = ERROR_NONE;
    int rc = MBEDTLS_EXIT_SUCCESS;
    if (outfile == NULL) {
        mbedtls_printf("outfile is null\n");
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    if (nbits < 0 || nbits > MBEDTLS_MPI_MAX_BITS) {
        mbedtls_printf("nbits error 0 < %d < %d\n", nbits, MBEDTLS_MPI_MAX_BITS);
        ret = -ERROR_COMMON_INPUT_PARAMETERS;
        goto finish;
    }
    mbedtls_mpi G, P, Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "hd_genprime";
    FILE *fout = NULL;
    int i = 0;

    mbedtls_mpi_init(&G); mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    rc = mbedtls_mpi_read_string(&G, 10, GENERATOR);
    if (rc != 0) {
        mbedtls_printf("mbedtls_mpi_read_string returned %d\n", ret);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf( "!Generating large primes may take minutes!\n" );
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush(stdout);

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char*)pers, strlen(pers));
    if (rc != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed failed returned %d\n", rc);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf( " ok\n  . Generating the modulus, please wait..." );
    fflush(stdout);

    /*
     * This can take a long time...
     */
    rc = mbedtls_mpi_gen_prime(&P, nbits, 1,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf("mbedtls_mpi_gen_prime returned %d\\n\\n\", rc");
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }
    mbedtls_printf( " ok\n  . Verifying that Q = (P-1)/2 is prime..." );
    fflush(stdout);

    rc = mbedtls_mpi_sub_int(&Q, &P, 1);
    if (rc != 0) {
        mbedtls_printf( "mbedtls_mpi_div_int returned %d\n\n", rc);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    rc = mbedtls_mpi_div_int(&Q, NULL, &Q, 2);
    if (rc != 0) {
        mbedtls_printf( "mbedtls_mpi_div_int returned %d\n\n", rc);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    rc = mbedtls_mpi_is_prime_ext(&Q, 50, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        mbedtls_printf( "mbedtls_mpi_is_prime_ext returned %d\n\n", rc);
        ret = -ERROR_CRYPTO_INIT_FAILED;
        goto finish;
    }

    mbedtls_printf( " ok\n  . Exporting the value in dh_prime.txt..." );
    fflush( stdout );

    fout = fopen(outfile, "wb+");
    if (fout == NULL) {
        mbedtls_printf( "Could not create %s\n\n", outfile);
        ret = -ERROR_COMMON_FILE_OPEN_FAILED;
        goto finish;
    }

    rc = mbedtls_mpi_write_file("P = ", &P, 16, fout);
    if (rc != 0) {
        mbedtls_printf("mbedtls_mpi_write_file P returned %d\n\n", rc);
        ret = -ERROR_COMMON_FILE_WRITE_FAILED;
        goto finish;
    }

    rc = mbedtls_mpi_write_file("G = ", &G, 16, fout);
    if (rc != 0) {
        mbedtls_printf("mbedtls_mpi_write_file G returned %d\n\n", rc);
        ret = -ERROR_COMMON_FILE_WRITE_FAILED;
        goto finish;
    }
    fclose(fout); fout = NULL;
    mbedtls_printf("ok \n\n");
    finish:
    mbedtls_mpi_free(&G); mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (fout != NULL) {
        fclose(fout);
    }
    return ret;
}