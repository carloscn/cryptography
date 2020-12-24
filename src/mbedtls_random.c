//
// Created by carlos on 2020/12/24.
//

#include "mbedtls_random.h"

static int _my_entropy_func(void *data, unsigned char *output, size_t len)
{
    return mbedtls_entropy_func(data, output, len);
}

#define SEED_CACHE_BUFFER_SIZE  (4096)
static unsigned char seed_cache_buffer[SEED_CACHE_BUFFER_SIZE];
static size_t seed_cache_counter = 0;

static int user_define_entropy_func(void *data, unsigned char *output, size_t len)
{
    int32_t ret = 0;
    int32_t i = 0;
    int32_t fetch_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    //mbedtls_printf("reseed times=%d\n", seed_cache_counter);
    if (seed_cache_counter >= SEED_CACHE_BUFFER_SIZE - len) {
        //mbedtls_printf("need fetch 8k seed data. times=%d\n", SEED_CACHE_BUFFER_SIZE/len);
        seed_cache_counter = 0;
        for (i = 0; i < SEED_CACHE_BUFFER_SIZE/fetch_len; i ++) {
            ret = mbedtls_entropy_func(data, seed_cache_buffer + i*fetch_len, fetch_len);
            //mbedtls_printf("-> fetched %d bytes seed data %d.\n", fetch_len ,i);
            if (ret != 0) {
                return ret;
            }
        }
    }
    memcpy(output, seed_cache_buffer + seed_cache_counter, len);
    seed_cache_counter += len;
    return 0;
}

int run_hmac_drbg( int argc, char *argv[] )
{
    FILE *f;
    int i, k, ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_hmac_drbg_context hmac_drbg;
    mbedtls_entropy_context entropy;
    uint32_t kb_size = 0;
    unsigned char buf[1024];

    printf("input argc = %d \n", argc - 1);

    if( argc < 3 )
    {
        mbedtls_fprintf( stderr, "usage: %s <output filename> <output size KB>\n", argv[0] );
        return( exit_code );
    }
    printf("output binary file: %s\n", argv[1]);
    printf("output binary size: %s KB\n", argv[2]);
    kb_size = atoi(argv[2]);
    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        mbedtls_printf( "failed to open '%s' for writing.\n", argv[1] );
        return( exit_code );
    }
    mbedtls_hmac_drbg_init( &hmac_drbg );
    mbedtls_entropy_init( &entropy );
    ret = mbedtls_hmac_drbg_seed( &hmac_drbg, 	\
			mbedtls_md_info_from_type( MBEDTLS_MD_SHA384 ), \
			user_define_entropy_func,   \
			&entropy,\
			(const unsigned char *) "RANDOM_GEN1111111111", \
			10 );
    if( ret != 0 )
    {
        mbedtls_printf( "failed in mbedtls_hmac_drbg_seed: %d\n", ret );
        goto cleanup;
    }
    mbedtls_hmac_drbg_set_prediction_resistance(
            &hmac_drbg, MBEDTLS_HMAC_DRBG_PR_OFF );
    mbedtls_hmac_drbg_set_reseed_interval(
            &hmac_drbg, 1 );
#if defined(MBEDTLS_FS_IO)
    //ret = mbedtls_hmac_drbg_update_seed_file( &hmac_drbg, "seedfile" );
    if( ret == MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR )
    {
        mbedtls_printf( "Failed to open seedfile. Generating one.\n" );
        ret = mbedtls_hmac_drbg_write_seed_file( &hmac_drbg, "seedfile" );
        if( ret != 0 )
        {
            mbedtls_printf( "failed in mbedtls_hmac_drbg_write_seed_file: %d\n", ret );
            goto cleanup;
        }
    }
    else if( ret != 0 )
    {
        mbedtls_printf( "failed in mbedtls_hmac_drbg_update_seed_file: %d\n", ret );
        goto cleanup;
    }
#endif
    for( i = 0, k = kb_size; i < k; i++ )
    {
        ret = mbedtls_hmac_drbg_random( &hmac_drbg, buf, sizeof( buf ) );
        if( ret != 0 )
        {
            mbedtls_printf("failed!\n");
            goto cleanup;
        }

        fwrite( buf, 1, sizeof( buf ), f );

        mbedtls_printf( "Generating 1 kb of data in file '%s'... %04.1f" \
				"%% done, total: %ldkb\r", argv[1], (100 * (float) (i + 1)) / k ,(long)(sizeof(buf) * k / 1024));
        fflush( stdout );
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

    cleanup:
    mbedtls_printf("\n");

    fclose( f );
    mbedtls_hmac_drbg_free( &hmac_drbg );
    mbedtls_entropy_free( &entropy );

    return( exit_code );
}

int mbedtls_random_request(uint8_t* buf, size_t len)
{

    int i, k, ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_hmac_drbg_context hmac_drbg;
    mbedtls_entropy_context entropy;
    size_t bulk_size = MBEDTLS_HMAC_DRBG_MAX_REQUEST;
    size_t req_times = 0;
    size_t cacu_len = 0;
    uint8_t *buf_hook = NULL;
    size_t rest_len = 0;

    mbedtls_hmac_drbg_init( &hmac_drbg );
    mbedtls_entropy_init( &entropy );
    ret = mbedtls_hmac_drbg_seed( &hmac_drbg, 	\
			mbedtls_md_info_from_type( MBEDTLS_MD_SHA384 ), \
			user_define_entropy_func,   \
			&entropy,\
			(const unsigned char *) "randomdata", \
			10 );
    if( ret != 0 )
    {
        mbedtls_printf( "failed in mbedtls_hmac_drbg_seed: %d\n", ret );
        goto cleanup;
    }
    mbedtls_hmac_drbg_set_prediction_resistance(
            &hmac_drbg, MBEDTLS_HMAC_DRBG_PR_OFF );
    mbedtls_hmac_drbg_set_reseed_interval(
            &hmac_drbg, 1 );
    buf_hook = buf;
    req_times = (len/bulk_size) + ((len%bulk_size)?1:0);
    rest_len = len;
    for( i = 0; i < req_times; i++ )
    {
        if (rest_len < bulk_size)
            bulk_size = rest_len;
        mbedtls_printf("req %d bulk / size : %ld \n", i, bulk_size);
        ret = mbedtls_hmac_drbg_random( &hmac_drbg, buf_hook, bulk_size );
        if( ret != 0 )
        {
            mbedtls_printf("failed!\n");
            goto cleanup;
        }
        fflush( stdout );
        rest_len -= bulk_size;
        buf_hook += bulk_size;
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

    cleanup:
    mbedtls_printf("\n");

    mbedtls_hmac_drbg_free( &hmac_drbg );
    mbedtls_entropy_free( &entropy );

    return( exit_code );
}