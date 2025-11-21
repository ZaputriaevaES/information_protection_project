#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* АБСОЛЮТНЫЙ МИНИМУМ для SHA256 */
#define MBEDTLS_SHA256_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

/* Отключить ВСЁ остальное */
//#undef MBEDTLS_MD_C
//#undef MBEDTLS_MD5_C
//#undef MBEDTLS_SHA1_C
//#undef MBEDTLS_SHA224_C
//#undef MBEDTLS_SHA384_C
//#undef MBEDTLS_SHA512_C
//#undef MBEDTLS_BIGNUM_C
//#undef MBEDTLS_ECP_C
//#undef MBEDTLS_ECDSA_C

/* Оптимизации для Cortex-M0 */
#define MBEDTLS_SHA256_SMALLER

#include "mbedtls/check_config.h"
#endif
