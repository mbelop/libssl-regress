/*
 *  Copyright (C) 2006-2007  Christophe Devine
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of XySSL nor the names of its contributors may be
 *      used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>

#include <ssl/aes.h>

/*
 * AES test vectors from:
 *
 * http://csrc.nist.gov/archive/aes/rijndael/rijndael-vals.zip
 */
static const unsigned char aes_test_ecb_dec[3][16] =
{
    { 0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58,
      0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0 },
    { 0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
      0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4 },
    { 0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
      0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE }
};

static const unsigned char aes_test_ecb_enc[3][16] =
{
    { 0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73,
      0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F },
    { 0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11,
      0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14 },
    { 0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D,
      0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4 }
};

static const unsigned char aes_test_cbc_dec[3][16] =
{
    { 0xFA, 0xCA, 0x37, 0xE0, 0xB0, 0xC8, 0x53, 0x73,
      0xDF, 0x70, 0x6E, 0x73, 0xF7, 0xC9, 0xAF, 0x86 },
    { 0x5D, 0xF6, 0x78, 0xDD, 0x17, 0xBA, 0x4E, 0x75,
      0xB6, 0x17, 0x68, 0xC6, 0xAD, 0xEF, 0x7C, 0x7B },
    { 0x48, 0x04, 0xE1, 0x81, 0x8F, 0xE6, 0x29, 0x75,
      0x19, 0xA3, 0xE8, 0x8C, 0x57, 0x31, 0x04, 0x13 }
};

static const unsigned char aes_test_cbc_enc[3][16] =
{
    { 0x8A, 0x05, 0xFC, 0x5E, 0x09, 0x5A, 0xF4, 0x84,
      0x8A, 0x08, 0xD3, 0x28, 0xD3, 0x68, 0x8E, 0x3D },
    { 0x7B, 0xD9, 0x66, 0xD5, 0x3A, 0xD8, 0xC1, 0xBB,
      0x85, 0xD2, 0xAD, 0xFA, 0xE8, 0x7B, 0xB1, 0x04 },
    { 0xFE, 0x3C, 0x53, 0x65, 0x3E, 0x2F, 0x45, 0xB5,
      0x6F, 0xCD, 0x88, 0xB2, 0xCC, 0x89, 0x8F, 0xF0 }
};

/*
 * AES-CFB test vectors (generated on 2008-02-12)
 */
static const unsigned char aes_test_cfb_dec[3][16] =
{
    { 0xBA, 0x75, 0x0C, 0xC9, 0x77, 0xF8, 0xD4, 0xE1,
      0x3E, 0x0F, 0xB5, 0x46, 0x2E, 0xA6, 0x33, 0xF6 },
    { 0xDB, 0x40, 0x4A, 0x98, 0x7B, 0xAA, 0xA3, 0xF3,
      0x92, 0x35, 0xAD, 0x58, 0x09, 0x9B, 0xFF, 0x6E },
    { 0xA8, 0x17, 0x41, 0x0E, 0x76, 0x71, 0x60, 0xE5,
      0xFD, 0x37, 0xC5, 0x43, 0xCC, 0xC8, 0xD6, 0xDA }
};

static const unsigned char aes_test_cfb_enc[3][16] =
{
    { 0x45, 0x62, 0xC5, 0xA1, 0xF9, 0x10, 0x8F, 0xE0,
      0x87, 0x24, 0x25, 0x68, 0xB5, 0x12, 0xF3, 0x8B },
    { 0xB8, 0xD4, 0xD5, 0x09, 0xF5, 0xEE, 0x08, 0x38,
      0x48, 0x9B, 0x9D, 0xAD, 0x11, 0xB4, 0x2E, 0xD2 },
    { 0xE9, 0x10, 0x80, 0xDA, 0xEE, 0x2D, 0x81, 0xD9,
      0x41, 0x78, 0x91, 0xD5, 0x98, 0x78, 0xE1, 0xFA }
};

int verbose = 1;

int
main(void)
{
    int i, j, u, v, offset;
    unsigned char key[32];
    unsigned char buf[16];
    unsigned char prv[16];
    unsigned char iv[16];
    aes_context ctx;

    memset( key, 0, 32 );

    /*
     * ECB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            printf( "  AES-ECB-%3d (%s): ", 128 + u * 64,
                    ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memset( buf, 0, 16 );

        if( v == AES_DECRYPT )
        {
            aes_setkey_dec( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_ecb( &ctx, v, buf, buf );

            if( memcmp( buf, aes_test_ecb_dec[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }
        else
        {
            aes_setkey_enc( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_ecb( &ctx, v, buf, buf );

            if( memcmp( buf, aes_test_ecb_enc[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }

    if( verbose != 0 )
        printf( "\n" );

    /*
     * CBC mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            printf( "  AES-CBC-%3d (%s): ", 128 + u * 64,
                    ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memset( iv , 0, 16 );
        memset( prv, 0, 16 );
        memset( buf, 0, 16 );

        if( v == AES_DECRYPT )
        {
            aes_setkey_dec( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_cbc( &ctx, v, 16, iv, buf, buf );

            if( memcmp( buf, aes_test_cbc_dec[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }
        else
        {
            aes_setkey_enc( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
            {
                unsigned char tmp[16];

                aes_crypt_cbc( &ctx, v, 16, iv, buf, buf );

                memcpy( tmp, prv, 16 );
                memcpy( prv, buf, 16 );
                memcpy( buf, tmp, 16 );
            }

            if( memcmp( prv, aes_test_cbc_enc[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }

    if( verbose != 0 )
        printf( "\n" );

    /*
     * CFB mode
     */
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            printf( "  AES-CFB-%3d (%s): ", 128 + u * 64,
                    ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memset( iv , 0, 16 );
        memset( buf, 0, 16 );
        offset = 0;

        if( v == AES_DECRYPT )
        {
            aes_setkey_dec( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_cfb( &ctx, v, 16, &offset, iv, buf, buf );

            if( memcmp( buf, aes_test_cfb_dec[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }
        else
        {
            aes_setkey_enc( &ctx, key, 128 + u * 64 );

            for( j = 0; j < 10000; j++ )
                aes_crypt_cfb( &ctx, v, 16, &offset, iv, buf, buf );

            if( memcmp( buf, aes_test_cfb_enc[u], 16 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }


    if( verbose != 0 )
        printf( "\n" );

    return( 0 );
}
