//
// Created by carwei01 on 2021/6/7.
//

/*-------------------------------------------------------------------
 *				F8 - Confidentiality Algorithm
 *-------------------------------------------------------------------
 *
 *	A sample implementation of f8, the 3GPP Confidentiality algorithm.
 *
 *	This has been coded for clarity, not necessarily for efficiency.
 *
 *	This will compile and run correctly on both Intel (little endian)
 *  and Sparc (big endian) machines. (Compilers used supported 32-bit ints)
 *
 *	Version 1.0		05 November  1999
 *
 *-------------------------------------------------------------------*/

#include "kasumi.h"
#include <stdio.h>

/*---------------------------------------------------------
 * f8()
 *		Given key, count, bearer, direction,  data,
 *		and bit length  encrypt the bit stream
 *---------------------------------------------------------*/
void f8( u8 *key, int count, int bearer, int dir, u8 *data, int length )
{
    REGISTER64_t A;		/* the modifier			*/
    REGISTER64_t temp;		/* The working register	*/
    int i, n;
    u8  ModKey[16];		/* Modified key		*/
    u16 blkcnt;			/* The block counter */

    /* Start by building our global modifier */

    temp.b32[0]  = temp.b32[1]  = 0;
    A.b32[0]     = A.b32[1]     = 0;

    /* initialise register in an endian correct manner*/

    A.b8[0]  = (u8) (count>>24);
    A.b8[1]  = (u8) (count>>16);
    A.b8[2]  = (u8) (count>>8);
    A.b8[3]  = (u8) (count);
    A.b8[4]  = (u8) (bearer<<3);
    A.b8[4] |= (u8) (dir<<2);

    /* Construct the modified key and then "kasumi" A */

    for( n=0; n<16; ++n )
        ModKey[n] = (u8)(key[n] ^ 0x55);
    KeySchedule( ModKey );

    Kasumi( A.b8 );	/* First encryption to create modifier */

    /* Final initialisation steps */

    blkcnt = 0;
    KeySchedule( key );

    /* Now run the block cipher */

    while( length > 0 )
    {
        /* First we calculate the next 64-bits of keystream */

        /* XOR in A and BLKCNT to last value */

        temp.b32[0] ^= A.b32[0];
        temp.b32[1] ^= A.b32[1];
        temp.b8[7] ^= (u8)  blkcnt;
        temp.b8[6] ^= (u8) (blkcnt>>8);

        /* KASUMI it to produce the next block of keystream */

        Kasumi( temp.b8 );

        /* Set <n> to the number of bytes of input data	*
         * we have to modify.  (=8 if length <= 64)		*/

        if( length >= 64 )
            n = 8;
        else
            n = (length+7)/8;

        /* XOR the keystream with the input data stream */

        for( i=0; i<n; ++i )
            *data++ ^= temp.b8[i];
        length -= 64;	/* done another 64 bits	*/
        ++blkcnt;		/* increment BLKCNT		*/
    }
}

/*-----------------------------------------------------------
 *			e n d    o f    f 8 . c
 *-----------------------------------------------------------*/