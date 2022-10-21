//
// Created by carwei01 on 2021/6/7.
//
/*-------------------------------------------------------------------
 *				F9 - Integrity Algorithm
 *-------------------------------------------------------------------
 *
 *	A sample implementation of f9, the 3GPP Integrity algorithm.
 *
 *	This has been coded for clarity, not necessarily for efficiency.
 *
 *	This will compile and run correctly on both Intel (little endian)
 *  and Sparc (big endian) machines. (Compilers used supported 32-bit ints)
 *
 *	Version 1.1		05 September  2000
 *
 *-------------------------------------------------------------------*/

#include "kasumi.h"
#include <stdio.h>
#define TEST_THRO
/*---------------------------------------------------------
 * f9()
 *		Given key, count, fresh, direction, data,
 *		and message length, calculate the hash value
 *---------------------------------------------------------*/
u8 *f9( u8 *key, int count, int fresh, int dir, u8 *data, int length )
{
    REGISTER64_t A;	/* Holds the CBC chained data			*/
    REGISTER64_t B;	/* Holds the XOR of all KASUMI outputs	*/
    u8  FinalBit[8] = {0x80, 0x40, 0x20, 0x10, 8,4,2,1};
    u8  ModKey[16];
    static u8 mac_i[4];	/* static memory for the result */
    int i, n;

    /* Start by initialising the block cipher */

    KeySchedule( key );

    /* Next initialise the MAC chain.  Make sure we	*
     * have the data in the right byte order.			*
     * <A> holds our chaining value...				*
     * <B> is the running XOR of all KASUMI o/ps		*/

    for( n=0; n<4; ++n )
    {
        A.b8[n]   = (u8)(count>>(24-(n*8)));
        A.b8[n+4] = (u8)(fresh>>(24-(n*8)));
    }
    Kasumi( A.b8 );
    B.b32[0] = A.b32[0];
    B.b32[1] = A.b32[1];

    /* Now run the blocks until we reach the last block */

    while( length >= 64 )
    {
        for( n=0; n<8; ++n )
            A.b8[n] ^= *data++;
        Kasumi( A.b8 );
        length -= 64;
        B.b32[0] ^= A.b32[0];	/* running XOR across */
        B.b32[1] ^= A.b32[1];	/* the block outputs	 */
    }

    /* Process whole bytes in the last block */

    n = 0;
    while( length >=8 )
    {
        A.b8[n++] ^= *data++;
        length -= 8;
    }


    /* Now add the direction bit to the input bit stream	*
     * If length (which holds the # of data bits in the	*
     * last byte) is non-zero we add it in, otherwise		*
     * it has to start a new byte.						*/

    if( length )
    {
        i = *data;
        if( dir )
            i |= FinalBit[length];
    }
    else
        i = dir ? 0x80 : 0;

    A.b8[n++] ^= (u8)i;

    /* Now add in the final '1' bit.  The problem here	*
     * is if the message length happens to be n*64-1.		*
     * If so we need to process this block and then		*
     * create a new input block of 0x8000000000000000.	*/

    if( (length==7) && (n==8 ) )	/* then we've filled the block */
    {
        Kasumi( A.b8 );
        B.b32[0] ^= A.b32[0];	/* running XOR across	*/
        B.b32[1] ^= A.b32[1];	/* the block outputs	*/

        A.b8[0] ^= 0x80;			/* toggle first bit */
        i = 0x80;
        n = 1;
    }
    else
    {
        if( length == 7 )		/* we finished off the last byte */
            A.b8[n] ^= 0x80;		/* so start a new one.....		*/
        else
            A.b8[n-1] ^= FinalBit[length+1];
    }


    Kasumi( A.b8 );
    B.b32[0] ^= A.b32[0];	/* running XOR across	*/
    B.b32[1] ^= A.b32[1];	/* the block outputs		*/

    /* Final step is to KASUMI what we have using the	*
     * key XORd with 0xAAAA.....						*/

    for( n=0; n<16; ++n )
        ModKey[n] = (u8)*key++ ^ 0xAA;
    KeySchedule( ModKey );
    Kasumi( B.b8 );

    /* We return the left-most 32-bits of the result */

    for( n=0; n<4; ++n )
        mac_i[n] = B.b8[n];

    return( mac_i );
}

/*-----------------------------------------------------------
 *			e n d    o f    f 9 . c
 *-----------------------------------------------------------*/
