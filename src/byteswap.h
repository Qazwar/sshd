/* byteswap.h
 * Defines the required byte swapping macros
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */

#ifndef _BYTESWAP_H_
#define _BYTESWAP_H_

/* Swaps a 32 bit value */
#define Swap32(x) ((x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24))
/* Swaps a 16 bit value */
#define Swap16(x) ((x >> 8) | (x << 8))
/* Swaps a 64 bit value */
#define Swap64(x)((x >> 56)|((x >> 40) & 0xff00)|((x >> 24) & 0xff0000)|((x >> 8) & 0xff000000)|((x & 0xff000000) << 8)|((x & 0xff0000) << 24)|((x&0xff00)<<40)|(x<<56))

#endif