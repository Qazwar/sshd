#ifndef _SWAP_H_
#define _SWAP_H_

#include "types.h"

uint64_t endian_swap64(uint64 x);
uint32_t endian_swap32(uint32 x);
uint16_t endian_swap16(uint16 x);

#if defined(_M_IX86) || defined(__i386__) || defined(_M_X64)
#define __LITTLE_ENDIAN__
#endif

#ifdef __LITTLE_ENDIAN__
#define __ntohl64(x) endian_swap64(x)
#define __htonl64(x) endian_swap64(x)
#define __ntohl32(x) endian_swap32(x)
#define __htonl32(x) endian_swap32(x)
#define __ntohl16(x) endian_swap16(x)
#define __htonl16(x) endian_swap16(x)

#else 
#define __ntohl64(x) x
#define __htonl64(x) x
#define __ntohl64(x) x
#define __htonl64(x) x
#define __ntohl32(x) x
#define __htonl32(x) x
#define __ntohl16(x) x
#define __htonl16(x) x
#endif

inline uint64_t endian_swap64(uint64 x)
{
    return (x>>56) | 
            ((x<<40) & 0x00FF000000000000) |
            ((x<<24) & 0x0000FF0000000000) |
            ((x<<8)  & 0x000000FF00000000) |
            ((x>>8)  & 0x00000000FF000000) |
            ((x>>24) & 0x0000000000FF0000) |
            ((x>>40) & 0x000000000000FF00) |
            (x<<56);
}

inline uint32_t endian_swap32(uint32 x)
{
    return  x = (x>>24) | 
        ((x<<8) & 0x00FF0000) |
        ((x>>8) & 0x0000FF00) |
        (x<<24);
}

inline uint16_t endian_swap16(uint16 x)
{
    return (x>>8) | (x<<8);
}

#endif