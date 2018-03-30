/* CStream
 * Generic stream implementation.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project includes */
#include "CStream.h"
#include "messages.h"
#include "byteswap.h"
#include "CBigInt.h"

/* C/C++ includes */
#include <vector>
#include <assert.h>

/* platform includes */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define MAX_STRING_LENGTH       (4096)

using namespace std;

namespace ssh
{
    /* CStream::writeByte
     * Writes a single byte to the stream.
     */
    bool CStream::writeByte(byte b)
    {
        return writeBytes(&b, sizeof(byte));
    }

    /* CStream::readBytes
     * Reads data from the stream and stores it in the vector
     */
    bool CStream::readVector(std::vector<byte> & vec, int length)
    {
        vec.resize( length );
        readBytes(&vec[0], length);

        return true;
    }

    /* CStream::writeBytes
     * Writes the contents of the ByteVector to the stream.
     */
    bool CStream::writeVector(const ByteVector & src)
    {
        if( src.empty() )
            return false;

        return writeBytes(&src[0], static_cast<int>(src.size()));
    }

    /* CStream::writeInt32
     * Writes a 32-bit unsigned integer to the stream encoded in 
     */
    bool CStream::writeInt32(uint32 value)
    {
#if 1
        /* swap the value from little-endian to big-endian */
        value = Swap32(value);
#endif
        return writeBytes(reinterpret_cast<byte*>(&value),sizeof(uint32));
    }

    /* CStream::writeInt64
     * Writes a 64-bit unsigned integer to the stream
     */
    bool CStream::writeInt64(uint64 value)
    {
        value = Swap64(value);
        return writeBytes(reinterpret_cast<byte*>(&value),sizeof(uint64));
    }

    /* CTransport::writeKex
     * Writes the keyexchange information to the output buffer. This can directly be followed
     * by a initial keyexchange packet if the guess was successful.
     */
    bool CStream::writeKex(const KeyExchangeInfo & info)
    {
        if( !writeByte(SSH_MSG_KEXINIT) || !writeBytes(info.cookie, 16) ) {
            return false;
        }

        for(int i = 0; i < MAX_ALGORITHM_COUNT; i++) {
            if( !writeString(info.algorithms[i]) ) {
                return false;
            }
        }
        if( !writeByte(info.follows) || /* first keyexchange packet follows */
            !writeInt32(0) )            /* reserved */
        {
            return false;
        }
        return true;
    }

    /* CStream::readInt32
     * Reads a unsigned 32 bit integer from the stream
     */
    bool CStream::readInt32(uint32 & v)
    {
        uint32 tmp;
        if( !readBytes(reinterpret_cast<byte *>(&tmp), sizeof(uint32)) )
            return false;
#if 1
        /* swap the byte ordering on little endian systems */
        v = Swap32(tmp);
#endif
        return true;
    }

    /* CStream::readInt64
     * Reads a 64 bit integer from the stream
     */
    bool CStream::readInt64(uint64 & v)
    {
        uint64 tmp;
        if( !readBytes(reinterpret_cast<byte *>(&tmp), sizeof(uint64)) )
            return false;
        v = Swap64(tmp);
        return true;
    }

    /* CStream::readByte
     * Reads a single byte from the stream
     */
    bool CStream::readByte(byte & b)
    {
        return readBytes(&b, sizeof(byte));
    }

    /* CStream::readKex
     * Reads a SSH_MSG_KEXINIT packet from the stream.
     */
    bool CStream::readKex(KeyExchangeInfo & info)
    {
        uint32  reserved;
        byte    id;     

        if( !readByte(id ) || (id != SSH_MSG_KEXINIT) || !readBytes(info.cookie, 16) ) {
            return false;
        }
        for(int i = 0; i < MAX_ALGORITHM_COUNT; i++) {
            if( !readString(info.algorithms[i]) ) {
                return false;
            }
        }
        if( !readByte(info.follows) || /* first keyexchange packet follows */
            !readInt32(reserved) ) 
        {
            return false;
        }
        if( reserved != 0 ) {
            return false;
        }
        return true;
    }

    /* CStream::writeString
     * Writes a string to the output buffer.
     */
    bool CStream::writeString(const std::string & str)
    {
        uint32 len = static_cast<uint32>( str.length() );
        if( !writeInt32(len) )
            return false;

        return writeBytes(reinterpret_cast<const uint8_t *>(str.c_str()), len);
    }

    /* CStream::writeString
     *
     */
    bool CStream::writeString(const char * str)
    {
        uint32_t len = strlen( str );
        if( !writeInt32(len) )
            return false;

        return writeBytes( (const byte *) str, len );
    }

    /* CStream::readString
     * Reads a string from the stream.
     */
    bool CStream::readString(std::string & str)
    {
        uint32 len;
        if( !readInt32(len) ) 
            return false;

        if( len == 0 || (len > MAX_STRING_LENGTH) )
            return true;    /* empty string */

        char * dst = new char[len + 1];
        if( !dst )
            return false;

        if( !readBytes((byte *)dst, len) ) {
            delete [] dst;
            return false;
        }

        dst[len] = 0;   /* null-terminate it */
        str = dst;

        delete [] dst;
        return true;
    }

    /* CStream::readUTF8
     * Reads a UTF-8 encoded string from the stream
     */
    bool CStream::readUTF8( std::wstring & str )
    {
        uint32 len;
        int res;

        if( !readInt32(len) )
            return false;

        if( len == 0 || len > MAX_STRING_LENGTH )
            return true;    /* empty string */

        /* read the raw data */
        char * dst = new char[len + 1];
        if( !dst )
            return false;

        if( !readBytes((byte *)dst, len) ) {
            delete [] dst;
            return false;
        }
        dst[len] = 0;

        /* calculate the required length */
        res = MultiByteToWideChar(CP_UTF8, 0, dst, -1, NULL, 0);
        if( res == 0 || res < 0 ) {
            delete [] dst;
            return false;
        }

        wchar_t * wdst = new wchar_t[res + 1];
        if( !wdst ) {
            delete [] dst;
            return false;
        }

        res = MultiByteToWideChar(CP_UTF8, 0, dst, -1, wdst,res);
        
        if( res <= 0 ) {
            delete [] dst;
            delete [] wdst;
            return false;
        }

        wdst[res] = 0;
        str = wdst;

        delete [] dst;
        delete [] wdst;

        return true;
    }

    /* CStream::readString
     *
     */
    bool CStream::readString(byte * dst, uint32 * length)
    {
        /* first read the length */
        if( !readInt32(*length) )
            return false;
        
        /* and then the actual string data */
        return readBytes(dst, *length);
    }

    /* CStream::readBigInt
     *
     */
#if defined(USE_OPENSSL)
    bool CStream::readBigInt(BIGNUM ** bn)
    {
        uint32 length;
        std::vector<byte> vec;

        if( !readInt32( length ) || (length > 4096) )
            return false;

        vec.resize( length );
        if( !readBytes( &vec[0], length ) )
            return false;
        
        if( !(*bn = BN_bin2bn( &vec[0], length, 0 )) )
            return false;

        if( (*bn)->neg ) {
            BN_free(*bn);
            *bn = NULL;
            return false;
        }
        /* success */
        return true;
    }

    /* writes a OpenSSL BIGNUM to the stream */
    bool CStream::writeBigInt(const BIGNUM * bn)
    {
        int numBytes;
        vector<uint8_t> dst;

        assert(bn != NULL);
        if(BN_is_zero(bn)) {
            return writeInt32(static_cast<uint32>(0));
        }
        if(BN_is_negative(bn)) {
            return false;
        }
        numBytes = BN_num_bytes(bn) + 1;
        if(numBytes < 2) {
            return false;
        }
        /* resize the vector to store the binary representation */
        dst.resize(numBytes);
        
        // padding byte
        dst[0] = 0x00;
        // convert the BN to the right representation
        int val = BN_bn2bin(bn, &dst[1]);
        if(val != (numBytes - 1)) {
            return false;
        }
        // check the first byte
        int nohighbit = (dst[1] & 0x80) ? 0 : 1;
        uint32 len = (uint32)(numBytes - nohighbit);
        if( !writeInt32(len) || !writeBytes(&dst[nohighbit], len) )
            return false;

        return true;
    }
#endif

    bool CStream::readBigInt(CBigInt ** bi)
    {
#if defined(USE_OPENSSL)
        BIGNUM * num;
        if( !readBigInt( &num ) )
            return false;

        *bi = new (std::nothrow) CBigInt( num );
        if( !(*bi) ) {
            BN_free(num);
            return false;
        }
        return true;
#endif
    }
};