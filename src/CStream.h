#ifndef _CSTREAM_H_
#define _CSTREAM_H_

/* C/C++ includes */
#include <string>
#include "types.h"

/* project includes */
#include "KeyExchange.h"
#include "defines.h"

#if defined(USE_OPENSSL)
#define WIN32_LEAN_AND_MEAN
#include <openssl/bn.h>
#endif

namespace ssh
{
    class CBigInt;

    /* CStream
     * Stream interface class. Each derived class must implement the basic functions
     * writeBytes() and readBytes().
     */
    class CStream
    {
    public:
    
        virtual ~CStream() {}

        virtual bool writeBytes(const byte *, int) {return false;}
        virtual bool readBytes(byte *, int) {return false;}
        
        bool readVector(std::vector<byte> &, int);
        bool writeVector(const ByteVector &);

        /* write functions */
        bool writeByte(byte);
        bool writeString(const std::string &);
        bool writeString(const char *);

        bool writeInt32(uint32);
        bool writeInt64(uint64);
#if defined(USE_OPENSSL)
        bool writeBigInt(const BIGNUM *);
        bool writeBigInt(const BIGNUM &);
#endif

        /* read functions */
        bool readString(std::string &);
        bool readString(byte *, uint32 *);
        bool readByte(byte &);
        bool readInt32(uint32 &);
        bool readInt64(uint64 &);
        bool readUTF8(std::wstring &); 

#if defined(USE_OPENSSL)
        bool readBigInt(BIGNUM **);
#endif
        bool readBigInt(CBigInt **);
        bool writeKex(const KeyExchangeInfo &);
        bool readKex(KeyExchangeInfo &);
    };
};

#endif