#if defined(USE_OPENSSL)
#include <openssl/bn.h>
#endif

#include "CStream.h"
#include "CBigInt.h"

#define MAX_NUMBER_LENGTH 512

namespace ssh
{
    /* CBigInt::write
     * Writes the integer to the stream.
     */
    bool CBigInt::write(CStream & stream) const
    {
#if defined(USE_OPENSSL)
        if(BN_is_zero(m_bn)) {
            return stream.writeInt32(static_cast<uint32>(0));
        }
        if(BN_is_negative(m_bn)) {
            return false;
        }
        int numBytes = BN_num_bytes(m_bn) + 1;
        if(numBytes < 2) {
            return false;
        }
        // get the length required to store the data
        unsigned char * data = new (std::nothrow) unsigned char[numBytes];
        if(data == NULL) {
            return false;
        }
        // padding byte
        data[0] = 0x00;
        // convert the BN to the right representation
        int val = BN_bn2bin(m_bn, data+1);
        if(val != numBytes - 1) {
            delete [] data;
            return false;
        }
        // check the first byte
        int nohighbit = (data[1] & 0x80) ? 0 : 1;
        uint32 len = (uint32)(numBytes - nohighbit);
        if( !stream.writeInt32(len) || !stream.writeBytes(data + nohighbit,len) ) {
            delete [] data;
            return false;
        }

        delete [] data;
        return true;
#else
        return false;
#endif
    }

    /* CBigInt::read
     * Reads a big integer from the stream.
     */
    bool CBigInt::read(CStream & stream) 
    {
        byte number[MAX_NUMBER_LENGTH];
        memset(number, 0, MAX_NUMBER_LENGTH);
        uint32 length = MAX_NUMBER_LENGTH;
        if( !stream.readString(number, &length) ) {
            return false;
        }
        
        if( (m_bn = BN_bin2bn(number, length, 0)) == NULL ) {
            return false;
        }
        if( m_bn->neg ) {
            return false;
        }
        return true;
    }

    /* CBigInt::CBigInt
     * Performs the required initialization
     */
    CBigInt::CBigInt()
    {
#if defined(USE_OPENSSL)
        m_bn = NULL;
#endif
    }

#if defined(USE_OPENSSL)
    CBigInt::CBigInt(BIGNUM * bn)
    {
        m_bn = BN_dup(bn);  /* need to duplicate it */
    }
#endif

    /* CBigInt::~CBigInt
     *
     */
    CBigInt::~CBigInt()
    {
#if defined(USE_OPENSSL)
        if( m_bn )
            BN_free(m_bn);
#endif
    }

    const void * CBigInt::Native() const
    {
        return (void *) m_bn;
    }
};