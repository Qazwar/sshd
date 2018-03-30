#ifndef _CHASHSTREAM_H_
#define _CHASHSTREAM_H_

#include "CStream.h"
#include "CHash.h"

namespace ssh
{
    /* CHashStream
     *
     */
    class CHashStream : public CStream
    {
    public:
        CHashStream(const char * name);
        ~CHashStream();

        bool writeBytes(const byte *, int);         /* updates the hash */
        void finalize(byte *, unsigned int *);      /* finalizes the hash */
        void finalize(std::vector<byte> &);
        void reset();

        bool operator!() {return false;}
    protected:
        CHash * m_hash;
    };
};

#endif