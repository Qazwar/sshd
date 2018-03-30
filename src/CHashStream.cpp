/* CHashStream.cpp
 *
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#include "CHashStream.h"

namespace ssh
{
    /* */
    CHashStream::CHashStream(const char * name)
    {
        m_hash = CHash::CreateInstance( name );
    }

    /* */
    CHashStream::~CHashStream()
    {
        if( m_hash )
            delete m_hash;
    }

    /* updates the digest with the supplied data */
    bool CHashStream::writeBytes(const byte * src, int count)
    {
        if( !src )
            return false;
        m_hash->update(src, count);
        return true;
    }

    /* Finalizes the hash */
    void CHashStream::finalize(byte * dst, unsigned int * length)
    {
        if( dst ) 
            m_hash->finalize(dst, length);
    }

    /* Finalizes the hash */
    void CHashStream::finalize(std::vector<byte> & vec)
    {
        unsigned int length;
        /* resize the vector */
        vec.resize( m_hash->length() );
        /* store the result in the vector */
        m_hash->finalize(&vec[0], &length);
    }

    /* */
    void CHashStream::reset()
    {
        m_hash->reinit();
    }
}