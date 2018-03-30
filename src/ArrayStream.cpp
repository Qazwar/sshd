/* ArrayStream.cpp
 * Implements the stream operation on arrays.
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */

#include "ArrayStream.h"

namespace ssh
{
    /* ArrayStream::ArrayStream
     * Constructor, perform the required initialization
     */
    ArrayStream::ArrayStream( const byte * buffer, uint32 length )
    {
        m_buffer    = buffer;
        m_length    = length;
        m_readPos   = 0;
    }

    /* ArrayStream::readBytes
     * Reads data from the array.
     */
    bool ArrayStream::readBytes( byte * dst, int length )
    {
        if( (m_readPos + length) > m_length )
            return false;

        memcpy(dst, m_buffer + m_readPos, length);
        m_readPos += length;

        return true;
    }

    /* ArrayWriteStream::ArrayWriteStream
     *
     */
    ArrayWriteStream::ArrayWriteStream( byte * dst, uint32_t length)
    {
        m_buffer = dst;
        m_length = length;
        m_writePos = 0;
    }

    /* ArrayWriteStream::writeBytes
     *
     */
    bool ArrayWriteStream::writeBytes( const byte * src, int length )
    {
        if( (m_writePos + length) > m_length)
            return false;

        memcpy(m_buffer + m_writePos, src, length);
        m_writePos += length;

        return true;
    }
};