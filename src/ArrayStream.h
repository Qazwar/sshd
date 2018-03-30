/* ArrayStream.h
 * Used to read/write complex types to/from a array
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */
#include "CStream.h"
#include "types.h"

namespace ssh
{
    /* ArrayStream
     * Stream I/0 from a array.
     */
    class ArrayStream : public ssh::CStream
    {
    public:
    
        ArrayStream( const byte * buffer, uint32 length );
        bool readBytes(byte *, int);
        
    protected:
        uint32 m_readPos, m_writePos, m_length;
        const byte * m_buffer;
    };

    /* ArrayWriteStream
     *
     */
    class ArrayWriteStream : public ssh::CStream
    {
    public:
        ArrayWriteStream(byte *, uint32_t);
        bool writeBytes( const byte * src, int length );
        uint32_t GetUsage() {return m_writePos;}

    protected:
        uint32_t m_writePos, m_length;
        byte * m_buffer;
    };
};