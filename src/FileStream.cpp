/* FileStream.cpp
 * Implements stream operations on files.
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */

/* C/C++ includes */
#include <cstdlib>
#include <cstdio>

/* project includes */
#include "FileStream.h"

namespace ssh
{
    /* FileStream::FileStream
     * Constructor, performs the initialization
     */
    FileStream::FileStream()
    {
        m_file = NULL;
    }

    /* FileStream::~FileStream
     * Destructor, performs the required cleanup
     */
    FileStream::~FileStream()
    {
        if( m_file ) 
            fclose( m_file );
    }

    /* FileStream::open
     * Opens and associates a file with the stream
     */
    bool FileStream::open( const char * filename, FileStream::StreamMode mode)
    {
        switch( mode )
        {
        case STREAM_MODE_READ:
            m_file = fopen( filename, "rb" );
            break;
        case STREAM_MODE_WRITE:
            m_file = fopen( filename, "wb" );
        }

        return (m_file != NULL);
    }

    /* FileStream::close
     * Closes the associated file.
     */
    void FileStream::close( void ) 
    {
        if( m_file ) {
            fclose( m_file );
            m_file = NULL;
        }
    }

    /* FileStream::writeBytes
     * Writes the requested data to the file.
     */
    bool FileStream::writeBytes(const byte * src, int count)
    {
        if( !src )
            return false;
        if( !m_file )
            return false;

        return (fwrite(src, 1, count, m_file) == count);
    }

    /* FileStream::readBytes
     * Reads the requested data from the file.
     */
    bool FileStream::readBytes(byte * dst, int count)
    {
        if( !dst )
            return false;
        if( !m_file )
            return false;

        return ( fread( dst, 1, count, m_file ) == count );
    }
};
