#ifndef _FILESTREAM_H_
#define _FILESTREAM_H_

/* C/C++ headers */
#include "CStream.h"

namespace ssh
{
    /* FileStream
     *
     */
    class FileStream : public CStream
    {
    public:
        FileStream();
        ~FileStream();

        typedef enum { 
            STREAM_MODE_READ = 0,
            STREAM_MODE_WRITE
        } StreamMode;

        /* opens/closes a file */
        bool open(const char * file, StreamMode);
        void close();

        /* Stream functions */
        bool writeBytes(const byte *, int);
        bool readBytes(byte *, int);

    protected:
        FILE * m_file;
    };
};

#endif
