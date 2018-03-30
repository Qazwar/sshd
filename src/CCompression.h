#ifndef _CCOMPRESSION_H_
#define _CCOMPRESSION_H_

/* project includes */
#include "CAlgorithm.h"

namespace ssh
{
    /* CCompression
     * Baseclass for the different compression implementations.
     */
    class CCompression : public CAlgorithm
    {
    public:
        int GetType() {return CAlgorithm::COMPRESSION;}
    };
};

#endif