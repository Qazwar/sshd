#ifndef _ALGORITHMCOLLECTION_H_
#define _ALGORITHMCOLLECTION_H_

#include "CCipher.h"
#include "CHmac.h"
#include "CCompression.h"

namespace sshd
{
    /* AlgorithmCollection
     *
     */
    class AlgorithmCollection
    {
    public:

        bool CreateInstances( const (&std::string)[MAX_ALGORITHM_COUNT] );
        bool InitializeKeys(const KeyVector &);

        CCipher *       ciphers[2];
        CHmac   *       mac[2];
        CCompression *  compression[2];
    };
};

#endif