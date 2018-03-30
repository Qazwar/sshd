/* project includes */
#include "CAlgorithm.h"
#include "CCipher.h"
#include "CHmac.h"
#include "CTransport.h"

/* c/c++ includes */
#include <cstdlib>

namespace ssh
{
    /* CAlgorithm::CreateInstance
     * Acts like a factory for the different algorithms.
     */
    CAlgorithm * CAlgorithm::Create(const std::string & name, int type, CTransport *)
    {
        switch( type )
        {
        case CAlgorithm::CIPHER:
            {
                return CCipher::CreateInstance( name );
            }
        case CAlgorithm::HMAC:
            {
                return CHmac::CreateInstance( name );
            }
        case CAlgorithm::COMPRESSION:
            {
                return NULL;
            }
        default:
            return NULL;
        }
    }
};