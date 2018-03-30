#include "CClientTransport.h"
#include "CKeyExchange.h"
#include "reasons.h"
#include "messages.h"
#include "errors.h"

/* C/C++ includes */
#include <string>

/* Boost */
#include <boost/shared_ptr.hpp>

using namespace std;

namespace ssh
{
    /* CClientTransport::handlePacket
     *
     */
    int CClientTransport::handlePacket()
    {
        return sshd_ERROR;
    }
};