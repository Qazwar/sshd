#ifndef _CKEYEXCHANGE_H_
#define _CKEYEXCHANGE_H_

/* project includes */
#include "CHostKey.h"
#include "CBigInt.h"
#include "CAlgorithm.h"

/* boost */
#include <boost/shared_ptr.hpp>

namespace ssh
{
    class CTransport;

    /* CKeyExchange
     * Baseclass for the keyexchange algorithms
     */
    class CKeyExchange : public CAlgorithm
    {
    public:
        CKeyExchange(CTransport * ts) {m_ts = ts;}
        virtual ~CKeyExchange() { }

        int GetType() {return CAlgorithm::KEYEXCHANGE;}

        virtual int ServerKeyExchange(CHostKey *, bool guess)   = 0;    /* performs the server-side keyexchange */
        virtual int ClientKeyExchange(CHostKey *, bool guess)   = 0;    /* performs the client-side keyexchange */

        const CBigInt * GetSharedSecret()           {return m_secret;}      /* returns the shared secret */
        const std::vector<byte> & GetExchangeHash() {return m_exchange;}    /* returns the exchange hash */

        virtual const char * GetHash() const = 0;

        /* factory */
        static CKeyExchange * CreateInstance(const std::string &, CTransport *);
    protected:
        CBigInt *               m_secret;       /* the shared secret */
        CTransport *            m_ts;           /* required in order to send packets */
        std::vector<byte>       m_exchange; /* the exchange hash */
    };
};

#endif