#ifndef _CHOSTKEY_H_
#define _CHOSTKEY_H_

/* project includes */
#include "types.h"
#include "CStream.h"
#include "CAlgorithm.h"
#include "CSettings.h"

namespace ssh
{
    /* CHostKey
     * Baseclass for the hostkey algorithms. Used for host verification.
     */
    class CHostKey : public CAlgorithm
    {
    public:

        virtual ~CHostKey() {}

        int GetType() {return CAlgorithm::HOSTKEY;}

        /*
         * Client operations.
         */
        /* Parses the keyblob sent by the server */
        virtual bool ParseKeyblob( const byte *, uint32 )       = 0;
        virtual bool ParseKeyblob( CStream & stream )           = 0;

        virtual bool WriteKeyblob( CStream & stream )           = 0;

        /* Parses the signature blob sent by the server */
        virtual bool ParseSignature( const byte *, uint32 )     = 0;;
        virtual bool ParseSignature( CStream & stream )         = 0;

        /* writes the signature to the stream */
        virtual bool WriteSignature( CStream & stream, const std::vector<uint8_t> & ) = 0;

        /* Verifies that the parsed signature matches */
        virtual bool VerifyHost( const std::vector<byte> & ) = 0;
        /* loads the keys */
        virtual bool loadKeys(const ssh::CSettings &)           = 0;

        /*
         * Server operations
         */
        virtual bool Sign( const std::vector<byte> &, std::vector<byte> & ) = 0;
        virtual bool WritePublicKey( CStream & ) = 0;       
        /*
         * Factory function.
         */
        static CHostKey * CreateInstance(const std::string &);
    };
};

#endif