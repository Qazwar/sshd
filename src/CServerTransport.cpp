/* CServerTransport
 * Implements the server aspect of the transport layer
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project specific includes */
#include "CServerTransport.h"
#include "debug.h"
#include "sshd.h"
#include "events.h"
#include "CKeyExchange.h"
#include "reasons.h"
#include "errors.h"

/* C/C++ includes */
#include <memory>   /* for auto_ptr */
#include <fstream>
#include <string>

/* Boost */
#include <boost/shared_ptr.hpp>

using namespace std;

namespace ssh
{
    /* CServerTransport::CServerTransport
     * Constructor, performs the required initializations.
     */
    CServerTransport::CServerTransport(
        const ssh::CSettings & settings,                            /* settings to be used */
        CNetwork * network,                                         /* network (socket) */
        ssh::sshd * server)                                         /* the ssh server */
        :   CTransport(settings, network), m_sshd( server )
    {
        m_pAuthService  = NULL;
        m_pService      = NULL;
    }

    /* CServerTransport::~CServerTransport
     * Destructor, performs the required cleanup.
     */
    CServerTransport::~CServerTransport()
    {
        if( m_pService )
            delete m_pService;
        if( m_pAuthService )
            delete m_pAuthService;
    }

    /* CServerTransport::displayMotd
     * Writes the contents of the MOTD (Message of the Day) file to the client.
     * Easier to just read the contents each time than storing the entire file in memory 
     * since it could be quite big and may be updated by the user while the server is still running.
     */
    int CServerTransport::displayMotd(const char * filename)
    {
        ifstream file;
        string line;

        if( filename == NULL )  /* don't display anything */
            return sshd_OK;

        file.open(filename, ios_base::in);
        if( !file ) {
            return sshd_INTERNAL_ERROR;
        }

        while( !file.eof() ) {
            getline(file, line);
            /* verify that the line doesn't start with SSH- */
            size_t pos = line.find("SSH-");
            if( pos == 0 ) {
                /* line begins with SSH-, abort the transmission of the MOTD */
                return sshd_OK;
            }
            if( !ds->writeLine(line) ) {
                return sshd_ERROR;
            }
        }
        return sshd_OK;
    }

    /* CServerTransport::displayMotd
     * Displays the message of the day.
     */
    int CServerTransport::displayMotd(const string & filename)
    {
        return displayMotd( filename.c_str() );
    }

    /* CServerTransport::establishConnection
     * Establishes the connection. Since the actual socket connection is already established 
     * the first thing the server needs to do is to exchange the version strings.
     */
    int CServerTransport::establishConnection()
    {
        int motdEnabled, res;
        string motdFile;

        /* Display the MOTD file for the client if it's enabled */
        if( m_settings.GetValue(SSHD_SETTING_MOTD_ENABLED, motdEnabled) &&
            motdEnabled &&
            m_settings.GetString(SSHD_SETTING_MOTD_FILE, motdFile) )
        {
            if( displayMotd(motdFile) != sshd_OK ) {
                return sshd_ERROR;
            }
        }

        ds->setBlockingMode( true );
        /* Exchange the protocol version strings */
        if( (res = exchangeProtocolVersions()) != sshd_OK ) 
        {
            return sshd_ERROR;
        }
        ds->setBlockingMode( false );

        res = performKeyExchange();
        if( res != sshd_OK )
            return sshd_ERROR;

        return sshd_OK;
    }

    /* CServerTransport::performKeyExchange 
     * Performs the server-side keyexchange.
     */
    int CServerTransport::performKeyExchange(bool bInitial, bool bInitiator)
    {
        int res;
        bool guess = false;
        CKeyExchange * keyexchange;
        CHostKey * hostkey;

        std::string matches[MAX_ALGORITHM_COUNT];

        /* create the local kex packet */
        if( !buildLocalKex() ) {
            return sshd_INTERNAL_ERROR;
        }

        res = exchangeKeyExchanges(m_localKex, m_remoteKex, bInitial, bInitiator);
        if( res != sshd_OK )
            return sshd_ERROR;

        /* Decide what algorithms to use */
        if( !DecideAlgorithms(m_remoteKex.algorithms, m_localKex.algorithms, matches, MAX_ALGORITHM_COUNT) ) {
            /* algorithms does not match */
            sshd_Log(sshd_EVENT_FATAL, "Algorithm missmatch.");
            disconnect( SSH_DISCONNECT_KEY_EXCHANGE_FAILED );
            return sshd_ERROR;
        }

        /* create the keyexchange instance */
        keyexchange = CKeyExchange::CreateInstance(matches[KEYEXCHANGE_METHOD], this);
        if( !keyexchange ) {
            disconnect( SSH_DISCONNECT_BY_APPLICATION );
            sshd_Log(sshd_EVENT_FATAL, "Failed to instansiate algorithms.");
            return sshd_INTERNAL_ERROR;
        }

        /* create the hostkey */
        hostkey = CHostKey::CreateInstance(matches[SERVER_HOSTKEY]);
        if( !hostkey ) {
            disconnect( SSH_DISCONNECT_BY_APPLICATION );
            return sshd_INTERNAL_ERROR;
        }

        /* load the server's private keys */
        if( !hostkey->loadKeys(m_settings) ) {
            sshd_Log(sshd_EVENT_FATAL, "Failed to load key-pair.");
            return sshd_INTERNAL_ERROR;
        }

        res = keyexchange->ServerKeyExchange(hostkey, guess && m_remoteKex.follows);
        if( res != sshd_OK )
        {
            sshd_Log(sshd_EVENT_FATAL, "Keyexchange failed.");
            disconnect( SSH_DISCONNECT_KEY_EXCHANGE_FAILED );
            return sshd_ERROR;
        }

        /* We need both the exchange hash and the shared secret to derive the keys */
        vector<byte> exchangeHash       = keyexchange->GetExchangeHash();
        const CBigInt * sharedSecret    = keyexchange->GetSharedSecret();

        m_exchangeHash = exchangeHash;

        if( m_sessionIdent.empty() ) {
            /* the first exchange hash is also the session identifier */
            DBG("First keyexchange, using the exchange hash as session identifier.");
            m_sessionIdent = exchangeHash;
        }

        KeyVector keyvec;

        /* Now derive the required keys */
        res = DeriveKeys(exchangeHash, m_sessionIdent, *sharedSecret, keyexchange->GetHash(), keyvec);
        if( res != sshd_OK ) {
            disconnect( SSH_DISCONNECT_KEY_EXCHANGE_FAILED );
            return sshd_ERROR;
        }

        /* Now initialize the algorithms */
        if( TakeKeysIntoUse( keyvec, matches ) != sshd_OK ) {
            disconnect( SSH_DISCONNECT_KEY_EXCHANGE_FAILED );
            return sshd_ERROR;
        }

        return sshd_OK;
    }

    /* CServerTransport::InitializeKeys
     *
     */
    void CServerTransport::InitializeKeys(const SecurityBlock & block, const KeyVector & vec)
    {
        /* encryption/decryption */
        if( block.enc_server_to_client )
            block.enc_server_to_client->EncryptInit(vec.keys[CIPHER_KEY_SERVER_TO_CLIENT].key , vec.keys[INITIAL_IV_SERVER_TO_CLIENT].key);

        if( block.enc_client_to_server )
            block.enc_client_to_server->DecryptInit(vec.keys[CIPHER_KEY_CLIENT_TO_SERVER].key , vec.keys[INITIAL_IV_CLIENT_TO_SERVER].key);

        /* integrity */
        if( block.hmac_client_to_server )
            block.hmac_client_to_server->Init( vec.keys[INTEGRITY_KEY_CLIENT_TO_SERVER].key );

        if( block.hmac_server_to_client )
            block.hmac_server_to_client->Init( vec.keys[INTEGRITY_KEY_SERVER_TO_CLIENT].key );
    }

    /* CServerTransport::TakeAlgorithmsInUse
     *
     */
    int CServerTransport::TakeAlgorithmsInUse( const SecurityBlock & block )
    {
        /* delete old instances */
        delete sendState.cipher;
        delete sendState.hmac;
        delete readState.cipher;
        delete readState.hmac;

        /* use the new ones */
        sendState.cipher    = block.enc_server_to_client;
        sendState.hmac      = block.hmac_server_to_client;
        readState.cipher    = block.enc_client_to_server;
        readState.hmac      = block.hmac_client_to_server;

        return sshd_OK;
    }
};