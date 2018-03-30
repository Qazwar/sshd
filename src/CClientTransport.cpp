/* CClientTransport.cpp
 * Implements the client side of the SSH prootocl.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */
#include "CClientTransport.h"
#include "CKeyExchange.h"
#include "reasons.h"
#include "messages.h"
#include "errors.h"
#include "sshd.h"

/* C/C++ includes */
#include <string>

/* Boost */
#include <boost/shared_ptr.hpp>

/*****************************************************/
/*                  DEFINITIONS                      */
/*****************************************************/
#define DEFAULT_POLL_INTERVALL (250)

using namespace std;

namespace ssh
{
    /* CClientTransport::CClientTransport
     *
     */
    CClientTransport::CClientTransport(const ssh::CSettings & settings, ssh::INotify * notify, ssh::IAuthenticate * auth) 
        : CTransport( settings, NULL ), m_iAuth( auth ), m_pNotify( notify )
    {
        m_pService  = NULL;
        m_status    = sshd_STATUS_IDLE;
    }

    /* CClientTransport::~CClientTransport
     * Performs the required cleanup.
     */
    CClientTransport::~CClientTransport()
    {
        if( m_pService )
            delete m_pService;
    }


    int CClientTransport::connect(const std::string & addr, const std::string & port)
    {
        /* save parameters needed to connect */
        m_addr = addr;
        m_port = port;

        /* create the network interface */
        ds = new ssh::CNetwork;
        if (!ds)
            return sshd_ERROR;

        /* spawn the connection thread */
        if (!spawn() )
            return sshd_ERROR;

        return sshd_OK;
    }

    /* CClientTransport::connect
     * Connects to the server.
     */
    int CClientTransport::connect(const char * addr, const char * port)
    {
        /* save parameters needed to connect */
        m_addr = addr;
        m_port = port;

        /* create the network interface */
        ds = new ssh::CNetwork;
        if (!ds)
            return sshd_ERROR;

        /* spawn the connection thread */
        if (!spawn() )
            return sshd_ERROR;

        return sshd_OK;
    }

    /* CClientTransport::Task()
     * The entry-point for the thread that handles the client connection. 
     */
    void CClientTransport::Task()
    {
        int res;

        setStatus(sshd_STATUS_CONNECTING);
        res = ds->connect( m_addr.c_str(), m_port.c_str() );    
        while( res == sshd_CONNECTION_PENDING )
        {
            /* Wait while connecting, but we also need to check if the connection attempt is aborted
             * during the process.
             */
            if( sshd_CheckAbortEvent_NoRet() ) {
                sshd_Log(sshd_EVENT_NOTIFY, "Connection closed by user.");

                if( m_pNotify )
                    m_pNotify->OnConnectFailure(this);

                setStatus(sshd_STATUS_FAILURE);
                return;
            }

            res = ds->poll( DEFAULT_POLL_INTERVALL );
        }

        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "Failed to connect to server");
            if( m_pNotify )
                m_pNotify->OnConnectFailure(this);
            
            setStatus(sshd_STATUS_FAILURE);
            return;
        }

        sshd_Log(sshd_EVENT_NOTIFY, "Connected to server.");
        res = establishConnection();
        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "Failed to establish connection to server.");
            ds->disconnect();
            /* */
            if( m_pNotify )
                m_pNotify->OnConnectFailure(this);

            setStatus(sshd_STATUS_FAILURE);
        } 
        else {
            /* connection established */
            m_pNotify->OnConnectSuccess(this);
            sshd_Log(sshd_EVENT_NOTIFY, "Connection established.");
            mainTask();

            /* connection closed, notify clients and change state. */
            setStatus(sshd_STATUS_CLOSED);
            if( m_pNotify )
                m_pNotify->OnCloseEvent(this);
        }   
    }


    /* CClientTransport::establishConnection
     * Establishes the SSH connection, exchanges the protocol version strings and performs the
     * initial keyexchange.
     */
    int CClientTransport::establishConnection(void)
    {
        int res;
    
        ds->setBlockingMode( true );
        res = exchangeProtocolVersions();
        if( res != sshd_OK )
        {
            if( res == sshd_PROTOCOL_VERSION_UNSUPPORTED ) {
                /* the server's protocol version isn't supported */
                sshd_Log(sshd_EVENT_FATAL, "Protocol version not supported.");
                disconnect( SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED );
            } else {
                sshd_Log(sshd_EVENT_FATAL, "Failed to exchange protocol version strings.");
                disconnect( SSH_DISCONNECT_PROTOCOL_ERROR );
            }
            return sshd_ERROR;
        }
        ds->setBlockingMode( false );

        /* check if the attempt is aborted */
        sshd_CheckAbortEvent();
        
        /* perform the initial keyexchange */
        res = performKeyExchange();
        if( res != sshd_OK ) 
        {
            sshd_Log(sshd_EVENT_FATAL, "Keyexchange failed.");
            return sshd_PROTOCOL_ERROR;
        }

        sshd_CheckAbortEvent();
        
        /* connection established */
        return sshd_OK;
    }

    /* CClientTransport::performKeyExchange
     * Performs the keyexchange.
     */
    int CClientTransport::performKeyExchange(bool bInitial, bool bInitiator)
    {
        int             res;
        bool            guess = false;
        std::string     matches[MAX_ALGORITHM_COUNT];
        KeyVector       keyvec;
        CKeyExchange *  keyexchange = NULL;
        CHostKey *      hostkey     = NULL;
        vector<byte>    exchangeHash;
        const CBigInt * sharedSecret;

        /* create the local kex packet */
        if( !buildLocalKex() ) {
            goto cleanup;
        }

        res = exchangeKeyExchanges(m_localKex, m_remoteKex, bInitial, bInitiator);
        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "Failed to exchange SSH_MSG_KEXINIT messages.");
            goto cleanup;
        }

        /* Decide what algorithms to use */
        if( !DecideAlgorithms(m_localKex.algorithms, m_remoteKex.algorithms, matches, MAX_ALGORITHM_COUNT) ) {
            sshd_Log(sshd_EVENT_FATAL, "Algorithm missmatch.");
            goto cleanup;
        }
        /* create the keyexchange instance */
        keyexchange = CKeyExchange::CreateInstance(matches[KEYEXCHANGE_METHOD], this);
        if( !keyexchange ) {
            goto cleanup;
        }

        /* create the hostkey */
        hostkey = CHostKey::CreateInstance(matches[SERVER_HOSTKEY]);
        if( !hostkey ) {
            goto cleanup;
        }

        res = keyexchange->ClientKeyExchange(hostkey, guess && m_remoteKex.follows);
        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "Keyexchange failed.");
            goto cleanup;
        }

        /* */
        //hostkey->fingerprint();

        /* We need both the exchange hash and the shared secret to derive the keys */
        exchangeHash        = keyexchange->GetExchangeHash();
        sharedSecret        = keyexchange->GetSharedSecret();

        m_exchangeHash = exchangeHash;

        if( m_sessionIdent.empty() )
            m_sessionIdent = exchangeHash;  /* first keyexchange, use the exchange hash as session identifier */

        /* Now derive the required keys */
        res = DeriveKeys(exchangeHash, m_sessionIdent, *sharedSecret, keyexchange->GetHash(), keyvec);
        if( res != sshd_OK )
        {
            sshd_Log(sshd_EVENT_FATAL, "Key derivation process failed.");
            goto cleanup;
        }

        res = TakeKeysIntoUse( keyvec, matches );
        if( res != sshd_OK )
        {
            sshd_Log(sshd_EVENT_FATAL, "Failed to take the new keys into use.");
            goto cleanup;
        }

        /* keyexchange successfull, but we still need to verify the host */
        delete keyexchange;
        delete hostkey;

        /* return success */
        return sshd_OK;

cleanup:
        delete keyexchange;
        delete hostkey;

        /* disconnect */
        disconnect( SSH_DISCONNECT_KEY_EXCHANGE_FAILED );
        return sshd_ERROR;
    }

    /* CServerTransport::InitializeKeys
     *
     */
    void CClientTransport::InitializeKeys(const SecurityBlock & block, const KeyVector & vec)
    {
        /* encryption/decryption */
        if( block.enc_server_to_client )
            block.enc_server_to_client->DecryptInit(vec.keys[CIPHER_KEY_SERVER_TO_CLIENT].key , vec.keys[INITIAL_IV_SERVER_TO_CLIENT].key);

        if( block.enc_client_to_server )
            block.enc_client_to_server->EncryptInit(vec.keys[CIPHER_KEY_CLIENT_TO_SERVER].key , vec.keys[INITIAL_IV_CLIENT_TO_SERVER].key);

        /* integrity */
        if( block.hmac_client_to_server )
            block.hmac_client_to_server->Init( vec.keys[INTEGRITY_KEY_CLIENT_TO_SERVER].key );

        if( block.hmac_server_to_client )
            block.hmac_server_to_client->Init( vec.keys[INTEGRITY_KEY_SERVER_TO_CLIENT].key );
    }

    /* CServerTransport::TakeAlgorithmsInUse
     *
     */
    int CClientTransport::TakeAlgorithmsInUse( const SecurityBlock & block )
    {
        /* delete old instances */
        delete sendState.cipher;
        delete sendState.hmac;
        delete readState.cipher;
        delete readState.hmac;

        /* use the new ones */
        sendState.cipher    = block.enc_client_to_server;
        sendState.hmac      = block.hmac_client_to_server;
        readState.cipher    = block.enc_server_to_client;
        readState.hmac      = block.hmac_server_to_client;

        return sshd_OK;
    }

    /* CClientTransport::getStatus
     * Returns the connection status.
     */
    sshd_ConnectStatus CClientTransport::getStatus()
    {
        sshd_ConnectStatus status;
        m_lock.acquire();
        status = m_status;
        m_lock.release();
        return m_status;
    }

    /* CClientTransport::setStatus
     *
     */
    void CClientTransport::setStatus(sshd_ConnectStatus status)
    {
        m_lock.acquire();
        m_status = status;
        m_lock.release();
    }
}