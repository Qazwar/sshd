#ifndef _CTRANSPORT_H_
#define _CTRANSPORT_H_

/* standard C/C++ includes */
#include <vector>

/* project specific includes */
#include "dmx.h"
#include "types.h"
#include "CComponent.h"
#include "CStream.h"
#include "KeyExchange.h"
#include "CBigInt.h"
#include "CSettings.h"
#include "CNetwork.h"

/* algorithms */
#include "CCipher.h"
#include "CCompression.h"
#include "CHmac.h"
#include "CHash.h"

#include "CThread.h"
#include "Event.h"
#include "Mutex.h"
#include "ssh_hdr.h"
#include "sequence_number.h"

/* Declarations */
#define MAX_EVENT_NOTIFY            (16)
#define MAX_KEYS                    (6)
#define MAX_KEY_LENGTH              (64)
/* */
enum {
    INITIAL_IV_CLIENT_TO_SERVER = 0,
    INITIAL_IV_SERVER_TO_CLIENT,
    CIPHER_KEY_CLIENT_TO_SERVER,
    CIPHER_KEY_SERVER_TO_CLIENT,
    INTEGRITY_KEY_CLIENT_TO_SERVER,
    INTEGRITY_KEY_SERVER_TO_CLIENT
};

/* */
enum {
    sshd_STATE_NO_PACKET = 0, 
    sshd_STATE_FIRST_BLOCK,
    sshd_STATE_FINALIZE,
    sshd_STATE_READING_PACKET,
    sshd_STATE_SENDING_PACKET,
    sshd_STATE_READING_PAYLOAD
};

#define MAX_SSH_PAYLOAD         (32000 - sizeof(ssh_hdr) - 255) /* padding and header is included in the size limit */

namespace ssh
{
    /* Forward declarations */
    class CTransport;

    typedef void (*EventNotification) (uint32, CTransport *, void *);

    struct NotifyEntity {
        EventNotification   notify;     /* notification function */
        uint32              mask;       /* event mask */
    };

    struct TransferState {
        int             state;          /* current state */
        
        uint32_t        dataSize;       /* total number of bytes to send */
        uint32_t        count;          /* number of bytes sent */
        uint32_t        blockSize;      /* block size */
        uint32_t        payloadSize;
        uint32_t        bufSize;

        CHmac           * hmac;         /* integrity control */
        CCompression    * compress;     /* compression */
        CCipher         * cipher;       /* symmetric cipher */
        
        ssh_hdr         * pHdr;             
        uint8_t         * pMac;
        uint8_t         * pPad;
        uint8_t         * pPayload;
        uint8_t         * pData;        /* data buffer */

        ssh_hdr         hdr;            
        sequence_number<uint32_t> seq;  /* sequence number */
    };

    struct KeyElement {
        byte key[256/8/*MAX_KEY_SIZE*/];
    };

    struct KeyVector {
        KeyElement keys[MAX_KEYS];
        KeyElement & operator[](int i) {return keys[i];}
    };

    struct ProtocolVersion {
        std::string protocolVersion;
        std::string softwareVersion;
        std::string comment;
    };

    typedef struct 
    {
        CCipher * enc_server_to_client;
        CCipher * enc_client_to_server;
        CHmac   * hmac_server_to_client;
        CHmac   * hmac_client_to_server;
    } SecurityBlock;

    /* CTransport
     * Implements the SSH transport layer.
     */
    class CTransport : public CStream, public Util::CThread
    {
    public:
        /* */
        CTransport(const CSettings &, ssh::CNetwork *);
        virtual ~CTransport();

        /* performs required initialization */
        bool init();

        virtual bool isServer() = 0;
        virtual int performKeyExchange(bool, bool) = 0;

        bool writeBytes(const byte *, int);
        bool readBytes(byte *, int);

        int sendPacket(int timeout = 10000);    /* sends a packet to the remote host */
        int readPacket(int timeout = 10000);    /* reads a packet from the remote host */

        void newPacket();
        int exchangeAndExpect(byte);            /* sends a message and expects a specific message type back */

        virtual const KeyExchangeInfo & getServerKex() = 0;
        virtual const KeyExchangeInfo & getClientKex() = 0;
        virtual const std::string & getServerProtocolString() = 0;
        virtual const std::string & getClientProtocolString() = 0;

        const std::vector<byte> & getExchangeHash() const       {return m_exchangeHash;}
        const std::vector<byte> & getSessionIdentifier() const  {return m_sessionIdent;}
        
    protected:
        void notify(uint32 mask, void * param = NULL);  /* perform the required notifications */
        void disconnect(uint32_t, const char * str = NULL);

        virtual int establishConnection()   = 0;

        /* exchanges the protocol versions */
        int     exchangeProtocolVersions();
        bool    parseProtocolVersion(const std::string &, ProtocolVersion *) const;
        int     exchangeKeyExchanges(const KeyExchangeInfo &, KeyExchangeInfo &, bool bInitial = true, bool bInitiator = true);
        bool    buildLocalKex();
        bool    buildLocalVersionString();
        int     parseRemoteKex(KeyExchangeInfo &);
        bool    isTransportPacket();

        bool DecideAlgorithms(const std::string client[],const std::string server[],std::string match[],int count) const;
        bool DecideAlgorithm(const std::string &, const std::string &, std::string &) const;

        /* Key derivation process */
        int     DeriveKeys(const ByteVector &, const ByteVector &, const CBigInt &, const char *, KeyVector &) const;
        int     DeriveKey(const ByteVector &, const ByteVector &, const CBigInt &, const char *, char, KeyElement &, unsigned int) const;
        
        int     TakeKeysIntoUse(const KeyVector & vec, const std::string matches[MAX_ALGORITHM_COUNT]);
        int     createAlgorithmInstances( const std::string names[MAX_ALGORITHM_COUNT], SecurityBlock & block );

        virtual void    InitializeKeys(const SecurityBlock & block, const KeyVector & vec) = 0;
        virtual int     TakeAlgorithmsInUse( const SecurityBlock & block ) = 0;

        virtual int handlePacket()  = 0;    /* handles the packet in the input buffer */
        bool getPacketType(byte &);


        /* Send/Read functions */

        int flushPacket(uint32_t);
        int sendPacketNonblock(int timeout = 0);
        int readPacketNonblock(int timeout = 0);

        void sendEncryptData();
        void sendCalcDigest(const byte * src, uint32_t len, uint32_t seq, byte * dst);
        void initSendState(uint32_t & seq);
        void randomizeData(uint8_t *, size_t);

        /*
         * Variables
         */
    
        CNetwork * ds;      /* down-stream component */

        /* the current read and write positions */
        int               m_writePos, m_readPos;

        TransferState   readState,  /* the read state */
                        sendState;  /* the send state */

        KeyExchangeInfo m_localKex,     /* local keyexchange information */
                        m_remoteKex;    /* remote keyexchange information */

        /* protocol version strings */
        std::string m_localVersion,
                    m_remoteVersion;

        std::vector<byte> m_sessionIdent;   /* the session identifier */
        std::vector<byte> m_exchangeHash;   /* the last exchange hash */

        const CSettings & m_settings;

        Util::Mutex m_notifyLock;
    };
};

#endif