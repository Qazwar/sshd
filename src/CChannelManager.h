#ifndef _CCHANNELMANAGER_H_
#define _CCHANNELMANAGER_H_

/* project specific includes */
#include "CChannel.h"
#include "MessageHandler.h"
#include "dmx.h"

namespace ssh
{
    /* CChannelManager
     * Handles the different channels.
     */
    class CChannelManager : public MessageHandler
    {
    public:
        CChannelManager(Demux &);
        ~CChannelManager();

        int process(byte, const byte *, int);

    protected:
        Demux & m_dmx;      /* the demux */
    };
};

#endif