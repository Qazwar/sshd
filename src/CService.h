/* CService.h
 * Declaration of the CService class.
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */
#ifndef _CSERVICE_H_
#define _CSERVICE_H_

#include "types.h"
#include "CSettings.h"
#include "CTransport.h"

#include <string>

enum
{
    SERVICE_OK = 0,
    SERVICE_PROTOCOL_ERROR
};

namespace ssh
{
    /* CService
     * Baseclass for the different services.
     */
    class CService
    {
    public:
        /* initializes the service based on the current settings */
        virtual bool init(const CSettings &)                            = 0;
        /* called if the service is accepted */
        virtual void OnAccept() {}
        /* reads data from the service */
        virtual int read(uint8_t * dst, uint32_t size, uint32_t * len)  = 0;
        /* returns true if the service has anything to send */
        virtual bool isDataAvailable(int)                               = 0;
        /* handles a packet */
        virtual int handle(const byte *, uint32_t)                      = 0;
        /* returns the name of the service */
        virtual std::string GetServiceName()                            = 0;

    protected:
        ssh::CTransport * m_pTransport;     /* the associated transport layer */
    };
};

#endif