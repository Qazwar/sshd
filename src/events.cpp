/* events.cpp
 * 
 * Implements the functions for handling event notification.
 * Copyright © 2009 Magnus Leksell, all rights reserved.
 */
#include "CTransport.h"
#include "sshd.h"

namespace ssh
{
    /* CTransport::registerEventNotify
     * Registers a event notification function.
     */
    int CTransport::registerEventNotify(EventNotification notify, uint32 mask)
    {
        int res = ERR_FAILED;

        m_notifyLock.acquire();
        for(int i = 0; i < MAX_EVENT_NOTIFY; i++) {
            if( !notifications[i].notify ) {
                notifications[i].notify = notify;
                notifications[i].mask   = mask;
                res = OK;
                break;
            }
        }
        m_notifyLock.release();
        return res;
    }

    /* CTransport::unregisterEventNotify
     * Unregisters a event notification.
     */
    void CTransport::unregisterEventNotify(EventNotification notify)
    {
        m_notifyLock.acquire();
        for(int i = 0; i < MAX_EVENT_NOTIFY; i++) {
            if( notifications[i].notify == notify ) {
                notifications[i].notify = 0;
            }
        }
        m_notifyLock.release();
    }

    /* CTransport::notify
     * Notifies the clients interested in the event.
     */
    void CTransport::notify(uint32 mask, void * param)
    {
        m_notifyLock.acquire();
        for(int i = 0; i < MAX_EVENT_NOTIFY; i++) {
            if( notifications[i].notify && (mask & notifications[i].mask) ) {
                /* notify the interested client */
                notifications[i].notify(mask, this, param);
            }
        }
        m_notifyLock.release();
    }
};