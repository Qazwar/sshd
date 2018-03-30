#ifndef _INOTIFY_H_
#define _INOTIFY_H_

namespace ssh
{
    class CClientTransport;
    /* INotify
     *
     */
    class INotify
    {
    public:
        virtual void OnConnectSuccess( CClientTransport *) = 0;
        virtual void OnConnectFailure( CClientTransport *) = 0;
        virtual void OnCloseEvent(CClientTransport *)       = 0;
    };
}

#endif