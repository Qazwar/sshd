/* dmx.h
 * Demux implementation.
 * 
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */

#ifndef _DMX_H_
#define _DMX_H_

#include <list>
#include "types.h"
#include "MessageHandler.h"

#define DMX_MAX_SECTION_SIZE        8

/*****************************************************************************/
/*                          ERROR CODES                                      */
/*****************************************************************************/

enum {
    DMX_OK = 0,
    DMX_ERROR_NULL_PARAMETER
};

namespace ssh
{
    class CTransport;

    /* FilerEntry
     * Stores the internal representation of a filter.
     */
    struct FilterEntry
    {
        typedef enum {SectionFilter, MessageFilter, MessageRangeFilter} FilerType;
        union {
            struct {
                byte sectionSize;
                byte filter;
                byte sectionData[DMX_MAX_SECTION_SIZE];
            } section;

            struct {
                byte type;  /* message type to filter on */ 
            } message;

            struct {
                byte low, high; /* range to filter */
            } range;
        } u;

        MessageHandler * m_pFilter; /* filter function */
        FilerType m_iType;
    };

    /* Demux
     * Demultiplexer
     */
    class Demux
    {
    public:
        /* allocates a filter for a message */
        int AllocateMessageFilter(MessageHandler *, byte);
        /* allocates a filter for a range */
        int AllocateRangeFilter(MessageHandler *, byte, byte);
        /* allocates a section filter */
        int AllocateSectionFilter(MessageHandler *, byte *, int, uint32);
        /* Frees a filter */
        int FreeFilter(int);

        friend class CTransport;    /* the transport layer needs to be a friend */
    private:
        /* handles a message */
        int HandleMessage(byte, const byte *, int);
        /* Dispatches a message */
        int DispatchMessage(byte, const byte *, int);

        /* the installed filters */
        std::list<FilterEntry> m_vFilters;
    };
};

#endif