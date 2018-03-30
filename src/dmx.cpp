/* dmx.cpp
 * Implements the demux functionality
 *
 * Copyright © 2009 Magnus Leksell, all rights reserved
 */

#include "dmx.h"
#include "CTransport.h"
#include "sshd.h"

/*****************************************************************************/
/*                      LOCAL DEFINITIONS                                    */
/*****************************************************************************/
#define DMX_LOCK()      /*this->m_lock.lock();*/
#define DMX_UNLOCK()    /*this->m_lock.unlock();*/

using namespace std;

namespace ssh
{
    /* Demux::AllocateMessageFilter
     * Allocates a message filter
     */
    int Demux::AllocateMessageFilter(MessageHandler * pFilter, byte msgId)
    {
        FilterEntry entry;
        if( !pFilter ) {
            return DMX_ERROR_NULL_PARAMETER;
        }

        DMX_LOCK()
        /* add the new filter entry */
        entry.m_iType           = FilterEntry::MessageFilter;
        entry.u.message.type    = msgId;
        entry.m_pFilter         = pFilter;
        m_vFilters.push_back(entry);
        DMX_UNLOCK();

        return DMX_OK;
    }

    /* Demux::AllocateRangeFilter
     * Allocate a filter which will filter on a range.
     */
    int Demux::AllocateRangeFilter(MessageHandler * pFilter,
        byte low,
        byte high)
    {
        FilterEntry entry;

        if( !pFilter ) 
            return DMX_ERROR_NULL_PARAMETER;
        
        DMX_LOCK()  
        entry.m_iType       = FilterEntry::MessageRangeFilter;
        entry.u.range.high  = high;
        entry.u.range.high  = low;
        entry.m_pFilter     = pFilter;
        m_vFilters.push_back(entry);
        DMX_UNLOCK();

        return DMX_OK;
    }

    /* Demux::HandleMessage
     * Dispatches a message to the receiver.
     */
    int Demux::HandleMessage(byte id, const byte * src, int len)
    {
        /* iterate the filters to find the recipient of the message */
        for(list<FilterEntry>::iterator it = m_vFilters.begin();
            it != m_vFilters.end();
            it++) 
        {
            const ssh::FilterEntry & entry = *it;
            switch( entry.m_iType ) 
            {
            case FilterEntry::MessageFilter:
                if( entry.u.message.type == id ) {
                    return entry.m_pFilter->process(id, src, len);
                }
                break;
            case FilterEntry::MessageRangeFilter:
                if( id >= entry.u.range.low && id <= entry.u.range.high ) {
                    return entry.m_pFilter->process(id, src, len);
                }
                break;
            case FilterEntry::SectionFilter: /* section filter */
                if( len >= entry.u.section.sectionSize ) {
                    bool match = false;
                    for(int i = 0; i < entry.u.section.sectionSize; i++) {
                        if( entry.u.section.filter & (0x80>>i) ) {
                            if( entry.u.section.sectionData[i] != src[i] ) {
                                match = false;
                                break;
                            }
                        }
                    }
                    if( match ) 
                        return entry.m_pFilter->process(id, src, len);
                    else
                        break;
                }
                break;
            }
        }
        return ERR_FAILED;  /* not match found */
    }
};