#ifndef GROUP_EVENT_HH
#define GROUP_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <stdint.h>

#include "event.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ipaddr.hh"

namespace vigil {

/** \ingroup noxevents
 *
 * Thrown for each group status change detected on the network.
 * Currently is only thrown by the group_manager component. 
 *
 */

struct Group_event
    : public Event,
      boost::noncopyable
{
    enum Action {
        ADD,
        REMOVE
    };

    Group_event(ipaddr group_, datapathid dp_, uint16_t port_, Action action_);
    Group_event(ipaddr group_, datapathid dp_, uint16_t port_, ipaddr src_, Action action_);
    
    // -- only for use within python
    Group_event();

    static const Event_name static_get_name() {
        return "Group_event";
    }
    
    ipaddr group;
    datapathid dp;
    uint16_t port;
    ipaddr src;
    Action action;
};

} // namespace vigil

#endif /* group-event.hh */
