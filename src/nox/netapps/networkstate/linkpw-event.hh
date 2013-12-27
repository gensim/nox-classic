#ifndef LINKPW_EVENT_HH
#define LINKPW_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <stdint.h>

#include "discovery/link-event.hh"
#include "linkweight.hh"

namespace vigil {

/** \ingroup noxevents
 *
 * Thrown for each link status change detected on the network.
 * Currently is only thrown by the linkphaseweight component. 
 *
 */

struct Linkpw_event
    : public Link_event
{
    enum Action {
        CHANGE = 2
    };
    
    Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, linkweight old_weight_);
               
    Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, linkweight old_weight_, linkweight new_weight_);
        
    // -- only for use within python
    Linkpw_event();

    static const Event_name static_get_name() {
        return "Linkpw_event";
    }
    
    linkweight old_weight;
    linkweight new_weight;
};

}

#endif