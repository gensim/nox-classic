#ifndef LINKPW_EVENT_HH
#define LINKPW_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <stdint.h>

#include "event.hh"
#include "linkweight.hh"
#include "netinet++/datapathid.hh"

namespace vigil {

/** \ingroup noxevents
 *
 * Thrown for each link status change detected on the network.
 * Currently is only thrown by the linkphaseweight component. 
 *
 */

struct Linkpw_event
    : public Event,
      boost::noncopyable
{
    enum Action {
        ADD,
        REMOVE,
        CHANGE
    };
    
    Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, Linkweight weight_);
               
    Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, Linkweight old_weight_, Linkweight new_weight_);
        
    // -- only for use within python
    Linkpw_event();

    static const Event_name static_get_name() {
        return "Linkpw_event";
    }
    
    datapathid dpsrc;
    datapathid dpdst;
    uint16_t sport;
    uint16_t dport;
    Action action;
    Linkweight old_weight;
    Linkweight new_weight;
};

}

#endif