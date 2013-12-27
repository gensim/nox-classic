#include "linkpw-event.hh"

#inlcude <assert>

namespace vigil {
    Linkpw_event::Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, linkweight weight_, )
        : Link_event(dpsrc_, dpdst_, sport, dport, action_)
        { 
            assert(action_ == ADD || action_ == REMOVE);
            if(action_ == ADD) 
            {
                new_weight = weight;
                old_weight = linkweight();
            } 
            else if(action_ == REMOVE)
            {
                new_weight = linkweight();
                old_weight = weight;
            }
        }   
    
    Linkpw_event::Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, linkweight old_weight_, linkweight new_weight_)
        : Link_event(dpsrc_, dpdst_, sport, dport, action_), 
          old_weight(old_weight_), new_weight(new_weight_)
        { assert(action_ == CHANGE); }              
    
    // -- only for use within python
    Linkpw_event::Linkpw_event() : Link_event() { }

} // namespace vigil