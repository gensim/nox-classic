#include "linkpw-event.hh"

#include "component.hh"
#include "assert.hh"
#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::container;

namespace vigil {
    Linkpw_event::Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, Linkweight weight_)
        : Event(static_get_name()), dpsrc(dpsrc_), dpdst(dpdst_),
          sport(sport_), dport(dport_), action(action_)
        { 
            assert(action_ == ADD || action_ == REMOVE);
            if(action_ == ADD) 
            {
                new_weight = weight_;
                old_weight = Linkweight();
            } 
            else if(action_ == REMOVE)
            {
                new_weight = Linkweight();
                old_weight = weight_;
            }
        }   
    
    Linkpw_event::Linkpw_event(datapathid dpsrc_, datapathid dpdst_,
               uint16_t sport_, uint16_t dport_,
               Action action_, Linkweight old_weight_, Linkweight new_weight_)
        : Event(static_get_name()), dpsrc(dpsrc_), dpdst(dpdst_),
          sport(sport_), dport(dport_), action(action_), 
          old_weight(old_weight_), new_weight(new_weight_)
        { assert(action_ == CHANGE); }              
    
    // -- only for use within python
    Linkpw_event::Linkpw_event() : Event(static_get_name()) { }

} // namespace vigil

namespace {

static Vlog_module lg("linkpw-event");

class LinkpwEvent_component
    : public Component {
public:
    LinkpwEvent_component(const Context* c,
                     const json_object*) 
        : Component(c) {
    }

    void configure(const Configuration*) {
    }

    void install() {
    }

private:
    
};

REGISTER_COMPONENT(container::Simple_component_factory<LinkpwEvent_component>, 
                   LinkpwEvent_component);

} // unnamed namespace