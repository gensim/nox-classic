#include "component.hh"
#include "group-event.hh"

#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::container;

namespace vigil {
    Group_event::Group_event(ipaddr group_, datapathid dp_, uint16_t port_, Action action_)
        : Event(static_get_name()), group(group_), dp(dp_), port(port_), action(action_) { src = ipaddr(0); }
    Group_event::Group_event(ipaddr group_, datapathid dp_, uint16_t port_, ipaddr src_, Action action_)
        : Event(static_get_name()), group(group_), dp(dp_), port(port_), src(src_),action(action_) { }
    
    // -- only for use within python
    Group_event::Group_event() : Event(static_get_name()) { }

} // namespace vigil
