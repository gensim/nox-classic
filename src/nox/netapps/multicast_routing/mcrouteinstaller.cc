#include "mcrouteinstaller.hh"
#include "openflow-default.hh"
#include "vlog.hh"
#include "assert.hh"
#include <boost/bind.hpp>

using namespace std;

namespace vigil 
{
  using namespace vigil::container;
  static Vlog_module lg("mcrouteinstaller");
  
  void mcrouteinstaller::configure(const Configuration*) 
  {
  }
  
  void mcrouteinstaller::install() 
  {
    resolve(ri);
    resolve(mcrouting);
  }

  bool mcrouteinstaller::get_multicast_tree_path(const ipaddr& src,
                                                 const ipaddr& group, 
                                                 network::route& route)
  {      
    MC_routing_module::AdjListPtr tree;
    MC_routing_module::DstPortMapPtr dsts;
    network::hop* newhop = NULL;
    route.next_hops.clear();
    if(!mcrouting->get_source_location(src, route)) return false;
    
    if(mcrouting->get_multicast_tree(src, group, tree, dsts)) {
        NodeQueue q;
        q.push((Node){datapathid(), route.in_switch_port.dpid, &route});
        while(q.size()!=0) {
            Node u = q.front();
            q.pop();
            for(MC_routing_module::AdjListNode::iterator it = (*tree)[u.id].begin();
                    it != (*tree)[u.id].end(); it++) {
                if(it->first == u.parent) continue;
                newhop = new network::hop(it->first, it->second.dstport);
                u.nhop->next_hops.push_front(std::make_pair(it->second.srcport, newhop));
                q.push((Node){u.id, it->first, newhop});                              
            }
            if(dsts->find(u.id) != dsts->end()) {
                for(MC_routing_module::PortSet::iterator it = (*dsts)[u.id].begin();
                    it != (*dsts)[u.id].end(); it++) {
                    newhop = new network::hop(datapathid(), 0);
                    u.nhop->next_hops.push_front(std::make_pair(*it, newhop));
                }
            }
        }
        return true;
    }
    return false;
  }

  void mcrouteinstaller::install_route(const Flow& flow, network::route route, 
				     uint32_t buffer_id, uint32_t wildcards,
				     uint16_t idletime, uint16_t hardtime)
  {
    ri->install_route(flow, route, buffer_id, wildcards, idletime, hardtime); 
  }

  void mcrouteinstaller::install_route(const Flow& flow, network::route route, 
				     uint32_t buffer_id,
				     hash_map<datapathid,ofp_action_list>& actions,
				     list<datapathid>& skipoutput,
				     uint32_t wildcards,
				     uint16_t idletime, uint16_t hardtime)
  {
    ri->install_route(flow, route, buffer_id, actions, skipoutput, wildcards, 
		       idletime, hardtime);  
  }
  
  void mcrouteinstaller::install_flow_entry(const datapathid& dpid,
					  const Flow& flow, uint32_t buffer_id, uint16_t in_port,
					  ofp_action_list act_list, uint32_t wildcards_,
					  uint16_t idletime, uint16_t hardtime, uint64_t cookie)
  {
    ri->install_flow_entry(dpid, flow, buffer_id, in_port, act_list, wildcards_, idletime, hardtime,cookie);
  }

  void mcrouteinstaller::getInstance(const container::Context* ctxt, 
				   vigil::mcrouteinstaller*& scpa)
  {
    scpa = dynamic_cast<mcrouteinstaller*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(mcrouteinstaller).name())));
  }
  

  REGISTER_COMPONENT(container::Simple_component_factory<mcrouteinstaller>, 
		     mcrouteinstaller);
} // unnamed namespace
