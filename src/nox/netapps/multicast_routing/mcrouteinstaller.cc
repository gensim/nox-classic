#include "mcrouteinstaller.hh"
#include "openflow-default.hh"
#include "vlog.hh"
#include "assert.hh"
#include <boost/bind.hpp>

#include "group_manager/group-event.hh"
#include "flow-removed.hh"
#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"

using namespace std;

namespace vigil 
{
  using namespace vigil::container;
  static Vlog_module lg("mcrouteinstaller");
  
  void mcrouteinstaller::configure(const Configuration* c) 
  {
  }
  
  void mcrouteinstaller::install() 
  {
    resolve(mcrouting);
    
    register_handler<Group_event>
        (boost::bind(&mcrouteinstaller::handle_group_event, this, _1));
    register_handler<Packet_in_event>
        (boost::bind(&mcrouteinstaller::handle_pkt_in, this, _1));
    register_handler<Flow_removed_event>
        (boost::bind(&mcrouteinstaller::handle_flow_removed, this, _1));        
  }
  
  void mcrouteinstaller::getInstance(const container::Context* ctxt, 
                   vigil::mcrouteinstaller*& scpa)
  {
    scpa = dynamic_cast<mcrouteinstaller*>
      (ctxt->get_by_interface(container::Interface_description
                  (typeid(mcrouteinstaller).name())));
  }
  
  Disposition mcrouteinstaller::handle_pkt_in(const Event& e)
  {
    const Packet_in_event& pie = assert_cast<const Packet_in_event&>(e);

    // Handle only multicast flow
    ipaddr src = (uint32_t)ntohl(pie.flow.nw_src);
    ipaddr group = (uint32_t)ntohl(pie.flow.nw_dst);
                  
    if (pie.flow.dl_type != ethernet::IP || 
        pie.flow.nw_proto != ip_::proto::UDP ||
        src == (uint32_t)0 || group == (uint32_t)0 ||
        src.isMulticast() || !group.isMulticast())
      return CONTINUE;
    
    if(gir_map.find(group) != gir_map.end() &&
       gir_map[group].find(src) != gir_map[group].end() &&
       gir_map[group][src].dpsrc == pie.datapath_id) {
        return CONTINUE;
    }

    install_route(src, group, -1); //ntohl(pie.buffer_id)

    return CONTINUE;
  }  
  
  Disposition mcrouteinstaller::handle_group_event(const Event& e)
  {
    const Group_event& ge = assert_cast<const Group_event&>(e);
    
    ipaddr src = ge.src;
    ipaddr group = ge.group;
    
    if( gir_map.find(group) == gir_map.end() ||
       (src == (uint32_t)0 && (ge.action == Group_event::ADD || ge.action == Group_event::REMOVE)) ||
       (src != (uint32_t)0 && (ge.action == Group_event::TOEXCLUDE || ge.action == Group_event::TOINCLUDE)) ||
       (src != (uint32_t)0 && gir_map[group].find(src) == gir_map[group].end()) )
        return CONTINUE;  
    
    if(gir_map.find(group) == gir_map.end() ||
       (src != (uint32_t)0 && gir_map[group].find(src) == gir_map[group].end())) {
        VLOG_WARN(lg, "Unkwon flow removed message src=%s group=%s",
                  src.string().c_str(), group.string().c_str());
        return CONTINUE;
    }   
    
    if(src == (uint32_t)0) {        
        for(SrcInstalledRuleMap::iterator it = gir_map[group].begin();
            it != gir_map[group].end(); it++) {
            if(mcrouting->has_multicast_route(group, it->first)
                || mcrouting->get_multicast_dst_size(group) != 0) {
                install_route(it->first, group);
            } else {
                //remove flows
            }
        }
    } else {
        if(mcrouting->has_multicast_route(group, src)
            || mcrouting->get_multicast_dst_size(group) != 0) {
            install_route(src, group);
        } else {
            //remove flows
        }        
    }   
    
    return CONTINUE;  
  }
  
  Disposition mcrouteinstaller::handle_flow_removed(const Event& e)
  {
    const Flow_removed_event& fre = assert_cast<const Flow_removed_event&>(e);
    
    const ofp_match* ofpm = fre.get_flow();    
    ipaddr src = (uint32_t)ntohl(ofpm->nw_src);
    ipaddr group = (uint32_t)ntohl(ofpm->nw_dst);
    
    if(ofpm->dl_type != ethernet::IP || 
       ofpm->nw_proto!=ip_::proto::UDP ||
       src == (uint32_t)0 || group == (uint32_t)0 ||
       src.isMulticast() || !group.isMulticast())
        return CONTINUE;
        
    if(gir_map.find(group) == gir_map.end() ||
       gir_map[group].find(src) == gir_map[group].end()) {
        VLOG_WARN(lg, "Unkwon flow removed message src=%s group=%s",
                  src.string().c_str(), group.string().c_str());
        return CONTINUE;
    }
    
    if(gir_map[group][src].dpsrc == fre.datapath_id &&
        gir_map[group][src].cookie == fre.cookie) {
        gir_map[group].erase(src);
        if(gir_map[group].size() == 0) {
            gir_map.erase(group);
            VLOG_DBG(lg, "Remove installed flow src=%s group=%s cookie=%"PRIx64"",
                  src.string().c_str(), group.string().c_str(), fre.cookie);
        }
    } else {
        VLOG_WARN(lg, "Flow removed message src = %s group = %s is invalid",
                  src.string().c_str(), group.string().c_str());
    }
    
    return CONTINUE;    
  }
  
  bool mcrouteinstaller::get_multicast_tree_path(const ipaddr& src,
                                                 const ipaddr& group, 
                                                 network::route& route)
  {      
    MC_routing_module::AdjListPtr tree;
    MC_routing_module::DstPortMapPtr dsts;
    network::hop* newhop = NULL;
    route.next_hops.clear();
    
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
  
  void mcrouteinstaller::install_route(const ipaddr& src, 
                                       const ipaddr& group,
                                       uint32_t buffer_id,
                                       uint16_t idletime,
                                       uint16_t hardtime)
  {
    network::route rte(datapathid(), OFPP_NONE);

    if(!mcrouting->get_source_location(src, rte)) return;

    if (get_multicast_tree_path(src, group, rte))
    {
      hash_map<datapathid,ofp_action_list> act;
      if(gir_map.find(group) == gir_map.end()) 
        gir_map[group] = SrcInstalledRuleMap();

      if(gir_map[group].find(src) == gir_map[group].end()) {
        gir_map[group][src] = (InstalledRule){rte.in_switch_port.dpid,0};
      } else {
        if(gir_map[group][src].dpsrc != rte.in_switch_port.dpid) 
            gir_map[group][src].cookie = 0;
        else
            gir_map[group][src].cookie++;
      }
      VLOG_DBG(lg, "Install route src=%s group=%s cookie=%"PRIx64"",
               src.string().c_str(), group.string().c_str(), gir_map[group][src].cookie);
      real_install_route(src, group, rte, buffer_id, act, true, idletime, hardtime);
    }   
  }
  
  void mcrouteinstaller::real_install_route(const ipaddr& src, 
                                            const ipaddr& group,
                                            network::route route,
                                            uint32_t buffer_id,
                                            hash_map<datapathid,ofp_action_list>& actions,
                                            bool removedmsg,
                                            uint16_t idletime,
                                            uint16_t hardtime)
  {
    if (route.in_switch_port.dpid.empty())
      return;
    
    //Recursively install 
    network::nextHops::iterator i = route.next_hops.begin();
    while (i != route.next_hops.end())
    {
      if (!(i->second->in_switch_port.dpid.empty()))
    real_install_route(src, group, *(i->second), -1, actions, false, idletime, hardtime);
      i++;
    }

    //Check for auxiliary actions
    hash_map<datapathid,ofp_action_list>::iterator j = \
      actions.find(route.in_switch_port.dpid);
    ofp_action_list oalobj;
    ofp_action_list* oal;
    if (j == actions.end())
      oal = &oalobj;
    else
      oal = &(j->second);

    
    i = route.next_hops.begin();
    while (i != route.next_hops.end())
    {
        ofp_action* ofpa = new ofp_action();
        ofpa->set_action_output(i->first, 0);
        oal->action_list.push_back(*ofpa);
        i++;
    }

    //Install flow entry
    install_flow_entry(route.in_switch_port.dpid, src, group, buffer_id, 
               route.in_switch_port.port, *oal, gir_map[group][src].cookie,
               removedmsg, idletime, hardtime);
  } 
  
  void mcrouteinstaller::install_flow_entry(const datapathid& dpid,
                                            const ipaddr& src, 
                                            const ipaddr& group,
                                            uint32_t buffer_id, 
                                            uint16_t in_port,
                                            ofp_action_list act_list,
                                            uint64_t cookie,
                                            bool removedmsg,
                                            uint16_t idletime, 
                                            uint16_t hardtime)
  {
    ssize_t size = sizeof(ofp_flow_mod)+act_list.mem_size();
    of_raw.reset(new uint8_t[size]);
    of_flow_mod ofm;
    ofm.header = openflow_pack::header(OFPT_FLOW_MOD, size);
    ofm.match.in_port = in_port;
    ofm.match.dl_type = ntohs(ethernet::IP);
    ofm.match.nw_src = ntohl((uint32_t)src);
    ofm.match.nw_dst = ntohl((uint32_t)group);
    ofm.match.nw_proto = ip_::proto::UDP;
    ofm.match.wildcards = OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_TYPE &
                          ~OFPFW_NW_SRC_MASK & ~OFPFW_NW_DST_MASK & ~OFPFW_NW_PROTO;
    ofm.cookie = cookie;
    ofm.command = (cookie==0)?OFPFC_ADD:OFPFC_MODIFY;
    ofm.flags = (removedmsg)?OFPFF_SEND_FLOW_REM:0;
    ofm.idle_timeout = idletime;
    ofm.hard_timeout = hardtime;
    ofm.buffer_id = buffer_id;
    ofm.out_port = OFPP_NONE;
    ofm.pack((ofp_flow_mod*) openflow_pack::get_pointer(of_raw));
    act_list.pack(openflow_pack::get_pointer(of_raw,sizeof(ofp_flow_mod)));
    VLOG_DBG(lg,"Install flow entry src=%s group=%s with %zu actions", 
         src.string().c_str(), group.string().c_str(), act_list.action_list.size());
    send_openflow_command(dpid, of_raw, false);
  }

  REGISTER_COMPONENT(container::Simple_component_factory<mcrouteinstaller>, 
		     mcrouteinstaller);
} // unnamed namespace
