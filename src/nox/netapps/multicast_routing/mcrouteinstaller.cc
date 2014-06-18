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
    
    ipaddr src = htonl(pie.flow.nw_src);
    ipaddr group = htonl(pie.flow.nw_dst);
    
    // Handle only multicast flow              
    if (pie.flow.dl_type != ethernet::IP || 
        pie.flow.nw_proto != ip_::proto::UDP ||
        src == (uint32_t)0 || group == (uint32_t)0 ||
        src.isMulticast() || !group.isMulticast())
      return CONTINUE;
    
    if(grr_map.find(group) != grr_map.end() &&
       grr_map[group].find(src) != grr_map[group].end()) { 
        if(grr_map[group][src].act.find(pie.datapath_id) != grr_map[group][src].act.end()) { 
            if(pie.buffer_id!=-1)
                forward_routed_flow(pie.datapath_id, src, group, pie.in_port,
                                    grr_map[group][src].act[pie.datapath_id], pie.buffer_id);
            else
                forward_routed_flow(pie.datapath_id, src, group, pie.in_port,
                                    grr_map[group][src].act[pie.datapath_id], *pie.get_buffer());
        } else {
            VLOG_ERR(lg, "Routed flow src=%s group=%s, but no dpid=%"PRIx64"",
                  src.string().c_str(), group.string().c_str(), pie.datapath_id.as_host());
        }
        return CONTINUE;
    }
    
    if(mcrouting->has_multicast_route(group, src) ||
       mcrouting->get_multicast_dst_size(group) != 0) {
        remove_block(src, group);
        reset_route(src, group, pie.buffer_id);
    } else {
        if(gbr_map.find(group) != gbr_map.end() &&
            gbr_map[group].find(src) != gbr_map[group].end()) 
            return CONTINUE;
        install_block(src, group, pie.datapath_id, pie.in_port);
    }

    return CONTINUE;
  }  
  
  Disposition mcrouteinstaller::handle_group_event(const Event& e)
  {
    const Group_event& ge = assert_cast<const Group_event&>(e);

    ipaddr src = ge.src;
    ipaddr group = ge.group;
    
    if( (((src == (uint32_t)0) && (ge.action == Group_event::ADD || ge.action == Group_event::REMOVE))) ||
       ((src != (uint32_t)0) && (ge.action == Group_event::TOEXCLUDE || ge.action == Group_event::TOINCLUDE))){
        VLOG_DBG(lg, "No action of group event, src=%s group=%s ge.action=%d",
                  src.string().c_str(), group.string().c_str(), ge.action);
        return CONTINUE;
    }
    if(gbr_map.find(group) == gbr_map.end() && grr_map.find(group) == grr_map.end()) {
        VLOG_DBG(lg, "No table has this group, src=%s group=%s",
                  src.string().c_str(), group.string().c_str());
        return CONTINUE;
    }
    
    hash_map<ipaddr,bool> route_reset;
    hash_set<ipaddr> route_remove;
    
    if(gbr_map.find(group) != gbr_map.end()) {
        if(src == (uint32_t)0) {
            for(SrcBlockedRuleMap::iterator it = gbr_map[group].begin();
                it != gbr_map[group].end(); it++) {
                if(mcrouting->has_multicast_route(group, it->first) || 
                    mcrouting->get_multicast_dst_size(group) != 0) { 
                    route_reset[it->first] = false;
                }
            }
        } else {
            if(gbr_map[group].find(src) != gbr_map[group].end()) {
                if(mcrouting->has_multicast_route(group, src) ||
                    mcrouting->get_multicast_dst_size(group) != 0) {
                    route_reset[src] = false;
                } 
            }
        }
    }
    
    if( grr_map.find(group) != grr_map.end() ) {
        if(src == (uint32_t)0) {
            for(SrcRoutedRuleMap::iterator it = grr_map[group].begin();
                it != grr_map[group].end(); it++) {
                if(mcrouting->has_multicast_route(group, it->first) || 
                    mcrouting->get_multicast_dst_size(group) != 0) {                
                    route_reset[it->first] = true;
                } else {
                    route_remove.insert(it->first);
                }
            }   
        } else {
            if(grr_map[group].find(src) != grr_map[group].end()) {
                if(mcrouting->has_multicast_route(group, src) ||
                    mcrouting->get_multicast_dst_size(group) != 0) {
                    route_reset[src] = true;
                } else {
                    route_remove.insert(src);
                }
            }
        }
    }
    
    for(hash_map<ipaddr,bool>::iterator it = route_reset.begin();
        it != route_reset.end(); it++) {
        if(!it->second) remove_block(it->first, group);
        reset_route(it->first, group);
    }
    for(hash_set<ipaddr>::iterator it = route_remove.begin();
        it != route_remove.end(); it++) {
        remove_route(*it, group);
    }
    
    return CONTINUE;  
  }
  
  Disposition mcrouteinstaller::handle_flow_removed(const Event& e)
  {
    const Flow_removed_event& fre = assert_cast<const Flow_removed_event&>(e);
    
    const ofp_match* ofpm = fre.get_flow();    
    ipaddr src = htonl(ofpm->nw_src);
    ipaddr group = htonl(ofpm->nw_dst);
    
    if(ofpm->dl_type != ethernet::IP || 
       ofpm->nw_proto!=ip_::proto::UDP ||
       src == (uint32_t)0 || group == (uint32_t)0 ||
       src.isMulticast() || !group.isMulticast())
        return CONTINUE;
    
    datapathid dpid = fre.datapath_id;
    uint64_t cookie = fre.cookie;
    VLOG_DBG(lg, "handle flow removed event src=%s group=%s dpid=%"PRIx64" cookie=%llu",
                  src.string().c_str(), group.string().c_str(), dpid.as_host(), cookie);
    if(fre.cookie == 0)
    {
        delete_blocked_table_entry(src, group, dpid);
    }
    else
    {       
        delete_routed_table_entry(src, group, dpid, cookie);
    }
    
    
    return CONTINUE;    
  }
  
  void mcrouteinstaller::reset_route(const ipaddr& src, 
                                        const ipaddr& group,
                                        uint32_t buffer_id)
  {
    VLOG_DBG(lg, "reset route src=%s group=%s", src.string().c_str(), group.string().c_str());
    network::route rte(datapathid(), OFPP_NONE);   
    hash_map<datapathid,ofp_action_list> act_list;    
    if(!mcrouting->get_multicast_tree_path(src, group, rte, &act_list)) return;
    
    install_route(src, group, rte, act_list, buffer_id); 
  }
  
  void mcrouteinstaller::install_route(const ipaddr src, 
                                       const ipaddr group,
                                       network::route& rte,
                                       hash_map<datapathid,ofp_action_list>& act_list,
                                       uint32_t buffer_id,
                                       uint16_t idletime,
                                       uint16_t hardtime)
  {
    if(add_routing_table_entry(src, group, rte, act_list))
      real_install_route(src, group, rte, buffer_id, act_list, true, idletime, hardtime);   
  }
  
  void mcrouteinstaller::remove_route(const ipaddr src, 
                                      const ipaddr group)
  {
    datapathid dpid;
    uint64_t cookie;
    if(delete_routed_table_entry(src, group, dpid, cookie)) {
      remove_routing_flow_entry(dpid, src, group);
    }
  }
  
  void mcrouteinstaller::install_block(const ipaddr src, 
                                       const ipaddr group,
                                       const datapathid& dpid,
                                       uint16_t in_port,
                                       uint16_t idletime, 
                                       uint16_t hardtime)
  {
    
    if(add_blocking_table_entry(src, group, dpid))
      install_blocking_flow_entry(dpid, src, group, in_port, idletime, hardtime);         
  }
  
  void mcrouteinstaller::remove_block(const ipaddr src, 
                                      const ipaddr group)
  {
    datapathid dpid;
    if(delete_blocked_table_entry(src, group, dpid)){
        VLOG_DBG(lg, "before remove_routing_flow_entry src=%s group=%s", src.string().c_str(), group.string().c_str());
      remove_blocking_flow_entry(dpid, src, group);
    }
  }
  
  void mcrouteinstaller::real_install_route(const ipaddr src, 
                                            const ipaddr group,
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
        
    install_routing_flow_entry(route.in_switch_port.dpid, src, group,
               route.in_switch_port.port, *oal, buffer_id,
               grr_map[group][src].cookie, removedmsg, idletime, hardtime);
  }
  
  bool mcrouteinstaller::add_routing_table_entry(const ipaddr src, const ipaddr group, 
                                                 network::route route, hash_map<datapathid,ofp_action_list>& act_list)
  {    
    if(grr_map.find(group) == grr_map.end()) 
        grr_map[group] = SrcRoutedRuleMap();

    VLOG_DBG(lg,"Add routing flow src=%s group=%s of dpid=%"PRIx64"", 
          src.string().c_str(), group.string().c_str(), route.in_switch_port.dpid.as_host() );
    if(grr_map[group].find(src) == grr_map[group].end()) {
        grr_map[group][src] = (RoutedRule){route.in_switch_port.dpid,1, act_list};
    } else {
        if(grr_map[group][src].dpsrc != route.in_switch_port.dpid) 
            grr_map[group][src].cookie = 1;
        else
            grr_map[group][src].cookie++;
    }
    return true;
  }
  
  bool mcrouteinstaller::delete_routed_table_entry(const ipaddr src, const ipaddr group, datapathid& dpid, uint64_t& cookie)
  {
    if(grr_map.find(group) == grr_map.end() ||
        grr_map[group].find(src) == grr_map[group].end()) {
        VLOG_WARN(lg, "Unkwon routing flow removed message src=%s group=%s",
                src.string().c_str(), group.string().c_str());
        return false;
    }  
    
    if(((grr_map[group][src].dpsrc == dpid && grr_map[group][src].cookie == cookie) || dpid.empty() ) )
    {
        VLOG_DBG(lg, "Remove installed routing flow src=%s group=%s dpid=%"PRIx64" cookie=%llu",
                src.string().c_str(), group.string().c_str(), dpid.as_host(), cookie);
    
        dpid = grr_map[group][src].dpsrc;
        cookie = grr_map[group][src].cookie;    
        grr_map[group].erase(src);
        if(grr_map[group].size() == 0) {
            grr_map.erase(group);
        }
    } else {
        VLOG_WARN(lg, "Routing flow removed message src = %s group = %s is invalid",
                src.string().c_str(), group.string().c_str());
        return false;
    }
    return true;
  }
  
  bool mcrouteinstaller::add_blocking_table_entry(const ipaddr src, const ipaddr group, const datapathid dpid)
  {
    if(gbr_map.find(group) != gbr_map.end() &&
       gbr_map[group].find(src) != gbr_map[group].end() &&
       gbr_map[group][src] != dpid) 
        return false;
        
    if(gbr_map.find(group) == gbr_map.end()) 
        gbr_map[group] = SrcBlockedRuleMap();
    if(gbr_map[group].find(src) == gbr_map[group].end())
        gbr_map[group][src] = dpid;
    return true;
  }
  
  bool mcrouteinstaller::delete_blocked_table_entry(const ipaddr src, const ipaddr group, datapathid& dpid)
  {
    if(gbr_map.find(group) == gbr_map.end() ||
        gbr_map[group].find(src) == gbr_map[group].end()) {
        VLOG_WARN(lg, "Unkwon blocking flow removed message src=%s group=%s",
                src.string().c_str(), group.string().c_str());
        return false;
    }
    VLOG_DBG(lg, "Delete installed blocking flow src=%s group=%s",
            src.string().c_str(), group.string().c_str());
    dpid = gbr_map[group][src];
    gbr_map[group].erase(src);
    if(gbr_map[group].size() == 0) {
        gbr_map.erase(group);            
    }
    
    return true;
  }
  
  void mcrouteinstaller::install_routing_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group,
                                                    uint16_t in_port, ofp_action_list act_list, uint32_t buffer_id,
                                                    uint64_t cookie, bool removedmsg, uint16_t idletime, uint16_t hardtime)
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
    ofm.command = (cookie==1)?OFPFC_ADD:OFPFC_MODIFY;
    ofm.flags = (removedmsg)?OFPFF_SEND_FLOW_REM:0;
    ofm.idle_timeout = idletime;
    ofm.hard_timeout = hardtime;
    ofm.buffer_id = buffer_id;
    ofm.out_port = OFPP_NONE;
    ofm.pack((ofp_flow_mod*) openflow_pack::get_pointer(of_raw));
    act_list.pack(openflow_pack::get_pointer(of_raw,sizeof(ofp_flow_mod)));
    VLOG_DBG(lg,"Install flow entry src=%s group=%s with %zu actions to %"PRIx64"", 
         src.string().c_str(), group.string().c_str(), act_list.action_list.size(), dpid.as_host());
    send_openflow_command(dpid, of_raw, false);
  }
  
  void mcrouteinstaller::remove_routing_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group)
  {
    ssize_t size = sizeof(ofp_flow_mod);
    of_raw.reset(new uint8_t[size]);
    of_flow_mod ofm;
    ofm.header = openflow_pack::header(OFPT_FLOW_MOD, size);
    ofm.match.dl_type = ntohs(ethernet::IP);
    ofm.match.nw_src = ntohl((uint32_t)src);
    ofm.match.nw_dst = ntohl((uint32_t)group);
    ofm.match.nw_proto = ip_::proto::UDP;
    ofm.match.wildcards = OFPFW_ALL & ~OFPFW_DL_TYPE &
                          ~OFPFW_NW_SRC_MASK & ~OFPFW_NW_DST_MASK & ~OFPFW_NW_PROTO;
    ofm.command = OFPFC_DELETE;
    ofm.buffer_id = -1;
    ofm.out_port = OFPP_NONE;
    ofm.pack((ofp_flow_mod*) openflow_pack::get_pointer(of_raw));
    VLOG_DBG(lg,"remove flow entry src=%s group=%s in %"PRIx64"", 
         src.string().c_str(), group.string().c_str(), dpid.as_host());
    send_openflow_command(dpid, of_raw, false);
  }
  
  void mcrouteinstaller::install_blocking_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group,
                                                     uint16_t in_port, uint16_t idletime, uint16_t hardtime)
  {
    ssize_t size = sizeof(ofp_flow_mod);
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
    ofm.cookie = 0;
    ofm.command = OFPFC_ADD;
    ofm.flags = OFPFF_SEND_FLOW_REM;
    ofm.idle_timeout = idletime;
    ofm.hard_timeout = hardtime;
    ofm.buffer_id = -1;
    ofm.out_port = OFPP_NONE;
    ofm.pack((ofp_flow_mod*) openflow_pack::get_pointer(of_raw));
    VLOG_DBG(lg,"Install drop flow entry src=%s group=%s to %"PRIx64"", 
         src.string().c_str(), group.string().c_str(), dpid.as_host());
    send_openflow_command(dpid, of_raw, false);
  } 
  
  void mcrouteinstaller::remove_blocking_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group)
  {
    ssize_t size = sizeof(ofp_flow_mod);
    of_raw.reset(new uint8_t[size]);
    of_flow_mod ofm;
    ofm.header = openflow_pack::header(OFPT_FLOW_MOD, size);
    ofm.match.dl_type = ntohs(ethernet::IP);
    ofm.match.nw_src = ntohl((uint32_t)src);
    ofm.match.nw_dst = ntohl((uint32_t)group);
    ofm.match.nw_proto = ip_::proto::UDP;
    ofm.match.wildcards = OFPFW_ALL & ~OFPFW_DL_TYPE &
                          ~OFPFW_NW_SRC_MASK & ~OFPFW_NW_DST_MASK & ~OFPFW_NW_PROTO;
    ofm.command = OFPFC_DELETE;
    ofm.buffer_id = -1;
    ofm.out_port = OFPP_NONE;
    ofm.pack((ofp_flow_mod*) openflow_pack::get_pointer(of_raw));
    VLOG_DBG(lg,"remove drop flow entry src=%s group=%s in %"PRIx64"", 
         src.string().c_str(), group.string().c_str(), dpid.as_host());
    send_openflow_command(dpid, of_raw, false);
  }
  
  void mcrouteinstaller::forward_routed_flow(const datapathid dpid, const ipaddr src, const ipaddr group,
                                             uint16_t in_port, ofp_action_list act_list, uint32_t buffer_id)
  {
    ssize_t size = act_list.mem_size();  
    of_raw.reset(new uint8_t[size]);
    
    act_list.pack(openflow_pack::get_pointer(of_raw));
    VLOG_DBG(lg,"Forward flow src=%s group=%s of dpid=%"PRIx64"", 
          src.string().c_str(), group.string().c_str(), dpid.as_host() );
    send_openflow_packet(dpid, buffer_id, (const ofp_action_header*)of_raw.get(), 
                         act_list.mem_size(), in_port, false);
  }
  
  void mcrouteinstaller::forward_routed_flow(const datapathid dpid, const ipaddr src, const ipaddr group,
                                             uint16_t in_port, ofp_action_list act_list, const Buffer& buf)
  {
    ssize_t size = act_list.mem_size();  
    of_raw.reset(new uint8_t[size]);
    
    act_list.pack(openflow_pack::get_pointer(of_raw));
    VLOG_DBG(lg,"Forward flow src=%s group=%s of dpid=%"PRIx64"", 
          src.string().c_str(), group.string().c_str(), dpid.as_host() );
    send_openflow_packet(dpid, buf, (const ofp_action_header*)of_raw.get(), 
                         act_list.mem_size(), in_port, false);
  }
   
  REGISTER_COMPONENT(container::Simple_component_factory<mcrouteinstaller>, 
		     mcrouteinstaller);
} // unnamed namespace
