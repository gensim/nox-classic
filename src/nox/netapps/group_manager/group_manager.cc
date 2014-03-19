#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>

#include "openflow-default.hh"
#include "assert.hh"
#include "flow.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "port-status.hh"
#include "packet-in.hh"
#include "vlog.hh"

#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"
#include "netinet++/igmp.hh"

#include "group_manager.hh"

namespace vigil {
namespace applications {
    
Vlog_module lg("group_manager");

// Variable
const uint32_t Group_manager::ROBUSTNESS = 2; 
const uint32_t Group_manager::STARTUP_QUERY_COUNT = ROBUSTNESS;
const uint32_t Group_manager::LAST_MEMBER_QUERY_COUNT = ROBUSTNESS;                                                             

// Interval
const timeval Group_manager::QUERY = {125, 0};              
const timeval Group_manager::QUERY_RESP = {10, 0}; 
const timeval Group_manager::STARTUP_QUERY = {30, 0};
const timeval Group_manager::LAST_MEMBER_QUERY = {1, 0};
const timeval Group_manager::GROUP_MEMBERSHIP = {260, 0}; // ROBUSTNESS * QUERY + QUERY_RESP

const ipaddr Group_manager::ALL_HOST_MULTICAST_ADDR(0xE0000001);
const ipaddr Group_manager::ALL_ROUTERS_MULTICAST_ADDR(0xE0000002);
const ipaddr Group_manager::IGMP_V3_REPORT_ADDR(0xE0000016);

std::size_t
Group_manager::lochash::operator()(const Interface& face) const
{
    HASH_NAMESPACE::hash<datapathid> dphash;
    HASH_NAMESPACE::hash<uint16_t> u16hash;
    return (dphash(face.dp) ^ u16hash(face.port));
}

bool
Group_manager::loceq::operator()(const Interface& a, const Interface& b) const
{
    return (a.dp == b.dp && a.port == b.port);
}

std::size_t
Group_manager::grouphash::operator()(const Group& g) const
{
    HASH_NAMESPACE::hash<datapathid> dphash;
    HASH_NAMESPACE::hash<uint16_t> u16hash;
    HASH_NAMESPACE::hash<uint32_t> u32hash;
    return (dphash(g.dp) ^ u16hash(g.port) ^ u32hash(g.addr));
}

bool
Group_manager::groupeq::operator()(const Group& a, const Group& b) const
{
    return (a.dp == b.dp && a.port == b.port && a.addr == b.addr);
}

Group_manager::Group_manager(const container::Context* c, const json_object*) 
    : Component(c) 
{
}

void 
Group_manager::configure(const container::Configuration* conf) 
{
    resolve(topology);
    //register events  
    register_event(Group_event::static_get_name());
}

void
Group_manager::install() 
{
    //register event handlers 
      
    register_handler<Datapath_join_event>
        (boost::bind(&Group_manager::handle_datapath_join, this, _1)); 
    register_handler<Port_status_event>
        (boost::bind(&Group_manager::handle_port_status, this, _1)); 
    register_handler<Link_event>
        (boost::bind(&Group_manager::handle_link_event, this, _1));
        
    uint32_t value[2];
    Packet_expr pe;
    value[0] = ethernet::IP;
    pe.set_field(Packet_expr::DL_TYPE, (uint32_t*) value);
    value[0] = ip_::proto::IGMP;
    pe.set_field(Packet_expr::NW_PROTO, (uint32_t*) value);
    register_handler_on_match(OFP_DEFAULT_PRIORITY, pe, 
        boost::bind(&Group_manager::handle_igmp, this, _1));      
}

void 
Group_manager::getInstance(const container::Context* c,
				  Group_manager*& component)
{
    component = dynamic_cast<Group_manager*>
        (c->get_by_interface(container::Interface_description
		      (typeid(Group_manager).name())));
}

Disposition 
Group_manager::handle_datapath_join(const Event& e)
{
    const Datapath_join_event& dj = assert_cast<const Datapath_join_event&>(e);
    for(std::vector<Port>::const_iterator p_iter = dj.ports.begin(); 
        p_iter != dj.ports.end(); ++p_iter) {
        if(p_iter->port_no <= 0 || p_iter->port_no >= OFPP_MAX) continue;
        start_general_query_timer((Interface){dj.datapath_id, p_iter->port_no});
    }
    return CONTINUE;
}
    
Disposition 
Group_manager::handle_port_status(const Event& e)
{
    const Port_status_event& ps = assert_cast<const Port_status_event&>(e);
    
    if(ps.reason == OFPPR_ADD){
        start_general_query_timer((Interface){ps.datapath_id, ps.port.port_no});
    }
    return CONTINUE;
}
    
Disposition 
Group_manager::handle_link_event(const Event& e)
{
    const Link_event& le = assert_cast<const Link_event&>(e);
    if (le.action == Link_event::REMOVE) {
        start_general_query_timer((Interface){le.dpsrc, le.sport});
        start_general_query_timer((Interface){le.dpdst, le.dport});
    }
    return CONTINUE;
}

Disposition 
Group_manager::handle_igmp(const Event& e)
{
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    const uint8_t* data = pi.get_buffer()->data();
    const size_t len = pi.get_buffer()->size();
    
    ethernet* ethh = (ethernet*) data;
    ip_* iph = (ip_*) ethh->data();
    size_t igmp_size = data+len - iph->data();
  
    SourceSet ss;
    if(igmp_size == sizeof(igmp)) {
        igmp* igmph = (igmp*) iph->data();       
        VLOG_DBG(lg, "Recv IGMP: %s", igmph->c_string());
        if(igmph->type == igmp_type::QUERY) {
            VLOG_WARN(lg, "Received IGMP Query message from unknow router, switch or another controller");
        } else if(igmph->type == igmp_type::V1_REPORT && iph->daddr == igmph->group) {
            process_record_source((Group){pi.datapath_id, pi.in_port, igmph->group}, ss, igmpv3_record_type::IS_EX, ICM_V1);
        } else if(igmph->type == igmp_type::V2_REPORT && iph->daddr == igmph->group) {
            process_record_source((Group){pi.datapath_id, pi.in_port, igmph->group}, ss, igmpv3_record_type::IS_EX, ICM_V2);
        } else if(igmph->type == igmp_type::LEAVE && iph->daddr == ALL_ROUTERS_MULTICAST_ADDR){
            process_record_source((Group){pi.datapath_id, pi.in_port, igmph->group}, ss, igmpv3_record_type::TO_IN, ICM_V2);
        } else if(igmph->type == igmp_type::V3_REPORT) {
            VLOG_WARN(lg, "Received IGMPv3 Report message is no Group Record");
        } else {
            VLOG_ERR(lg, "Unknow IGMP header type");
        }
    } else if(igmp_size > sizeof(igmpv3_report)) {
        igmpv3_report* igmpv3h = (igmpv3_report*) iph->data();
        VLOG_DBG(lg, "Recv IGMP: %s", igmpv3h->c_string());
        igmpv3_record* r = (igmpv3_record*) &igmpv3h->record[0];
        for(uint16_t i=0; i < ntohs(igmpv3h->numrec); i++, r = (igmpv3_record*)r->next(), ss.clear()) {
            for(uint16_t j=0; j < ntohs(r->numsrc); j++) {
                ss.insert(r->sources[j]);
            }
            process_record_source((Group){pi.datapath_id, pi.in_port, r->group}, ss, r->type, ICM_V3);
        }
    }
    return CONTINUE;
}

void 
Group_manager::process_record_source(const Group& g, SourceSet& ss, const uint8_t type, const igmp_compatibility_mode version)
{    
    SourceSet query_set;
    SourceSet::const_iterator ss_iter;
    SourceSet::iterator sts_iter;
    SrcTimerMap::iterator stm_iter;
    
    if(gr_map.find(g) == gr_map.end()) {
        if(type == igmpv3_record_type::BLOCK ||
            ((type == igmpv3_record_type::TO_IN ||
              type == igmpv3_record_type::IS_IN ||
              type == igmpv3_record_type::ALLOW 
            ) && ss.empty())) {
            return;
        }
        add_group(g);
    } 
    
    if(gr_map[g]->compat > version) {
        gr_map[g]->compat = version;
    }
    
    switch(type) {
        case igmpv3_record_type::TO_IN:
            if(gr_map[g]->compat == ICM_V1) break;
        case igmpv3_record_type::ALLOW:            
        case igmpv3_record_type::IS_IN:
            for(ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {                                           // (B)=GMI
                start_group_source_timer(g, *ss_iter);
            }
            if(gr_map[g]->filter == IFM_EXCLUDE) {
                for(sts_iter=gr_map[g]->st_set.begin(); sts_iter!=gr_map[g]->st_set.end(); sts_iter++) { // Delete (Y*A)
                    if(ss.find(*sts_iter) != ss.end()) 
                        delete_group_timeout_source(g, *sts_iter);                                            // STS=Y-A
                } 
            }
            if(type == igmpv3_record_type::TO_IN) {
                query_set.clear();
                for(stm_iter=gr_map[g]->st_map.begin(); stm_iter!=gr_map[g]->st_map.end(); stm_iter++) {
                    if(ss.find(stm_iter->first) == ss.end()) 
                        query_set.insert(stm_iter->first);
                } 
                start_group_source_specific_query_timer(g, query_set);                                  // Send Q(G,STM)
                if(gr_map[g]->filter == IFM_EXCLUDE) start_group_specific_query_timer(g);                      // GM=GMI
            }
            break;
        case igmpv3_record_type::TO_EX:
            if(gr_map[g]->compat == ICM_V1 || gr_map[g]->compat == ICM_V2) ss.clear();
        case igmpv3_record_type::IS_EX:
            if(gr_map[g]->filter == IFM_INCLUDE) {
                gr_map[g]->filter = IFM_EXCLUDE;
                post(new Group_event(g.addr, g.dp, g.port, Group_event::TOEXCLUDE));
                for(ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {                                       // (B-A)=0
                    if(gr_map[g]->st_map.find(*ss_iter) == gr_map[g]->st_map.end()) 
                        add_group_timeout_source(g, *ss_iter);                                              // STS=(B-A)
                }
                for(stm_iter=gr_map[g]->st_map.begin(); stm_iter!=gr_map[g]->st_map.end(); stm_iter++) { // Delete (A-B)
                    if(ss.find(stm_iter->first) == ss.end()) 
                        delete_group_source(g, stm_iter->first);                                            // STM=(A*B)
                }
            } else if(gr_map[g]->filter == IFM_EXCLUDE) {
                for(ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {                                   // (A-X-Y)=GMI 
                    if(gr_map[g]->st_map.find(*ss_iter) == gr_map[g]->st_map.end()&& 
                        gr_map[g]->st_set.find(*ss_iter) == gr_map[g]->st_set.end())
                        start_group_source_timer(g, *ss_iter);                                  // STM=X+(A-X-Y)=X+(A-Y)
                }
                for(stm_iter=gr_map[g]->st_map.begin(); stm_iter!=gr_map[g]->st_map.end(); stm_iter++) { // Delete (X-A)
                    if(ss.find(stm_iter->first) == ss.end() ||   
                        gr_map[g]->st_set.find(stm_iter->first) != gr_map[g]->st_set.end()) 
                        delete_group_source(g, stm_iter->first); // STM=((X+(A-Y))A)-Y=(AX+(A-Y))-Y=((AX-Y)+(A-Y))=(A-Y)
                }  
                for(sts_iter=gr_map[g]->st_set.begin(); sts_iter!=gr_map[g]->st_set.end(); sts_iter++) { // Delete (Y-A)
                    if(ss.find(*sts_iter) == ss.end())                                                        
                        delete_group_timeout_source(g, *sts_iter);                                            // STS=Y*A
                }            
            }
            if(type == igmpv3_record_type::TO_EX) {
                query_set.clear();
                for(stm_iter=gr_map[g]->st_map.begin(); stm_iter!=gr_map[g]->st_map.end(); stm_iter++) {  
                    query_set.insert(stm_iter->first);
                }
                start_group_source_specific_query_timer(g, query_set);                                  // send Q(G,STM)
            }
            start_group_member_timer(g, version);                                                              // GT=GMI
            break;
        case igmpv3_record_type::BLOCK:
            if(gr_map[g]->compat == ICM_V1 || gr_map[g]->compat == ICM_V2) break;
            query_set.clear();
            if(gr_map[g]->filter == IFM_INCLUDE) {
                for(ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {
                    if(gr_map[g]->st_map.find(*ss_iter) != gr_map[g]->st_map.end()) 
                        query_set.insert(*ss_iter);                                                    // Query_Set=(A*B)
                }
            } else if(gr_map[g]->filter == IFM_EXCLUDE) {
                for(ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {
                    if(gr_map[g]->st_set.find(*ss_iter) == gr_map[g]->st_set.end()) 
                        query_set.insert(*ss_iter);                                                    // Query_Set=(A-Y)
                } 
                
                for(ss_iter=query_set.begin(); ss_iter!=query_set.end(); ss_iter++) {
                    if(gr_map[g]->st_map.find(*ss_iter) == gr_map[g]->st_map.end()) {
                        start_group_source_timer(g, *ss_iter);                                              //(A-X-Y)=GMI
                    }
                } 
            }
            start_group_source_specific_query_timer(g, query_set);                                 // Send Q(G,Query_Set)
            break;
    }        
}

void
Group_manager::start_group_member_timer(const Group& g, const igmp_compatibility_mode version)
{
    gr_map[g]->gs_timer.cancel();
    gr_map[g]->gss_timer.cancel();
    
    if(version <= ICM_V1) {
        gr_map[g]->gm_v1_timer.cancel();
        Timer_Callback cb1 = boost::bind(&Group_manager::v1_group_member_callback, this, g); 
        gr_map[g]->gm_v1_timer = post(cb1, GROUP_MEMBERSHIP); 
    }
    
    if(version <= ICM_V2) {
        gr_map[g]->gm_v2_timer.cancel();
        Timer_Callback cb2 = boost::bind(&Group_manager::v2_group_member_callback, this, g); 
        gr_map[g]->gm_v2_timer = post(cb2, GROUP_MEMBERSHIP);        
    }
    
    if(version <= ICM_V3) {
        gr_map[g]->gm_v3_timer.cancel();
        Timer_Callback cb3 = boost::bind(&Group_manager::v3_group_member_callback, this, g); 
        gr_map[g]->gm_v3_timer = post(cb3, GROUP_MEMBERSHIP);
    }
}

void
Group_manager::v1_group_member_callback(const Group& g)
{
    if(gr_map.find(g)==gr_map.end()) return;    
    gr_map[g]->compat = ICM_V2;
}

void
Group_manager::v2_group_member_callback(const Group& g)
{
    if(gr_map.find(g)==gr_map.end()) return;   
    gr_map[g]->compat = ICM_V3;
}

void
Group_manager::v3_group_member_callback(const Group& g)
{
    if(gr_map.find(g)==gr_map.end()) return; 
    if(gr_map[g]->filter == IFM_EXCLUDE) {
        gr_map[g]->filter = IFM_INCLUDE;
        for(SrcTimeoutSet::iterator sts_iter=gr_map[g]->st_set.begin(); sts_iter!=gr_map[g]->st_set.end(); sts_iter++)
            delete_group_timeout_source(g, *sts_iter);
        post(new Group_event(g.addr, g.dp, g.port, Group_event::TOINCLUDE));            
    }
    if(gr_map[g]->filter == IFM_INCLUDE && gr_map[g]->st_map.size() == 0) {
        delete_group(g);
    }
}

void
Group_manager::start_group_source_timer(const Group& g, const ipaddr& src)
{
    if(gr_map.find(g) == gr_map.end()) return;
    if(add_group_source(g, src)) {
        Timer_Callback cb = boost::bind(&Group_manager::group_source_callback, this, g, src);        
        gr_map[g]->st_map[src] = post(cb, GROUP_MEMBERSHIP);
    } else {
        gr_map[g]->st_map[src].cancel();
        gr_map[g]->st_map[src].reset(GROUP_MEMBERSHIP.tv_sec, GROUP_MEMBERSHIP.tv_usec);
    }
}

void
Group_manager::group_source_callback(const Group& g, const ipaddr& src)
{
    if(gr_map.find(g) == gr_map.end()) return;
    if(gr_map[g]->st_map.find(src) == gr_map[g]->st_map.end()) return;    
    
    delete_group_source(g, src);
    if(gr_map[g]->filter == IFM_INCLUDE) {         
        if(gr_map[g]->st_map.size() == 0) {
            delete_group(g);
        }
    } else if(gr_map[g]->filter == IFM_EXCLUDE) {
        add_group_timeout_source(g, src);
    }
}


void
Group_manager::start_general_query_timer(const Interface& face)
{    
    if(gq_map.find(face)!=gq_map.end()) gq_map[face].cancel();
    Timer_Callback cb = boost::bind(&Group_manager::general_query_callback, this, face, 1);
    gq_map[face] = post(cb, STARTUP_QUERY);
}

void
Group_manager::general_query_callback(const Interface& face, const uint32_t count)
{
    if(gq_map.find(face)==gq_map.end()) return;
    
    Topology::DpInfo dpinfo = topology->get_dpinfo(face.dp);
    std::vector<Port>::const_iterator p_iter = dpinfo.ports.begin();
    for(;p_iter != dpinfo.ports.end(); ++p_iter) if(face.port == p_iter->port_no) break;
   
    if(!dpinfo.active || topology->is_internal(face.dp, face.port) || p_iter == dpinfo.ports.end()) {
        gq_map.erase(face);
        return;
    }

    send_general_query(face.dp, *p_iter);   
    Timer_Callback cb = boost::bind(&Group_manager::general_query_callback, 
        this, face, (count == STARTUP_QUERY_COUNT)? count : count+1);
    gq_map[face] = post(cb, (count == STARTUP_QUERY_COUNT) ? QUERY : STARTUP_QUERY);
}

void
Group_manager::start_group_specific_query_timer(const Group& g)
{   
    if(gr_map.find(g) == gr_map.end()) return;
    
    const timeval tv = gr_map[g]->gs_timer.get_time();
    if(tv.tv_sec != 0 || tv.tv_usec != 0) return;
    
    Timer_Callback cb = boost::bind(&Group_manager::group_specific_query_callback, this, g, 0);      
    gr_map[g]->gs_timer = post(cb);
}

void
Group_manager::group_specific_query_callback(const Group& g, const uint32_t count)
{
    if(gr_map.find(g) == gr_map.end()) return;
    
    Topology::DpInfo dpinfo = topology->get_dpinfo(g.dp);
    std::vector<Port>::const_iterator p_iter = dpinfo.ports.begin();
    for(;p_iter != dpinfo.ports.end(); ++p_iter) if(g.port == p_iter->port_no) break;

    if(!dpinfo.active || topology->is_internal(g.dp, g.port) || p_iter == dpinfo.ports.end()) {
        delete_group(g);
        return;
    }   
    
    if(count < LAST_MEMBER_QUERY_COUNT) {
        send_group_specific_query(g.dp, *p_iter, g.addr);
        
        Timer_Callback cb = boost::bind(&Group_manager::group_specific_query_callback, this, g, count+1);
        gr_map[g]->gs_timer = post(cb, LAST_MEMBER_QUERY);
    } else {
        delete_group(g);
    }   
}

void 
Group_manager::start_group_source_specific_query_timer(const Group& g, const SourceSet& ss)
{
    if(gr_map.find(g) == gr_map.end()) return;
    
    const timeval tv = gr_map[g]->gss_timer.get_time();
    if(tv.tv_sec != 0 || tv.tv_usec != 0) return;
    
    Timer_Callback cb = boost::bind(&Group_manager::group_source_specific_query_callback, this, g, ss, 0);      
    gr_map[g]->gss_timer = post(cb);
}

void 
Group_manager::group_source_specific_query_callback(const Group& g, const SourceSet& ss, const uint32_t count)
{
    if(gr_map.find(g) == gr_map.end()) return;
    
    Topology::DpInfo dpinfo = topology->get_dpinfo(g.dp);
    std::vector<Port>::const_iterator p_iter = dpinfo.ports.begin();
    for(;p_iter != dpinfo.ports.end(); ++p_iter) if(g.port == p_iter->port_no) break;

    if(!dpinfo.active || topology->is_internal(g.dp, g.port) || p_iter == dpinfo.ports.end()) {
        delete_group(g);
        return;
    }   
    
    if(count < LAST_MEMBER_QUERY_COUNT) {
        send_group_source_specific_query(g.dp, *p_iter, g.addr, ss);
        
        Timer_Callback cb = boost::bind(&Group_manager::group_source_specific_query_callback, this, g, ss, count+1);      
        gr_map[g]->gss_timer = post(cb, LAST_MEMBER_QUERY);
    } else {
        for(SourceSet::const_iterator ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {
            delete_group_source(g, *ss_iter);
        }
        if(gr_map[g]->filter == IFM_INCLUDE && gr_map[g]->st_map.empty()) {
            delete_group(g);
        }
    }   
}
    
bool 
Group_manager::add_group(const Group& g)
{
    if(gr_map.find(g) == gr_map.end()) {
        VLOG_INFO(lg, "Add Group: %s %d %s", g.dp.string().c_str(), g.port, g.addr.string().c_str());
        gr_map[g] = (RecordPtr) new Record();
        post(new Group_event(g.addr, g.dp, g.port, Group_event::ADD));
        return true;
    }
    return false;
}

bool 
Group_manager::delete_group(const Group& g)
{  
    if(gr_map.find(g) != gr_map.end()) {
        for(SrcTimerMap::const_iterator stm_iter=gr_map[g]->st_map.begin(); stm_iter!=gr_map[g]->st_map.end(); stm_iter++) 
            delete_group_source(g, stm_iter->first);
        for(SrcTimeoutSet::const_iterator sts_iter=gr_map[g]->st_set.begin(); sts_iter!=gr_map[g]->st_set.end(); sts_iter++) 
            delete_group_source(g, *sts_iter);
        VLOG_INFO(lg, "Delete Group: %s %d %s", g.dp.string().c_str(), g.port, g.addr.string().c_str());
        gr_map[g]->gm_v1_timer.cancel();
        gr_map[g]->gm_v2_timer.cancel();
        gr_map[g]->gm_v3_timer.cancel();
        gr_map[g]->gs_timer.cancel();
        gr_map[g]->gss_timer.cancel();
        if(gr_map[g]->filter == IFM_EXCLUDE) {
            gr_map[g]->filter = IFM_INCLUDE;
            post(new Group_event(g.addr, g.dp, g.port, Group_event::TOINCLUDE));            
        }
        gr_map.erase(g);          
        post(new Group_event(g.addr, g.dp, g.port, Group_event::REMOVE));
        return true;
    }
    return false;
}

bool 
Group_manager::add_group_source(const Group& g, const ipaddr& src)
{
    if(gr_map.find(g) != gr_map.end() && gr_map[g]->st_map.find(src) == gr_map[g]->st_map.end()) {
        VLOG_INFO(lg, "Add Group Source: %s %d %s %s", g.dp.string().c_str(), g.port, g.addr.string().c_str(), src.string().c_str());
        post(new Group_event(g.addr, g.dp, g.port, src, Group_event::ADD));
        return true;
    }
    return false;
}

bool 
Group_manager::delete_group_source(const Group& g, const ipaddr& src)
{
    if(gr_map.find(g) != gr_map.end() && gr_map[g]->st_map.find(src) != gr_map[g]->st_map.end()) {
        VLOG_INFO(lg, "Delete Group Source: %s %d %s %s", g.dp.string().c_str(), g.port, g.addr.string().c_str(), src.string().c_str());  
        gr_map[g]->st_map[src].cancel();
        gr_map[g]->st_map.erase(src);
        post(new Group_event(g.addr, g.dp, g.port, src, Group_event::REMOVE));
        return true;
    }
    return false;
}

bool 
Group_manager::add_group_timeout_source(const Group& g, const ipaddr& src)
{
    if(gr_map.find(g) != gr_map.end() && gr_map[g]->st_set.find(src) == gr_map[g]->st_set.end()) {
        VLOG_INFO(lg, "Add Group Timeout Source: %s %d %s %s", g.dp.string().c_str(), g.port, g.addr.string().c_str(), src.string().c_str());
        gr_map[g]->st_set.insert(src);
        return true;
    }
    return false;
}

bool 
Group_manager::delete_group_timeout_source(const Group& g, const ipaddr& src)
{
    if(gr_map.find(g) != gr_map.end() && gr_map[g]->st_set.find(src) != gr_map[g]->st_set.end()) {
        VLOG_INFO(lg, "Delete Group Timeout Source: %s %d %s %s", g.dp.string().c_str(), g.port, g.addr.string().c_str(), src.string().c_str());
        gr_map[g]->st_set.erase(src);
        return true;
    }
    return false;    
}

void
Group_manager::send_general_query(const datapathid& dp, const Port& port) 
{
    ipaddr daddr = ALL_HOST_MULTICAST_ADDR;
    uint16_t iph_tlen = sizeof(ip_) + sizeof(igmpv3_query);
    uint8_t igmph_code = igmpv3_query::cal_code(QUERY_RESP);    
    uint8_t igmph_qqic = igmpv3_query::cal_code(QUERY);
    uint8_t igmph_sqrv = igmpv3_query::cal_sqrv(ROBUSTNESS, false);
    
    Array_buffer buf(sizeof(ethernet) + iph_tlen);
    memset(buf.data(), 0, buf.size());
    
    ethernet* ethh = (ethernet*) buf.data();
    ethh->daddr = get_eth_multicast_addr(daddr);
    ethh->saddr = port.hw_addr;
    ethh->type = ethernet::IP;
    
    ip_* iph = (ip_*) ethh->data();
    iph->ihl = 5;
    iph->ver = 4;
    iph->tos = 0;
    iph->tot_len = htons(iph_tlen);
    iph->id = 0;
    iph->frag_off = htons(ip_::DONT_FRAGMENT);
    iph->ttl = 1;
    iph->protocol = ip_::proto::IGMP;
    iph->saddr = ipaddr("0.0.0.0");
    iph->daddr = daddr; 
    iph->csum = iph->calc_csum();
      
    igmpv3_query* igmph = (igmpv3_query*) iph->data();
    igmph->type = igmp_type::QUERY;
    igmph->code = igmph_code;
    igmph->group = (uint32_t)0;
    igmph->sqrv = igmph_sqrv;
    igmph->qqic = igmph_qqic;
    igmph->numsrc = htons(0);           
    igmph->csum = igmph->calc_csum(); 
    
    VLOG_DBG(lg, "Send IGMP General Query to Port %d of Datapath %s: %s", port.port_no, dp.string().c_str(), igmph->string().c_str());     
    send_openflow_packet(dp, buf, port.port_no, OFPP_CONTROLLER, true);
}

void
Group_manager::send_group_specific_query(const datapathid& dp, const Port& port, const ipaddr& gaddr) 
{
    ipaddr daddr = gaddr;
    uint16_t iph_tlen = sizeof(ip_) + sizeof(igmpv3_query);
    uint8_t igmph_code = igmpv3_query::cal_code(LAST_MEMBER_QUERY);    
    uint8_t igmph_qqic = igmpv3_query::cal_code(QUERY);
    uint8_t igmph_sqrv = igmpv3_query::cal_sqrv(ROBUSTNESS, false);
    
    Array_buffer buf(sizeof(ethernet) + iph_tlen);
    memset(buf.data(), 0, buf.size());
    
    ethernet* ethh = (ethernet*) buf.data();
    ethh->daddr = get_eth_multicast_addr(daddr);
    ethh->saddr = port.hw_addr;
    ethh->type = ethernet::IP;
    
    ip_* iph = (ip_*) ethh->data();
    iph->ihl = 5;
    iph->ver = 4;
    iph->tos = 0;
    iph->tot_len = htons(iph_tlen);
    iph->id = 0;
    iph->frag_off = htons(ip_::DONT_FRAGMENT);
    iph->ttl = 1;
    iph->protocol = ip_::proto::IGMP;
    iph->saddr = ipaddr("0.0.0.0");
    iph->daddr = daddr; 
    iph->csum = iph->calc_csum();
      
    igmpv3_query* igmph = (igmpv3_query*) iph->data();
    igmph->type = igmp_type::QUERY;
    igmph->code = igmph_code;
    igmph->group = gaddr;
    igmph->sqrv = igmph_sqrv;
    igmph->qqic = igmph_qqic;
    igmph->numsrc = htons(0);           
    igmph->csum = igmph->calc_csum();   
    VLOG_DBG(lg, "Send IGMP Group Specific Query to Port %d of Datapath %s: %s", port.port_no, dp.string().c_str(), igmph->string().c_str());     
    send_openflow_packet(dp, buf, port.port_no, OFPP_CONTROLLER, true);
}

void
Group_manager::send_group_source_specific_query(const datapathid& dp, const Port& port, const ipaddr& gaddr, const SourceSet& ss) 
{
    ipaddr daddr = gaddr;
    uint16_t iph_tlen = sizeof(ip_) + sizeof(igmpv3_query) + ss.size()*4;
    uint8_t igmph_code = igmpv3_query::cal_code(LAST_MEMBER_QUERY);    
    uint8_t igmph_qqic = igmpv3_query::cal_code(QUERY);
    uint8_t igmph_sqrv = igmpv3_query::cal_sqrv(ROBUSTNESS, false);
    
    Array_buffer buf(sizeof(ethernet) + iph_tlen);
    memset(buf.data(), 0, buf.size());
    
    ethernet* ethh = (ethernet*) buf.data();
    ethh->daddr = get_eth_multicast_addr(daddr);
    ethh->saddr = port.hw_addr;
    ethh->type = ethernet::IP;
    
    ip_* iph = (ip_*) ethh->data();
    iph->ihl = 5;
    iph->ver = 4;
    iph->tos = 0;
    iph->tot_len = htons(iph_tlen);
    iph->id = 0;
    iph->frag_off = htons(ip_::DONT_FRAGMENT);
    iph->ttl = 1;
    iph->protocol = ip_::proto::IGMP;
    iph->saddr = ipaddr("0.0.0.0");
    iph->daddr = daddr; 
    iph->csum = iph->calc_csum();
      
    igmpv3_query* igmph = (igmpv3_query*) iph->data();
    igmph->type = igmp_type::QUERY;
    igmph->code = igmph_code;
    igmph->group = gaddr;
    igmph->sqrv = igmph_sqrv;
    igmph->qqic = igmph_qqic;
    igmph->numsrc = htons(ss.size());
    uint16_t i = 0;
    for(SourceSet::const_iterator ss_iter=ss.begin(); ss_iter!=ss.end(); ss_iter++) {
        igmph->sources[i++] = *ss_iter;
    }    
    igmph->csum = igmph->calc_csum();   
    
    VLOG_DBG(lg, "Send IGMP Group Source Specific Query to Port %d of Datapath %s: %s", port.port_no, dp.string().c_str(), igmph->string().c_str());     
    send_openflow_packet(dp, buf, port.port_no, OFPP_CONTROLLER, true);
}

ethernetaddr
Group_manager::get_eth_multicast_addr(uint32_t addr) const
{
    uint8_t* p = (uint8_t*) &addr;
    uint8_t ethaddr[6];
    ethaddr[0] = 0x01;
    ethaddr[1] = 0x00;
    ethaddr[2] = 0x5E;
    ethaddr[3] = p[1] & 0x7F;
    ethaddr[4] = p[2];
    ethaddr[5] = p[3];
    return ethernetaddr(ethaddr);
}

REGISTER_COMPONENT(container::Simple_component_factory<Group_manager>, Group_manager);

}
} // unnamed namespace
