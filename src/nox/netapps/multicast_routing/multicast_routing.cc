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
#include "group_manager/group-event.hh"
#include "vlog.hh"
#include "netinet++/ipaddr.hh"

#include "multicast_routing.hh"

namespace vigil {
namespace applications {
    
Vlog_module lg("multicast_routing");

std::size_t
MC_routing_module::mtkhash::operator()(const MulticastTreeKey& mtk) const
{
    return HASH_NAMESPACE::hash<ipaddr>()(mtk.group) ^ HASH_NAMESPACE::hash<ipaddr>()(mtk.src);
}

bool
MC_routing_module::mtkeq::operator()(const MulticastTreeKey& a, const MulticastTreeKey& b) const
{
    return (a.group == b.group && a.src == b.src);
}

MC_routing_module::MC_routing_module(const container::Context* c, const json_object*) 
    : Component(c) 
{
}

void 
MC_routing_module::configure(const container::Configuration* conf) 
{
    resolve(topology);
    //register events   
}

void
MC_routing_module::install() 
{
    //register event handlers 
    register_handler<Group_event>
        (boost::bind(&MC_routing_module::handle_group_event, this, _1));
}

void 
MC_routing_module::getInstance(const container::Context* c,
				  MC_routing_module*& component)
{
    component = dynamic_cast<MC_routing_module*>
        (c->get_by_interface(container::Interface_description
		      (typeid(MC_routing_module).name())));
}

Disposition
MC_routing_module::handle_group_event(const Event& e)
{
    const Group_event& ge = assert_cast<const Group_event&>(e);
    
    MulticastTreeKey mtk = {ge.group, ge.src};
    MulticastTreeMap::iterator mtm_it = mt_map.find(mtk);
    mc_routing_tree_mode mode;
    DestMapPtr dmp;
    AdjListPtr alp;
    
    if (ge.action == Group_event::REMOVE) {
        bool isDelDp = false, isDelPort = false;
        DestMap::iterator dm_it;
        PortSet::iterator ps_it;
        if(mtm_it == mt_map.end()) {
            VLOG_ERR(lg, "Remove unknown multicast tree, group %s src %s", 
                ge.group.string().c_str(), ge.src.string().c_str());
            return CONTINUE;
        } else {
            mode = mt_map[mtk].mode; 
            dmp = mt_map[mtk].dests;
            alp = mt_map[mtk].mctree;
        }
        
        dm_it = dmp->find(ge.dp);
        if(dm_it == dmp->end()) {
            VLOG_ERR(lg, "Remove unknown multicast tree datapath, group %s src %s dp %s", 
                ge.group.string().c_str(), ge.src.string().c_str(), ge.dp.string().c_str());
            return CONTINUE;
        }
        
        ps_it = dm_it->second.find(ge.port);
        if(ps_it == dm_it->second.end()) {
            VLOG_ERR(lg, "Remove unknown multicast tree datapath port, group %s src %s dp %s port %u", 
                ge.group.string().c_str(), ge.src.string().c_str(), ge.dp.string().c_str(), ge.port);
            return CONTINUE;
        }
        
        isDelPort = true;
        dm_it->second.erase(ps_it);
        if(dm_it->second.empty()) {
            isDelDp = true;
            dmp->erase(dm_it);
        }  
        
        if(isDelDp) {
            calculate_multicast_shared_tree(alp, dmp);
        }
        
    } else if (ge.action == Group_event::ADD) {
        bool isAddDp = false, isAddPort = false;
        if(mtm_it == mt_map.end()) {            
            mode = (!find_src(ge.src)) ? MRTM_SHARED : MRTM_SOURCE;
            dmp = (DestMapPtr) new DestMap;
            alp = (AdjListPtr) new AdjList;
            mt_map[mtk] = (MulticastTreeVal){dmp, alp, mode};
        } else {
            mode = mt_map[mtk].mode; 
            dmp = mt_map[mtk].dests;
            alp = mt_map[mtk].mctree;
        }
        
        if(dmp->find(ge.dp) == dmp->end()) {
            isAddDp = true;
            isAddPort = true;
            PortSet ps;
            ps.insert(ge.port);
            (*dmp)[ge.dp] = ps;
        } else {
            if((*dmp)[ge.dp].find(ge.port) == (*dmp)[ge.dp].end()) {
                isAddPort = true;
                (*dmp)[ge.dp].insert(ge.port);
            }
        }
        
        if(isAddDp) {
            calculate_multicast_shared_tree(alp, dmp);
        }
        
    } else {
        VLOG_ERR(lg, "Unknown group event action %u", ge.action);
    }
    
    return CONTINUE;
}

bool 
MC_routing_module::find_src(const ipaddr& src) const
{
    return false;
}

void
MC_routing_module::calculate_multicast_shared_tree(AdjListPtr& mctree, const DestMapPtr& dests) 
{
    AdjListPtr graph ;
    get_graph_from_topology(graph);    
    kmb_approximation_algorithm(mctree, graph, dests);
}

void
MC_routing_module::kmb_approximation_algorithm(AdjListPtr& mctree, const AdjListPtr& graph, const DestMapPtr& dests) 
{
    AdjListPtr subgraph;
    get_complete_subgraph(subgraph, graph, dests);
}

void 
MC_routing_module::get_graph_from_topology(AdjListPtr& graph)
{
    graph = (AdjListPtr) new AdjList();
    
    std::list<datapathid> dplist = topology->get_datapaths();
    for(std::list<datapathid>::const_iterator it = dplist.begin(); it != dplist.end(); it++) {        
        AdjListNode aln;
        Topology::DatapathLinkMap neighbors = topology->get_outlinks(*it);
        for(Topology::DatapathLinkMap::iterator dlm_it = neighbors.begin(); dlm_it != neighbors.end(); dlm_it++) {
            LinkList ll;
            for(std::list<Topology::LinkPorts>::iterator lp_it = dlm_it->second.begin(); lp_it != dlm_it->second.end(); lp_it++) {
                Link link = {lp_it->src, lp_it->dst, 1}; 
                ll.push_back(link);
            }
            if(!ll.empty()) {
                aln[dlm_it->first] = ll;
            }
        }
        if(!aln.empty()) {
            (*graph)[*it] = aln;
        }
    }
}

void
MC_routing_module::get_complete_subgraph(AdjListPtr& subgraph, const AdjListPtr& graph, const DestMapPtr& dests)
{
    subgraph = (AdjListPtr) new AdjList();
    
    for(DestMap::iterator src_it = dests->begin(); src_it != dests->end(); src_it++) {
        for(DestMap::iterator dst_it = dests->begin(); dst_it != dests->end(); dst_it++) {
            if(src_it->first == dst_it->first) continue;
            
        }
    }
}

REGISTER_COMPONENT(container::Simple_component_factory<MC_routing_module>, MC_routing_module);

}
} // unnamed namespace
