#include "multicast_routing.hh"
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

namespace vigil {
namespace applications {
    
Vlog_module log("multicast_routing");

MC_routing_module::MC_routing_module(const container::Context* c, const json_object*) 
    : Component(c) 
{
}

void 
MC_routing_module::configure(const container::Configuration* conf) 
{
    resolve(routing);
    resolve(hit);
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

bool 
MC_routing_module::get_multicast_tree_path(const ipaddr& src,
                                           const ipaddr& group, 
                                           network::route& route,
                                           Src2TreeListPtr& stot,
                                           hash_map<datapathid,ofp_action_list>* oal)
{      
    AdjListPtr tree;
    DstPortMapPtr dsts;
    hash_set<datapathid> checked;    
    route.next_hops.clear();   
    
    if(get_multicast_tree(src, group, tree, dsts) && 
        get_route_source_tree(src, tree, route, stot)) {
        
        if(oal) oal->clear();
        
        network::hop* nhop = &route;
        while(nhop->next_hops.size()>0) {
            if(oal) (*oal)[nhop->in_switch_port.dpid] = ofp_action_list();
            nhop = nhop->next_hops.front().second;
        }            
    
        network::hop* newhop = NULL;
        NodeQueue q;
        q.push((Node){datapathid(), nhop->in_switch_port.dpid, nhop});
        while(q.size()!=0) {
            Node u = q.front();
            if(oal) (*oal)[u.id] = ofp_action_list();
            q.pop();
            for(AdjListNode::iterator it = (*tree)[u.id].begin();
                    it != (*tree)[u.id].end(); it++) {
                if(it->first == u.parent) continue;
                if(checked.find(it->first)!=checked.end())  continue;
                checked.insert(it->first);
                newhop = new network::hop(it->first, it->second.dstport);
                u.nhop->next_hops.push_front(std::make_pair(it->second.srcport, newhop));
                q.push((Node){u.id, it->first, newhop});                              
            }
            if(dsts->find(u.id) != dsts->end()) {
                for(PortSet::iterator it = (*dsts)[u.id].begin();
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

bool
MC_routing_module::get_multicast_tree(const ipaddr& src, 
                                      const ipaddr& group,
                                      AdjListPtr& tree,
                                      DstPortMapPtr& dsts) 
{
    VLOG_DBG(log, "Get multicast tree");
    if(get_multicast_source_tree(src, group, tree, dsts)) {
        print_graph(tree, 1);
        return true;
    } else if(get_multicast_shared_tree(group, tree, dsts)) {
        print_graph(tree, 2);
        return true;
    }
    return false;
}

bool
MC_routing_module::get_route_source_tree(const ipaddr& saddr,
                                       const AdjListPtr& mctree,
                                       network::route& route,
                                       Src2TreeListPtr& stot)
{
    hostiptracker::location sloc = hit->get_latest_location(saddr);    
    if(sloc.dpid.empty()) return false;
    
    route.in_switch_port.dpid = sloc.dpid;
    route.in_switch_port.port = sloc.port;
    
    datapathid src = sloc.dpid;
    datapathid dst;
    Linkweight max = (Linkweight){Linkweight::MAX_INT, Linkweight::MAX_INT};
    for(AdjList::iterator it = mctree->begin(); it != mctree->end(); it++) {
        Routing_module::RoutePtr rte;
        bool bIsOK = routing->get_route((RouteId){src, it->first}, rte);   
        if(bIsOK && max > rte->weight) {
            dst = it->first;
            max = rte->weight;
        }
    }
    
    if(dst.empty()) return false;   
    
    stot = (Src2TreeListPtr) new Src2TreeList;
    network::hop* rp = &route;
    Routing_module::RoutePtr rte;
    routing->get_route((RouteId){src, dst}, rte);    
    datapathid dpsrc = src, dpdst;
    for(std::list<Routing_module::Link>::iterator l_it = rte->path.begin(); l_it != rte->path.end(); l_it++) {
        dpdst = l_it->dst;
        bool last = (mctree->find(dpdst) != mctree->end());
        (*stot)[dpsrc] = (NextHop){dpdst, l_it->outport, last};
        network::hop* newhop = new network::hop(dpdst, l_it->inport);
        rp->next_hops.push_front(std::make_pair(l_it->outport, newhop)); 
        rp = newhop;
        dpsrc = dpdst;
    }
    
    return true;
}

bool
MC_routing_module::get_multicast_source_tree(const ipaddr& src, 
                                             const ipaddr& group,
                                             AdjListPtr& tree,
                                             DstPortMapPtr& dsts) 
{    
    if(mt_map.find(group) == mt_map.end() ||
        mt_map[group].srcs->find(src) == mt_map[group].srcs->end() ) {
        return false;
    }
    VLOG_DBG(log, "Get multicast source tree %s %s", group.string().c_str(), src.string().c_str());
    tree = (*(mt_map[group].srcs))[src].tree;
    dsts = (DstPortMapPtr) new DstPortMap;
    for(DstPortMap::iterator it = mt_map[group].dsts->begin();
        it != mt_map[group].dsts->end(); it++) {
        if(dsts->find(it->first) == dsts->end()) 
            (*dsts)[it->first] = PortSet();
        (*dsts)[it->first].insert(it->second.begin(), it->second.end());
    }
    for(DstPortMap::iterator it = (*mt_map[group].srcs)[src].dsts->begin();
        it != (*mt_map[group].srcs)[src].dsts->end(); it++) {
        if(dsts->find(it->first) == dsts->end()) 
            (*dsts)[it->first] = PortSet();
        (*dsts)[it->first].insert(it->second.begin(), it->second.end());
    }
    
    return true;
}

bool 
MC_routing_module::get_multicast_shared_tree(const ipaddr& group, 
                                             AdjListPtr& tree,
                                             DstPortMapPtr& dsts)
{
    if(mt_map.find(group) == mt_map.end()) {
        return false;
    }    
    tree = mt_map[group].tree;
    dsts = (DstPortMapPtr) new DstPortMap;
    for(DstPortMap::iterator it = mt_map[group].dsts->begin();
        it != mt_map[group].dsts->end(); it++) {
        if(dsts->find(it->first) == dsts->end()) 
            (*dsts)[it->first] = PortSet();
        (*dsts)[it->first].insert(it->second.begin(), it->second.end());
    }
    
    return true;
}

bool 
MC_routing_module::has_multicast_route(ipaddr group, ipaddr src)
{
    if(has_multicast_route(group)) 
        return mt_map[group].srcs->find(src) != mt_map[group].srcs->end();
    return false;
}

size_t 
MC_routing_module::get_multicast_dst_size(ipaddr group, ipaddr src)
{
    if(has_multicast_route(group, src))
        return (*mt_map[group].srcs)[src].dsts->size();
    return 0;
}
    
bool 
MC_routing_module::has_multicast_route(ipaddr group)
{
    return mt_map.find(group) != mt_map.end();
}
 
size_t 
MC_routing_module::get_multicast_dst_size(ipaddr group)
{
    if(has_multicast_route(group))
        return mt_map[group].dsts->size();
    return 0;
}

Disposition
MC_routing_module::handle_group_event(const Event& e)
{
    const Group_event& ge = assert_cast<const Group_event&>(e);
    
    DstPortMapPtr dsts, sdsts;
    AdjListPtr tree;
    MulticastSrcMapPtr srcs;
    VLOG_DBG(log, "Handle group event %s, %s, %d", 
             ge.group.string().c_str(), ge.src.string().c_str(), ge.action);
    if( ge.action == Group_event::ADD ) { 
        if(ge.src.addr == 0) {
            add_multicast_route(ge.group); 
        } else {
            if(get_multicast_route(ge.group, dsts, tree, srcs)) {  
                add_multicast_source(ge.src, srcs);
                if(get_multicast_source(ge.src, srcs, sdsts, tree)) {                    
                    if(add_dst_port(sdsts, ge.dp, ge.port))
                        update_multicast_source_tree(tree, dsts, sdsts, ge.src); 
                }
            }
        }
    } else if( ge.action == Group_event::REMOVE ) { 
        if(ge.src.addr == 0) {
            remove_multicast_route(ge.group);
        } else {
            if(get_multicast_route(ge.group, dsts, tree, srcs)) {
                if(get_multicast_source(ge.src, srcs, sdsts, tree)) {
                    if(remove_dst_port(sdsts, ge.dp, ge.port)) {
                        update_multicast_source_tree(tree, dsts, sdsts, ge.src);
                    }
                }
                remove_multicast_source(ge.src, srcs);
            }
        }
    } else if( ge.action == Group_event::TOEXCLUDE ) {
        if(ge.src.addr == 0) {
            if(get_multicast_route(ge.group, dsts, tree, srcs)) {  
                if(add_dst_port(dsts, ge.dp, ge.port)) {
                    update_multicast_shared_tree(tree, dsts);
                    for(MulticastSrcMap::iterator msm_it = srcs->begin(); msm_it != srcs->end(); msm_it++) {
                        get_multicast_source(msm_it->first, srcs, sdsts, tree);
                        if(sdsts->find(ge.dp) == sdsts->end()) 
                            update_multicast_source_tree(tree, dsts, sdsts, ge.src);
                    }
                }
            }
        }
    } else if( ge.action == Group_event::TOINCLUDE ) {
        if(ge.src.addr == 0) {
            if(get_multicast_route(ge.group, dsts, tree, srcs)) { 
                if(remove_dst_port(dsts, ge.dp, ge.port)) {
                    update_multicast_shared_tree(tree, dsts);
                    for(MulticastSrcMap::iterator msm_it = srcs->begin(); msm_it != srcs->end(); msm_it++) {
                        get_multicast_source(msm_it->first, srcs, sdsts, tree);
                        if(sdsts->find(ge.dp) == sdsts->end()) 
                            update_multicast_source_tree(tree, dsts, sdsts, ge.src);
                    }
                }
            }
        }
    }
    
    return CONTINUE;
}

Disposition 
MC_routing_module::handle_linkpw_change(const Event& e)
{
    const Linkpw_event& le = assert_cast<const Linkpw_event&>(e);
    if(le.action != Linkpw_event::REMOVE) return CONTINUE; 

    DstPortMapPtr dsts, sdsts;
    AdjListPtr tree;
    MulticastSrcMapPtr srcs;
    
    for(MulticastTreeMap::iterator mm_it = mt_map.begin();
        mm_it != mt_map.end(); mm_it++) {
        get_multicast_route(mm_it->first, dsts, tree, srcs);
        if(is_link_changed(tree, le)) 
            update_multicast_shared_tree(tree, dsts);

        for(MulticastSrcMap::iterator msm_it = srcs->begin(); msm_it != srcs->end(); msm_it++) {
            get_multicast_source(msm_it->first, srcs, sdsts, tree);
            if(is_link_changed(tree, le)) 
                update_multicast_source_tree(tree, dsts, sdsts, msm_it->first);
        }
    }

    return CONTINUE;    
}

bool 
MC_routing_module::is_link_changed(const AdjListPtr& tree, const Linkpw_event& le)
{
    if( tree->find(le.dpsrc) != tree->end() ) {
        if( (*tree)[le.dpsrc].find(le.dpdst) != (*tree)[le.dpsrc].end() ) {
            if( (*tree)[le.dpsrc][le.dpdst].srcport == le.sport &&
                (*tree)[le.dpsrc][le.dpdst].dstport == le.dport)
                return true;
        }
    }
    return false;
}

bool 
MC_routing_module::get_multicast_route(const ipaddr g, DstPortMapPtr& dsts, AdjListPtr& tree, MulticastSrcMapPtr& srcs)
{
    if(mt_map.find(g) != mt_map.end()) {
        dsts = mt_map[g].dsts;
        tree = mt_map[g].tree;
        srcs = mt_map[g].srcs;
        return true;
    }
    return false;
}

void 
MC_routing_module::add_multicast_route(const ipaddr g)
{
    if(mt_map.find(g) == mt_map.end()) {
        VLOG_DBG(log, "Add multicast route %s", g.string().c_str());
        DstPortMapPtr dsts = (DstPortMapPtr) new DstPortMap;
        AdjListPtr tree = (AdjListPtr) new AdjList;
        MulticastSrcMapPtr srcs = (MulticastSrcMapPtr) new MulticastSrcMap; 
        mt_map[g] = (MulticastRoute){srcs, dsts, tree};
    } 
}

void 
MC_routing_module::remove_multicast_route(const ipaddr g)
{
    if(mt_map.find(g) != mt_map.end()) {          
        if(mt_map[g].dsts->size()==0 &&
            mt_map[g].srcs->size()==0) {
            VLOG_DBG(log, "Remove multicast route %s", g.string().c_str());
            mt_map.erase(g);
        }
    } 
}

bool 
MC_routing_module::get_multicast_source(const ipaddr src, MulticastSrcMapPtr& srcs, DstPortMapPtr& dsts, AdjListPtr& tree)
{
    if(srcs->find(src) != srcs->end()) {
        dsts = (*srcs)[src].dsts;
        tree = (*srcs)[src].tree;
        return true;
    }
    return false;
}

void 
MC_routing_module::add_multicast_source(const ipaddr src, MulticastSrcMapPtr& srcs)
{
    if(srcs->find(src) == srcs->end()) {
        DstPortMapPtr dsts = (DstPortMapPtr) new DstPortMap;
        AdjListPtr tree = (AdjListPtr) new AdjList;
        (*srcs)[src] = (MulticastSrc){dsts, tree};
    }
}

void 
MC_routing_module::remove_multicast_source(const ipaddr src, MulticastSrcMapPtr& srcs)
{
    if(srcs->find(src) != srcs->end() && 
        ((*srcs)[src].dsts->size()==0)) {
        srcs->erase(src);
    }
}

bool 
MC_routing_module::add_dst_port(DstPortMapPtr& dsts, const datapathid& dpid, const uint16_t port) const
{
    bool bNeedUpdated = false;
    if(dsts->find(dpid) == dsts->end()) {
        (*dsts)[dpid] = PortSet();
        bNeedUpdated = true;
    }
    (*dsts)[dpid].insert(port); 
    return bNeedUpdated;
}

bool
MC_routing_module::remove_dst_port(DstPortMapPtr& dsts, const datapathid& dpid, const uint16_t port) const
{
    bool bNeedUpdated = false;
    if(dsts->find(dpid) == dsts->end()) {
        VLOG_DBG(log, "Remove unknown port %"PRIx16" of switch %"PRIx64" ", port, dpid.as_host());
        return bNeedUpdated;
    }
    (*dsts)[dpid].erase(port);
    if((*dsts)[dpid].size() == 0) {
        dsts->erase(dpid);
        bNeedUpdated = true;
    }
    
    return bNeedUpdated;
}

bool
MC_routing_module::update_multicast_source_tree(AdjListPtr& mctree, const DstPortMapPtr& dsts, const DstPortMapPtr& sdsts, const ipaddr& src) 
{
    if(dsts->size()==0 && sdsts->size()==0){
        mctree->clear();
        return true;
    }
    VLOG_DBG(log, "Update multicast source tree src");
    
    DstSetPtr dsp = (DstSetPtr) new DstSet;

    DstPortMap::iterator it;
    for(it = dsts->begin(); it != dsts->end(); it++) dsp->insert(it->first);
    for(it = sdsts->begin(); it != sdsts->end(); it++) dsp->insert(it->first);
    
    return kmb_approximation_algorithm(mctree, dsp);
}

bool
MC_routing_module::update_multicast_shared_tree(AdjListPtr& mctree, const DstPortMapPtr& dsts) 
{
    if(dsts->size()==0){
        mctree->clear();
        return true;
    }
    VLOG_DBG(log, "Update multicast shared tree");
    DstSetPtr dsp = (DstSetPtr) new DstSet;
    for(DstPortMap::iterator it = dsts->begin(); it != dsts->end(); it++) 
        dsp->insert(it->first);
            
    return kmb_approximation_algorithm(mctree, dsp);
}

bool
MC_routing_module::kmb_approximation_algorithm(AdjListPtr& mctree, const DstSetPtr& dsp) 
{
    AdjListPtr subgraph, mintree;
    RouteDirection rd;
 
    VLOG_DBG(log, "KMB approximation algorithm");
    if(!complete_subgraph(subgraph, dsp, rd)) return false;
    mintree = minimum_spanning_tree(subgraph);
    subgraph = reverse_mintree(mintree, rd); 
    mintree = minimum_spanning_tree(subgraph);
    fixup_leaves(mctree, mintree, dsp);
    for(DstSet::iterator it = dsp->begin(); it != dsp->end(); it++) {
        if(mctree->find(*it) == mctree->end()) {
            (*mctree)[*it] = AdjListNode();
        }
    }
    print_graph(mctree, 0);
    return true;
}

bool
MC_routing_module::complete_subgraph(AdjListPtr& subgraph, const DstSetPtr& dsp, RouteDirection& rd)
{
    subgraph = (AdjListPtr) new AdjList();    
    
    for(DstSet::iterator src_it = dsp->begin(); src_it != dsp->end(); src_it++) { 
        for(DstSet::iterator dst_it = src_it; dst_it != dsp->end(); dst_it++) {
            if(*src_it == *dst_it) continue;
            Routing_module::RoutePtr route1, route2;
            bool bIsOK1 = routing->get_route((RouteId){*src_it, *dst_it}, route1);
            bool bIsOK2 = routing->get_route((RouteId){*dst_it, *src_it}, route2);
            
            if(bIsOK1 && bIsOK2) {
                if(route1->weight >= route2->weight) {
                    rd.insert((RouteId){*src_it, *dst_it});  
                    (*subgraph)[*src_it][*dst_it] = 
                        (Link){route1->path.front().outport, route1->path.back().inport, route1->weight};
                    (*subgraph)[*dst_it][*src_it] = 
                        (Link){route1->path.back().inport, route1->path.front().outport, route1->weight};
                } else {
                    rd.insert((RouteId){*dst_it, *src_it});
                    (*subgraph)[*dst_it][*src_it] = 
                        (Link){route2->path.front().outport, route2->path.back().inport, route2->weight};
                    (*subgraph)[*src_it][*dst_it] = 
                        (Link){route2->path.front().inport, route2->path.back().outport, route2->weight};
                }
                
            } else {
                return false;
            }
        }
    }
    return true;
}

MC_routing_module::AdjListPtr
MC_routing_module::minimum_spanning_tree(const AdjListPtr& graph)
{
    AdjListPtr tree = (AdjListPtr) new AdjList();
    
    if(graph->size() == 0) return tree;
    
    MinHeap mh(graph);
    
    while(!mh.isEmpty()) {
        MinHeapNodePtr minNode = mh.extractMin();
        datapathid u = minNode->dpid;
        datapathid p = mh.getParent(u);
        if(!p.empty()) {
            (*tree)[p][u] = (Link){(*graph)[p][u].srcport, (*graph)[p][u].dstport, (*graph)[p][u].weight};
            (*tree)[u][p] = (Link){(*graph)[u][p].srcport, (*graph)[u][p].dstport, (*graph)[u][p].weight};
        }
        
        for(AdjListNode::iterator aln_it = (*graph)[u].begin(); aln_it != (*graph)[u].end(); aln_it++) {
            datapathid v = aln_it->first;
            if(mh.isInMinHeap(v) && aln_it->second.weight < mh.getKey(v)) {                
                mh.decreaseKey(v, aln_it->second.weight);
                mh.setParent(u, v);
            }
        }
    }
    return tree;
}

MC_routing_module::AdjListPtr
MC_routing_module::reverse_mintree(const AdjListPtr& tree, const RouteDirection& rd)
{
    AdjListPtr subgraph = (AdjListPtr) new AdjList();
    
    if(tree->size() == 0) return subgraph;
    
    for(AdjList::iterator al_it = tree->begin(); al_it != tree->end(); al_it++) {
        for(AdjListNode::iterator aln_it = al_it->second.begin(); aln_it != al_it->second.end(); aln_it++) {
            if(al_it->first >= aln_it->first) continue;
            datapathid src, dst;
            if(rd.find((RouteId){al_it->first, aln_it->first}) != rd.end()) {
                src = al_it->first;
                dst = aln_it->first;
            } else {
                src = aln_it->first;
                dst = al_it->first;
            }
            Routing_module::RoutePtr route;
            bool bIsOK = routing->get_route((RouteId){src, dst}, route);
            if(bIsOK) {                
                src = route->id.src;
                for(std::list<Routing_module::Link>::iterator l_it = route->path.begin(); l_it != route->path.end(); l_it++) {
                    dst = l_it->dst;
                    AdjList::iterator ssub_it = subgraph->find(src);
                    if(ssub_it == subgraph->end()) (*subgraph)[src] = AdjListNode();                   
                    (*subgraph)[src][dst] = (Link){l_it->outport, l_it->inport, l_it->weight};
                    AdjList::iterator dsub_it = subgraph->find(dst);
                    if(dsub_it == subgraph->end()) (*subgraph)[dst] = AdjListNode();                       
                    (*subgraph)[dst][src] = (Link){l_it->inport, l_it->outport, l_it->weight};                    
                    src = dst;
                }
            }            
        }        
    }
    
    return subgraph;
}

void 
MC_routing_module::fixup_leaves(AdjListPtr& mctree, const AdjListPtr& mintree, const DstSetPtr& dsp)
{
    std::queue<datapathid> leaves;
    
    mctree->clear();
    for(AdjList::iterator al_it = mintree->begin(); al_it != mintree->end(); al_it++) {
        (*mctree)[al_it->first] = al_it->second;
        if(al_it->second.size() == 1 && dsp->find(al_it->first) == dsp->end()) 
            leaves.push(al_it->first);
    }
    
    while(!leaves.empty()) {
        datapathid u = leaves.front();
        leaves.pop();
        for(AdjListNode::iterator vit = (*mctree)[u].begin(); vit != (*mctree)[u].end(); vit++) {
            datapathid v = vit->first;                
            (*mctree)[v].erase(u);
            if((*mctree)[v].size() == 1 && dsp->find(v) == dsp->end())
                leaves.push(v);
        }
        mctree->erase(u);
    }
}

void 
MC_routing_module::print_graph(const AdjListPtr& graph, int reason)
{
    const char* p = NULL;
    if(reason == 0)  p = "After updated tree";
    else if(reason == 1)  p = "Get source tree";
    else if(reason == 2)  p = "Get shared tree";
    VLOG_DBG(log, "%s, print graph, node size = %u", p, graph->size());
    for(AdjList::iterator al_it = graph->begin(); al_it != graph->end(); al_it++) {
        if(al_it->second.size() == 0) continue;
        for(AdjListNode::iterator aln_it = al_it->second.begin(); aln_it != al_it->second.end(); aln_it++) {
            VLOG_DBG(log, "src=%"PRIx64", dst=%"PRIx64" weight=%s", 
                     al_it->first.as_host(), aln_it->first.as_host(), aln_it->second.weight.string().c_str());
        }
    }
}

REGISTER_COMPONENT(container::Simple_component_factory<MC_routing_module>, MC_routing_module);

}
} // unnamed namespace
