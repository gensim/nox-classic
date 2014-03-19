#ifndef MULTICAST_ROUTING_HH
#define MULTICAST_ROUTING_HH

#include "component.hh"
#include "hash_map.hh"
#include "hash_set.hh"
#include "network_graph.hh"
#include "routing/routing.hh"
#include "topology/topology.hh"
#include "hoststate/hostiptracker.hh"

namespace vigil {
namespace applications {

class MC_routing_module : public container::Component 
{
public:  
    typedef struct {
        uint16_t srcport;
        uint16_t dstport;
        Linkweight weight;
    } Link;
    typedef hash_map<datapathid, Link> AdjListNode;
    typedef hash_map<datapathid, AdjListNode> AdjList; 
    typedef boost::shared_ptr<AdjList> AdjListPtr; 
    typedef hash_set<uint16_t> PortSet;
    typedef hash_map<datapathid, PortSet> DstPortMap;
    typedef boost::shared_ptr<DstPortMap> DstPortMapPtr; 
    
    MC_routing_module(const container::Context* c, const json_object*); 
    ~MC_routing_module() {}

    void configure(const container::Configuration*);

    void install();

    static void getInstance(const container::Context* c, MC_routing_module*& component);
    
    bool get_source_location(const ipaddr& src, network::route& route);
    
    bool get_multicast_tree(const ipaddr& src, const ipaddr& group, 
                            AdjListPtr& tree, DstPortMapPtr& dsts);
    
    bool get_multicast_source_tree(const ipaddr& src, const ipaddr& group, 
                                   AdjListPtr& tree, DstPortMapPtr& dsts);
    
    bool get_multicast_shared_tree(const ipaddr& src, const ipaddr& group, 
                                   AdjListPtr& tree, DstPortMapPtr& dsts);
                                   
    bool has_multicast_route(ipaddr group, ipaddr src);
    
    bool has_multicast_route(ipaddr group);

    size_t get_multicast_dst_size(ipaddr group);

private:
  
    typedef struct {
        datapathid dpid;
        uint16_t port;        
    } SrcInfo;
    
       
    typedef hash_set<datapathid> DstSet;
    typedef boost::shared_ptr<DstSet> DstSetPtr;
       
    typedef Routing_module::RouteId RouteId;    
    typedef hash_set<RouteId, Routing_module::ridhash, Routing_module::rideq> RouteDirection;
    typedef hash_set<ipaddr> GroupSet;
    typedef hash_map<ipaddr, GroupSet> SrcGroupMap;
    
    typedef struct { 
        DstPortMapPtr dsts;
        AdjListPtr tree;
        bool updated;
    } MulticastSrc;
    
    typedef hash_map<ipaddr, MulticastSrc> MulticastSrcMap;
    typedef boost::shared_ptr<MulticastSrcMap> MulticastSrcMapPtr;
    typedef struct {
        MulticastSrcMapPtr srcs;
        DstPortMapPtr dsts;
        AdjListPtr tree;
        bool updated;
    } MulticastRoute;      
    
    typedef hash_map<ipaddr, MulticastRoute> MulticastTreeMap; 
    
    struct MinHeapNode {
        Linkweight key;
        datapathid dpid;
        uint32_t idx;
    };
    typedef boost::shared_ptr<MinHeapNode> MinHeapNodePtr;
    
    class MinHeap {      
    public:
        MinHeap(AdjListPtr graph) {            
            size = capacity = graph->size();              
            uint32_t i;
            AdjList::iterator al_it;
            for(i = 0, al_it = graph->begin(); al_it != graph->end(); i++, al_it++) {
                MinHeapNodePtr newNode = (MinHeapNodePtr) new MinHeapNode();
                newNode->key = Linkweight(Linkweight::MAX_INT, Linkweight::MAX_INT);
                newNode->dpid = al_it->first;
                newNode->idx = i;
                dps[al_it->first] = newNode;
                pos[i] = newNode;
            }            
            pos[0]->key = Linkweight();
        }
        
        bool isInMinHeap(datapathid u) {
            if(dps[u]->idx < pos.size()) return true;
            return false;
        }
        
        bool isEmpty() {
            return (pos.size() == 0);
        }    
        
        Linkweight getKey(datapathid u) {
            return dps[u]->key;
        }
        
        void setKey(datapathid u, const Linkweight& k) {
            dps[u]->key = k;
        }
        
        MinHeapNodePtr extractMin() {
            assert(!isEmpty());
            
            MinHeapNodePtr root = pos[0];            
            MinHeapNodePtr lastNode = pos[pos.size() - 1];
            swapNode(0, pos.size()-1);       
            pos.erase(pos.size()-1);
            
            minHeapify(0);
            
            return root;
        }
        
        void decreaseKey(datapathid u, Linkweight key) {
            uint32_t i = dps[u]->idx;
            dps[u]->key = key;
            
            while(i && pos[i]->key < pos[(i-1)/2]->key) { 
                swapNode(i, (i-1)/2);                
                i = (i-1)/2;
            }
        }
    private:
        void minHeapify(uint32_t idx) {
            uint32_t smallest, left, right;
            smallest = idx;
            left = 2 * idx + 1;
            right = 2 * idx + 2;
            
            if(left < pos.size() && pos[left]->key < pos[smallest]->key) smallest = left;
            if(right < pos.size() && pos[right]->key < pos[smallest]->key) smallest = right;
            
            if(smallest != idx) {
                swapNode(smallest, idx);                
                minHeapify(smallest);
            }
        }
        
        void swapNode(uint32_t a, uint32_t b) {
            MinHeapNodePtr t = pos[a];
            pos[a] = pos[b];
            pos[b] = t;
            
            pos[a]->idx = a;
            pos[b]->idx = b;
        }
        
        typedef hash_map<datapathid, MinHeapNodePtr> DpMap;
        typedef hash_map<uint32_t, MinHeapNodePtr> PosMap;
        uint32_t size;
        uint32_t capacity;
        PosMap pos;
        DpMap dps;
    };
    
    SrcGroupMap sg_map;
    MulticastTreeMap mt_map;
    Routing_module *routing;
    hostiptracker *hit;   
    
    Disposition handle_group_event(const Event& e);
    Disposition handle_hostip_location(const Event& e);
    
    bool get_multicast_route(const ipaddr g, DstPortMapPtr& dsts, AdjListPtr& tree, MulticastSrcMapPtr& srcs);
    void add_multicast_route(const ipaddr g);
    void remove_multicast_route(const ipaddr g);
    bool get_multicast_source(const ipaddr src, MulticastSrcMapPtr& srcs, DstPortMapPtr& dsts, AdjListPtr& tree);
    void add_multicast_source(const ipaddr src, MulticastSrcMapPtr& srcs);
    void remove_multicast_source(const ipaddr src, MulticastSrcMapPtr& srcs);
    
    bool add_dst_port(DstPortMapPtr& dsts, const datapathid& dpid, const uint16_t port) const;
    bool remove_dst_port(DstPortMapPtr& dsts, const datapathid& dpid, const uint16_t port) const;
    
    void add_source_group(const ipaddr g, const ipaddr src, const MulticastSrcMapPtr& srcs);
    void remove_source_group(const ipaddr g, const ipaddr src, const MulticastSrcMapPtr& srcs);
    
    bool update_multicast_source_tree(AdjListPtr& mctree, const DstPortMapPtr& dsts, const DstPortMapPtr& sdsts, const ipaddr& src);
    bool update_multicast_shared_tree(AdjListPtr& mctree, const DstPortMapPtr& dsts);
    
    bool kmb_approximation_algorithm(AdjListPtr& mctree, const DstSetPtr& dsp);    
    bool complete_subgraph(AdjListPtr& subgraph, const DstSetPtr& dsp, RouteDirection& rd);
    AdjListPtr minimum_spanning_tree(const AdjListPtr& subgraph);
    AdjListPtr reverse_mintree(const AdjListPtr& tree, const RouteDirection& rd);
    void fixup_leaves(AdjListPtr& mctree, const AdjListPtr& mintree, const DstSetPtr& dsp);
    void print_graph(const AdjListPtr& graph);
};

}
}

#endif  
