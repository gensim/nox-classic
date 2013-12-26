#ifndef MULTICAST_ROUTING_HH
#define MULTICAST_ROUTING_HH

#include "component.hh"
#include "hash_map.hh"
#include "hash_set.hh"
#include "routing/routing.hh"
#include "topology/topology.hh"

namespace vigil {
namespace applications {

class MC_routing_module : public container::Component 
{
public:  
    
    MC_routing_module(const container::Context* c, const json_object*); 
    ~MC_routing_module() {}

    void configure(const container::Configuration*);

    void install();

    void getInstance(const container::Context* c, MC_routing_module*& component);

private:
    enum mc_routing_tree_mode {
        MRTM_SHARED,
        MRTM_SOURCE
    };
    
    typedef struct {
        uint16_t srcport;
        uint16_t dstport;
        uint32_t weight;
    } Link;
    
    typedef hash_set<uint16_t> PortSet;
    typedef hash_map<datapathid, PortSet> DestMap;
    typedef boost::shared_ptr<DestMap> DestMapPtr;
    typedef std::list<Link> LinkList;
    typedef hash_map<datapathid, LinkList> AdjListNode;
    typedef hash_map<datapathid, AdjListNode> AdjList;
    typedef boost::shared_ptr<AdjList> AdjListPtr;
    
    typedef struct {
        ipaddr group;
        ipaddr src;
    } MulticastTreeKey;
    
    typedef struct {        
        DestMapPtr dests;
        AdjListPtr mctree;
        mc_routing_tree_mode mode;
    } MulticastTreeVal;
    
    struct mtkhash {
        std::size_t operator()(const MulticastTreeKey& mtk) const;
    };

    struct mtkeq {
        bool operator()(const MulticastTreeKey& a, const MulticastTreeKey& b) const;
    };
    
    typedef boost::shared_ptr<MulticastTreeVal> MulticastTreeValPtr;
    typedef hash_set<ipaddr, Routing_module::RoutePtr> SharedMap;
    typedef hash_map<ipaddr, SharedMap> GroupSharedMap;
    typedef hash_map<MulticastTreeKey, MulticastTreeVal, mtkhash, mtkeq> MulticastTreeMap;
    
    GroupSharedMap gs_map;
    MulticastTreeMap mt_map;
    Topology *topology;
    
    Disposition handle_group_event(const Event& e);
    
    bool find_src(const ipaddr& src) const;
    void calculate_multicast_shared_tree(AdjListPtr& mctree, const DestMapPtr& dests);
    void kmb_approximation_algorithm(AdjListPtr& mctree, const AdjListPtr& graph, const DestMapPtr& dests);
    void get_graph_from_topology(AdjListPtr& graph);
    void get_complete_subgraph(AdjListPtr& subgraph, const AdjListPtr& graph, const DestMapPtr& dests);
};

}
}

#endif  
