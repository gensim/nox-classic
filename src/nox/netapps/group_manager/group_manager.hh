#ifndef GROUP_MANAGER_HH
#define GROUP_MANAGER_HH

#include "component.hh"
#include "hash_map.hh"
#include "hash_set.hh"
#include "topology/topology.hh"

namespace vigil {
namespace applications {

class Group_manager : public container::Component 
{
public:
    
    // Variable
    static const uint32_t ROBUSTNESS;               // IGMP is robust to (ROBUSTNESS -1) packet losses 
    static const uint32_t STARTUP_QUERY_COUNT;      // the number of Queries sent out on startup
    static const uint32_t LAST_MEMBER_QUERY_COUNT;  // the number of Group-Specific Queries sent before the router assume there are no local members

    // Interval
    static const timeval QUERY;                     // between General Queries sent by the Querier                          
    static const timeval QUERY_RESP;                // inserted into the periodic General Queries                           
    static const timeval STARTUP_QUERY;             // the interval between General Queries sent by a Querier on startup    
    static const timeval LAST_MEMBER_QUERY;         // inserted into Group-Specific Queries sent in response to Leave Group messages
    static const timeval GROUP_MEMBERSHIP;          // the amount of time that must pass before a multicast route decides there are no more member of a group on a network
    
    static const ipaddr ALL_HOST_MULTICAST_ADDR;    // 224.0.0.1
    static const ipaddr ALL_ROUTERS_MULTICAST_ADDR; // 224.0.0.2
    static const ipaddr IGMP_V3_REPORT_ADDR;        // 224.0.0.22
    
    Group_manager(const container::Context* c, const json_object*); 
    ~Group_manager() {}

    void configure(const container::Configuration*);

    void install();

    void getInstance(const container::Context* c, Group_manager*& component);

private:
    enum igmp_filter_mode {
        IFM_INCLUDE = 0,
        IFM_EXCLUDE
    };
    
    enum igmp_compatibility_mode {
        ICM_V1 = 0,
        ICM_V2,
        ICM_V3
    };
    
    typedef struct {
        datapathid dp;
        uint16_t port;
    } Interface;
    
    typedef struct {
        datapathid dp;
        uint16_t port;
        ipaddr addr;
    } Group;
      
    struct iphash {
        std::size_t operator()(const ipaddr& ip) const;
    };    

    typedef hash_map<ipaddr, Timer, iphash> SrcTimerMap; 
    typedef hash_set<ipaddr, iphash> SrcTimeoutSet;
    typedef hash_set<ipaddr, iphash> SourceSet;
    
    typedef struct record{
        record() {filter = IFM_INCLUDE; compat = ICM_V3;}
        igmp_filter_mode filter;
        igmp_compatibility_mode compat;
        Timer gm_v1_timer;                      // IGMP Group Member v1 Timer
        Timer gm_v2_timer;                      // IGMP Group Member v2 Timer
        Timer gm_v3_timer;                      // IGMP Group Member v3 Timer                  
        Timer gs_timer;                         // IGMP Group-Specific Query Timer
        Timer gss_timer;                        // IGMP Group-and-Source Specific Query Timer
        SrcTimerMap st_map;                     // Sources
        SrcTimeoutSet st_set;                   // Timeout Sources
    } Record;
    
    struct lochash {
        std::size_t operator()(const Interface& face) const;
    };

    struct loceq {
        bool operator()(const Interface& a, const Interface& b) const;
    };
    
    struct grouphash {
        std::size_t operator()(const Group& g) const;
    };

    struct groupeq {
        bool operator()(const Group& a, const Group& b) const;
    };  
    
    typedef boost::shared_ptr<Record> RecordPtr;
    typedef hash_map<Interface, Timer, lochash, loceq> GeneralQuerierMap; 
    typedef hash_map<Group, RecordPtr, grouphash, groupeq> GroupRecordMap;  
    
    GeneralQuerierMap gq_map;
    GroupRecordMap gr_map;
    Topology *topology;
    
    // event handler
    Disposition handle_igmp(const Event&);    
    Disposition handle_datapath_join(const Event&);    
    Disposition handle_datapath_leave(const Event&);    
    Disposition handle_port_status(const Event&);    
    Disposition handle_link_event(const Event&);    
    
    void process_record_source(const Group& g, SourceSet& ss, const uint8_t type, const igmp_compatibility_mode version);
    
    void start_group_member_timer(const Group& g, const igmp_compatibility_mode version);    
    void v1_group_member_callback(const Group& g);
    void v2_group_member_callback(const Group& g);
    void v3_group_member_callback(const Group& g);
    void start_group_source_timer(const Group& g, const ipaddr& src);    
    void group_source_callback(const Group& g, const ipaddr& src);    

        // startup query function and callback function
    void start_general_query_timer(const Interface& loc);    
    void general_query_callback(const Interface& loc, const uint32_t count);    
    void start_group_specific_query_timer(const Group& g);    
    void group_specific_query_callback(const Group& g, const uint32_t count);    
    void start_group_source_specific_query_timer(const Group& g, const SourceSet& ss);    
    void group_source_specific_query_callback(const Group& g, const SourceSet& ss, const uint32_t count);
    
    // maintain groups and sources
    bool add_group(const Group& g);    
    bool delete_group(const Group& g);    
    bool add_group_source(const Group& g, const ipaddr& src);    
    bool delete_group_source(const Group& g, const ipaddr& src);    
    bool add_group_timeout_source(const Group& g, const ipaddr& src);    
    bool delete_group_timeout_source(const Group& g, const ipaddr& src);
    
    // send IGMP query messages
    void send_general_query(const datapathid& dp, const Port& port);
    void send_group_specific_query(const datapathid& dp, const Port& port, const ipaddr& gaddr);
    void send_group_source_specific_query(const datapathid& dp, const Port& port, const ipaddr& gaddr, const SourceSet& ss);
    
    ethernetaddr get_eth_multicast_addr(uint32_t addr) const;   
    
};

}
}

#endif  
