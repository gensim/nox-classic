#ifndef MCROUTEINSTALLER_HH__
#define MCROUTEINSTALLER_HH__

#include "network_graph.hh"
#include "openflow/openflow.h"
#include "openflow-pack.hh"
#include "openflow-action.hh"
#include "hash_map.hh"
#include "multicast_routing.hh"

namespace vigil 
{
  using namespace std;
  using namespace vigil;
  using namespace vigil::container;    
  using namespace vigil::applications;
 
  /** \brief Class to install route.
   * \ingroup noxcomponents
   * 
   * Routes are installed in the reverse order, so as to prevent
   * multiple packet in per flow.  This is not bullet-proof but
   * is better than installing it the forward manner at least.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date February 2009
   */
  class mcrouteinstaller
    : public Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node JSON object
     */
    mcrouteinstaller(const Context* c,const json_object* node) 
      : Component(c) 
    {}
    
    /** Destructor.
     */
    virtual ~mcrouteinstaller()
    { ; }

    /** Configure component
     * @param config configuration
     */
    void configure(const Configuration* config);

    /** Start component.
     */
    void install();

    /** Get instance (for python)
     * @param ctxt context
     * @param scpa reference to return instance with
    */
    static void getInstance(const container::Context*, 
			    vigil::mcrouteinstaller*& scpa);
    
    void install_route(const ipaddr src, 
                       const ipaddr group,
                       uint32_t buffer_id=-1, 
                       uint16_t idletime=DEFAULT_FLOW_TIMEOUT, 
                       uint16_t hardtime=0);                    
                        
    void remove_route(const ipaddr src, 
                      const ipaddr group);
                       
    void install_block(const ipaddr src, 
                       const ipaddr group,
                       const datapathid& dpid,
                       uint16_t in_port,
                       uint16_t idletime=DEFAULT_FLOW_TIMEOUT, 
                       uint16_t hardtime=0);
                       
    void remove_block(const ipaddr src,
                      const ipaddr group);
                       
  private:
      
    Disposition handle_group_event(const Event& e);
    Disposition handle_pkt_in(const Event& e);
    Disposition handle_flow_removed(const Event& e);
    
    void real_install_route(const ipaddr src, const ipaddr group, network::route route, uint32_t buffer_id,
                            hash_map<datapathid,ofp_action_list>& actions, bool removedmsg, 
                            uint16_t idletime, uint16_t hardtime);
                             
    bool add_routing_table_entry(const ipaddr src, const ipaddr group, network::route route, hash_map<datapathid,ofp_action_list>& act_list);
    bool delete_routed_table_entry(const ipaddr src, const ipaddr group, datapathid& dpid, uint64_t& cookie);
    bool add_blocking_table_entry(const ipaddr src, const ipaddr group, const datapathid dpid);
    bool delete_blocked_table_entry(const ipaddr src, const ipaddr group,  datapathid& dpid);
    
    void install_routing_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group, uint16_t in_port, ofp_action_list act_list, uint32_t buffer_id, uint64_t cookie, bool removedmsg, uint16_t idletime, uint16_t hardtime);                               
    void remove_routing_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group);                            
    void install_blocking_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group, uint16_t in_port, uint16_t idletime, uint16_t hardtime);                                      
    void remove_blocking_flow_entry(const datapathid dpid, const ipaddr src, const ipaddr group);
    
    void forward_routed_flow(const datapathid dpid, const ipaddr src, const ipaddr group, uint16_t in_port, ofp_action_list act_list, uint32_t buffer_id);
    void forward_routed_flow(const datapathid dpid, const ipaddr src, const ipaddr group, uint16_t in_port, ofp_action_list act_list, const Buffer& buf);
    
    typedef struct {
        datapathid dpsrc;
        uint64_t cookie;
        hash_map<datapathid,ofp_action_list> act;
    } RoutedRule;
    
    typedef hash_map<ipaddr, RoutedRule> SrcRoutedRuleMap;
    typedef hash_map<ipaddr, SrcRoutedRuleMap> GroupRoutedRuleMap;
    
    typedef hash_map<ipaddr, datapathid> SrcBlockedRuleMap;
    typedef hash_map<ipaddr, SrcBlockedRuleMap> GroupBlockedRuleMap;
    
    GroupRoutedRuleMap grr_map;
    GroupBlockedRuleMap gbr_map;  
    /** Reference to multicast routing module.
     */
    MC_routing_module* mcrouting;
    
    /** Buffer for openflow message.
     */
    boost::shared_array<uint8_t> of_raw;

  };
  
} // namespace vigil

#endif 
