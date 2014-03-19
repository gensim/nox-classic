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
    /** \brief Post flow record or not
     */
    bool post_flow_record;
    
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
    
    void install_route(const ipaddr& src, 
                       const ipaddr& group,
                       uint32_t buffer_id=-1,  
                       uint16_t idletime=DEFAULT_FLOW_TIMEOUT,
                       uint16_t hardtime=0);

  private:
      
    Disposition handle_group_event(const Event& e);
    Disposition handle_pkt_in(const Event& e);
    Disposition handle_flow_removed(const Event& e);
    
    bool get_multicast_tree_path(const ipaddr& src, const ipaddr& group, network::route& route);
    
    void real_install_route(const ipaddr& src, const ipaddr& group, network::route route, uint32_t buffer_id,
                            hash_map<datapathid,ofp_action_list>& actions, bool removedmsg, uint16_t idletime, uint16_t hardtime);
                            
    void install_flow_entry(const datapathid& dpid, const ipaddr& src, const ipaddr& group, uint32_t buffer_id, 
                            uint16_t in_port, ofp_action_list act_list, uint64_t cookie,
                            bool removedmsg, uint16_t idletime, uint16_t hardtime);                           
      
    typedef struct {
        datapathid parent;
        datapathid id;
        network::hop* nhop;
    } Node;
    typedef std::queue<Node> NodeQueue;
    
    typedef struct {
        datapathid dpsrc;
        uint64_t cookie;
    } InstalledRule;
    
    typedef hash_map<ipaddr, InstalledRule> SrcInstalledRuleMap;
    typedef hash_map<ipaddr, SrcInstalledRuleMap> GroupInstalledRuleMap;
    
    GroupInstalledRuleMap gir_map;
      
    /** Reference to multicast routing module.
     */
    MC_routing_module* mcrouting;
    
    /** Buffer for openflow message.
     */
    boost::shared_array<uint8_t> of_raw;

  };
  
} // namespace vigil

#endif 
