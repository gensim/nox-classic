#ifndef MCROUTEINSTALLER_HH__
#define MCROUTEINSTALLER_HH__

#include "network_graph.hh"
#include "openflow/openflow.h"
#include "openflow-pack.hh"
#include "openflow-action.hh"
#include "hash_map.hh"
#include "multicast_routing.hh"
#include "route/routeinstaller.hh"

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

    /** Get multicast source-based path route.
     * Note that a route for a list of destination is a tree.
     * @param src source
     * @param group group of destination
     * @param route route to populate with source network termination
     * @return if route is found
     */
    bool get_multicast_tree_path(const ipaddr& src, const ipaddr& group, network::route& route);

    /** Install route, i.e., sending the route setup to a set of switches.
     * Throws Route_install_event if desired.
     * @param flow reference to flow to route
     * @param route network route to be installed
     * @param buffer_id id of buffer
     * @param actions list of datapath id and action list pairs
     * @param skipoutput list of datapath id to skip output action
     * @param wildcards wildcard flags
     * @param idletime idle timeout value
     * @param hardtime hard timeout value
     */
    void install_route(const Flow& flow, network::route route, uint32_t buffer_id,
		       hash_map<datapathid,ofp_action_list>& actions,
		       list<datapathid>& skipoutput,
		       uint32_t wildcards=0,
		       uint16_t idletime=DEFAULT_FLOW_TIMEOUT, 
		       uint16_t hardtime=0);

    /** Install route, i.e., sending the route setup to a set of switches.
     * @param flow reference to flow to route
     * @param route network route to be installed
     * @param buffer_id id of buffer
     * @param wildcards wildcard flags
     * @param idletime idle timeout value
     * @param hardtime hard timeout value
     */
    void install_route(const Flow& flow, network::route route, uint32_t buffer_id,
		       uint32_t wildcards=0, 
		       uint16_t idletime=DEFAULT_FLOW_TIMEOUT, 
		       uint16_t hardtime=0);

    /** Install flow entry to switch.
     * @param dpid datapathid of switch to send flow entry to
     * @param flow reference to flow to route
     * @param buffer_id id of buffer
     * @param in_port input port
     * @param act_list list of action to install on top of forwarding
     * @param wildcards wildcard flags
     * @param idletime idle timeout value
     * @param hardtime hard timeout value
     * @param cookie cookie for flow mod
     */
    void install_flow_entry(const datapathid& dpid,
			    const Flow& flow, uint32_t buffer_id, uint16_t in_port,
			    ofp_action_list act_list, uint32_t wildcards=0,
			    uint16_t idletime=DEFAULT_FLOW_TIMEOUT, 
			    uint16_t hardtime=0, uint64_t cookie=0);

  private:
      
    typedef struct {
        datapathid parent;
        datapathid id;
        network::hop* nhop;
    } Node;
    typedef std::queue<Node> NodeQueue;
      
    /** Reference to routeinstaller.
     */
    routeinstaller* ri;

    /** Reference to multicast routing module.
     */
    MC_routing_module* mcrouting;

  };
  
} // namespace vigil

#endif 
