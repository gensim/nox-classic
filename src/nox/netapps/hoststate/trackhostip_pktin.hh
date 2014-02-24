#ifndef trackhostip_pktin_HH
#define trackhostip_pktin_HH

#include "component.hh"
#include "config.h"
#include "hostiptracker.hh"
#include "topology/topology.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace std;
  using namespace vigil::container;
  using namespace vigil::applications;

  /** \brief trackhostip_pktin: Tracks host ip location using packet in
   * \ingroup noxcomponents
   */
  class trackhostip_pktin
    : public Component 
  {
  public:
    /** \brief Constructor of trackhostip_pktin.
     *
     * @param c context
     * @param node configuration (JSON object)
     */
    trackhostip_pktin(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Handle packet in to register host location
     * @param e packet in event
     * @return CONTINUE
     */
    Disposition handle_pkt_in(const Event& e);

    /** \brief Configure trackhostip_pktin.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Start trackhostip_pktin.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of trackhostip_pktin.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
			    trackhostip_pktin*& component);

  private:
    /** Reference to topology
     */
    Topology* topo;
    /** Reference to hosttracker
     */
    hostiptracker* hit;
  };
}

#endif
