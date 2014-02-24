#ifndef simplemcrouting_HH
#define simplemcrouting_HH

/** Post in flowroute_record or not.
 */
#define SIMPLEMCROUTING_POST_RECORD_DEFAULT false

#include "component.hh"
#include "config.h"
#include "mcrouteinstaller.hh"
#include "route/flowroute_record.hh"

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

  /** \brief simplemcrouting: routing with dependencies on authenticator
   * \ingroup noxcomponents
   *
   * Can choose to set flow installed into flowroute_record with arguments
   * <PRE>
   *    simplemcrouting=postrecord=true
   * </PRE>
   * or
   * <PRE>
   *    simplemcrouting=postrecord=false
   * </PRE>
   *
   * 'cos this is easier to do than understand why authenticator does not
   * register some mac addresses 
   */
  class simplemcrouting
    : public Component 
  {
  public:
    /** \brief Post flow record or not
     */
    bool post_flow_record;

    /** \brief Constructor of simplemcrouting.
     *
     * @param c context
     * @param node XML configuration (JSON object)
     */
    simplemcrouting(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Configure simplemcrouting.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Handle packet in to route
     * @param e packet in event
     * @return CONTINUE always
     */
    Disposition handle_pkt_in(const Event& e);

    /** \brief Start simplemcrouting.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of simplemcrouting.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
			    simplemcrouting*& component);

  private:
    /** Reference to mcrouteinstaller
     */
    mcrouteinstaller* mri;
    /** Reference to flowroute_record
     */
    flowroute_record* frr;
  };
}

#endif
