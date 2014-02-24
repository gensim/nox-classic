#ifndef hostiptracker_HH
#define hostiptracker_HH

#include "component.hh"
#include "config.h"
#include "netinet++/ipaddr.hh"
#include "netinet++/datapathid.hh"
#include "hash_map.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

/** Default number of host locations to store per host
 */
#define DEFAULT_HOSTIP_N_BINDINGS 1
/** Default host timeout (5 min)
 */
#define DEFAULT_HOSTIP_TIMEOUT 300

namespace vigil
{
  using namespace std;
  using namespace vigil::container;

  struct Host_location_event;

  /** \brief hostiptracker: Track locations of host (ipaddr)
   * \ingroup noxcomponents
   * 
   * Track last n known locations of host ip attachment.
   */
  class hostiptracker
    : public Component 
  {
  public:
    /** Struct to hold host location.
     */
    struct location
    {
      /** Constructor
       * @param dpid switch datapath id
       * @param port port of switch host is connected to
       * @param tv time of connection/detection
       */
      location(datapathid dpid, uint16_t port, time_t tv);

      /** Empty Constructor
       */
      location():
	dpid(datapathid()), port(0)
      {};

      /** Set value of location
       * @param loc location to copy value from
       */
      void set(const location& loc);

      /** Switch host is located on
       */
      datapathid dpid;
      /** Port host is attached to.
       */
      uint16_t port;
      /** Last known active time
       */
      time_t lastTime;
    };

    /** Host timeout (in s)
     */
    uint16_t hostTimeout;
    /** Default number of bindings to store
     */
    uint8_t defaultnBindings;
    /** Number of binding to store
     */
    hash_map<ipaddr,uint8_t> nBindings;

    /** \brief Constructor of hostiptracker.
     *
     * @param c context
     * @param node XML configuration (JSON object)
     */
    hostiptracker(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Check host timeout 
     */
    void check_timeout();

    /** \brief Find oldest host.
     * @return ethernet address of host with earliest timeout
     */
    const ipaddr oldest_host();

    /** \brief Get number of binding host can have.
     * @param host host as identified by ethernet address
     * @return number of bindings host can have
     */
    uint8_t getBindingNumber(ipaddr host);

    /** \brief Retrieve location of host
     * @param host host as identified by ethernet address
     * @return list of location(s)
     */
    const list<location> getLocations(ipaddr host);

    /** \brief Set location.
     * @param host host as identified by ethernet address
     * @param loc location host is detected
     * @param postEvent indicate if Host_location_event should be posted
     */
    void add_location(ipaddr host, location loc, bool postEvent=true);

    /** \brief Set location.
     * @param host host as identified by ethernet address
     * @param dpid switch datapath id
     * @param port port of switch host is connected to
     * @param tv time of connection/detection (default to 0 == now)
     * @param postEvent indicate if Host_location_event should be posted
     */
    void add_location(ipaddr host, datapathid dpid, uint16_t port,
		      time_t tv=0, bool postEvent=true);

    /** \brief Unset location
     * @param host host as identified by ethernet address
     * @param dpid switch datapath id
     * @param port port of switch host is connected to
     * @param postEvent indicate if Host_location_event should be posted
     */
    void remove_location(ipaddr host, datapathid dpid, uint16_t port,
			 bool postEvent=true);

    /** \brief Unset location
     * @param host host as identified by ethernet address
     * @param loc location host is detached from
     * @param postEvent indicate if Host_location_event should be posted
     */
    void remove_location(ipaddr host, location loc,
			 bool postEvent=true);

    /** \brief Get locations
     * @param host ethernet address of host
     * @return locations
     */
    const list<location> get_locations(ipaddr host);

    /** \brief Get latest location
     * @param host ethernet address of host
     * @return location (with empty datapath id if no binding found)
     */
    const location get_latest_location(ipaddr host);

    /** \brief Get all hosts
     * @return list of all host mac
     */
    const list<ipaddr> get_hosts();

    /** \brief Configure hostiptracker.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Start hostiptracker.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of hostiptracker.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
			    hostiptracker*& component);

  private:
    /** Ethernet address to location mapping.
     */
    hash_map<ipaddr,list<location> > hostlocation;

    /** Get oldest location.
     * @param loclist location list
     * @return pointer to oldest item
     */
    list<location>::iterator get_oldest(list<location>& loclist);

    /** Get newest location.
     * @param loclist location list
     * @return pointer to newest item
     */
    list<location>::iterator get_newest(list<location>& loclist);
  };

  /** \ingroup noxevents
   * \brief Structure to hold host and location change
   */
  struct HostIP_location_event : public Event
  {
    /** \brief Type of host-location event
     */
    enum type
    {
      ADD,
      REMOVE,
      MODIFY
    };

    /** \brief Constructor
     * @param host_ mac address of host
     * @param loc_ location of host
     * @param type_ type of event
     */
    HostIP_location_event(const ipaddr host_,
			const list<hostiptracker::location> loc_,
			enum type type_);

    /** For use within python.
     */
    HostIP_location_event() : Event(static_get_name()) 
    { }

    /** Static name required in NOX.
     */
    static const Event_name static_get_name() 
    {
      return "HostIP_location_event";
    }

    /** Reference to host
     */
    ipaddr host;
    /** Current/New location of host
     */
    list<hostiptracker::location> loc;
    /** Type of event
     * @see #type
     */
    enum type eventType;
  };
}

#endif
