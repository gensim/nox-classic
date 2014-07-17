#ifndef linkphaseweight_HH
#define linkphaseweight_HH 1

#include "component.hh"
#include "config.h"
#include "hash_map.hh"
#include "netinet++/datapathid.hh"
#include "datapathmem.hh"
#include "linkload.hh"
#include "linkpw-event.hh"
#include <boost/shared_array.hpp>

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#define LINKWIGHT_DEFAULT_INTERVAL LINKLOAD_DEFAULT_INTERVAL
#define LINKWIGHT_DEFAULT_ALPHA 0
#define LINKWIGHT_DEFAULT_PART 10

namespace vigil
{
  using namespace std;
  using namespace vigil::container;
  
  class linkphaseweight
    : public Component 
  {
  public:
      
    struct Link {
        datapathid dpsrc;
        datapathid dpdst;
        uint16_t sport;
        uint16_t dport;
    };
    
    struct linkhash {
        std::size_t operator()(const Link& e) const;
    };

    struct linkeq {
        bool operator()(const Link& a, const Link& b) const;
    };
    
    typedef hash_map<Link, double, linkhash, linkeq> LinkRatioMap;    
    
    LinkRatioMap lr_map;
    
    /** Interval to query for weight
     */
    time_t weight_interval;
    
    /* The parameter to calculate linkweight
     */
    double alpha;
    
    /* The parameter to diff between new ratio and old ratio
     */
    int part;

    /** \brief Constructor of linkphaseweight.
     *
     * @param c context
     * @param node configuration (JSON object) 
     */
    linkphaseweight(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Configure linkphaseweight.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Start linkphaseweight.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of linkphaseweight.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
                linkphaseweight*& component);
                
    Disposition handle_link_change(const Event& e);
                
    void periodic_probe();
    
    Linkweight get_link_weight(const Link& link);
    
    Linkweight get_link_weight(datapathid dpsrc, datapathid dpdst, uint16_t sport, uint16_t dport);

  private:

    /** \brief Reference to link load
     */
    linkload* lload;
    
    /** Iterator for probing
     */
    LinkRatioMap::iterator lrm_it;
    
    /** \brief Update phaseweightmap
     * @param it iterator of phaseweightmap
     */
    void updatePhaseWeight(LinkRatioMap::iterator& it);
    
    /** \brief Get next time to send probe
     *
     * @return time for next probe
     */
    timeval get_next_time();
    
    /** \brief Calculate weight
     *
     * @return weight of link
     */
    Linkweight calculate_weight(double ratio);
            
  };
}

#endif