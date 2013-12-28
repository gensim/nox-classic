#include "linkphaseweight.hh"

#include <boost/bind.hpp>
#include "discovery/link-event.hh"

#include "assert.hh"

#include "vlog.hh"

namespace vigil
{
  static Vlog_module lg("linkphaseweight");
  
  std::size_t 
  linkphaseweight::linkhash::operator()(const Link& e) const
  {
    HASH_NAMESPACE::hash<datapathid> dphash;
    HASH_NAMESPACE::hash<uint16_t> u16hash;
    return dphash(e.dpsrc) ^ dphash(e.dpdst) ^ u16hash(e.sport) ^ u16hash(e.dport); 
  }
        
  bool 
  linkphaseweight::linkeq::operator()(const Link& a, const Link& b) const
  {
    return (a.dpsrc == b.dpsrc && a.dpdst == b.dpdst &&
            a.sport == b.sport && a.dport == b.dport);
  }
  
  void linkphaseweight::configure(const Configuration* c) 
  {
    //Get commandline arguments
    const hash_map<string, string> argmap = \
      c->get_arguments_list();
    hash_map<string, string>::const_iterator i;
    i = argmap.find("interval");
    if (i != argmap.end())
      weight_interval = atoi(i->second.c_str());
    else
      weight_interval = LINKWIGHT_DEFAULT_INTERVAL;  
    
    i = argmap.find("alpha");
    if (i != argmap.end())
      alpha = atof(i->second.c_str());
    else
      alpha = LINKWIGHT_DEFAULT_ALPHA;  
       
    resolve(lload);
    register_event(Linkpw_event::static_get_name());
    
    lload->load_interval = weight_interval;
  }
  
  void linkphaseweight::install()
  {
    register_handler<Link_event>
        (boost::bind(&linkphaseweight::handle_link_change, this, _1));
        
    pwm_it = phaseweightmap.begin();
    
    post(boost::bind(&linkphaseweight::periodic_probe, this), get_next_time());
  }
  
  void linkphaseweight::getInstance(const container::Context* c, 
                linkphaseweight*& component)
  {
    component = dynamic_cast<linkphaseweight*>
    (c->get_by_interface(container::Interface_description
                (typeid(linkphaseweight).name())));
  }
  
  Disposition linkphaseweight::handle_link_change(const Event& e)
  {
    const Link_event& le = assert_cast<const Link_event&>(e);
    
    Link link = { le.dpsrc, le.dpdst, le.sport, le.dport };
    
    PhaseWeightMap::iterator i = phaseweightmap.find(link); 
    
    if(le.action == Link_event::REMOVE) {
        if(i !=  phaseweightmap.end()) {
            post(new Linkpw_event(link.dpsrc, link.dpsrc, link.sport, link.dport, Linkpw_event::REMOVE, phaseweightmap[link].weight));
            phaseweightmap.erase(i);
            
        } else {
            VLOG_WARN(lg, "Duplicate Add Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16") ignored!",
                le.dpsrc.as_host(), le.dpdst.as_host(), le.sport, le.dport);
        }
    } else if(le.action == Link_event::ADD) {
        if(i == phaseweightmap.end()) {
            phaseweightmap.insert(make_pair(link, (phaseweight){LP_LOW, Linkweight(1)}));
            post(new Linkpw_event(link.dpsrc, link.dpsrc, link.sport, link.dport, Linkpw_event::ADD, phaseweightmap[link].weight));
        } else {
            VLOG_WARN(lg, "Duplicate Remove Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16") ignored!",
                le.dpsrc.as_host(), le.dpdst.as_host(), le.sport, le.dport);
        }
    }
    return CONTINUE;
  }
  
  void linkphaseweight::periodic_probe()
  {
    if (phaseweightmap.size() != 0)
    {
      if (pwm_it == phaseweightmap.end())
    pwm_it = phaseweightmap.begin();
      
      VLOG_DBG(lg, "Probe weight to Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16")",
           pwm_it->first.dpsrc.as_host(), pwm_it->first.dpdst.as_host(), pwm_it->first.sport, pwm_it->first.dport);

      updatePhaseWeight(pwm_it);

      pwm_it++;
    }

    post(boost::bind(&linkphaseweight::periodic_probe, this), get_next_time());
  }
  
  void linkphaseweight::updatePhaseWeight(PhaseWeightMap::iterator& it)
  {
    float tx_ratio, rx_ratio, ratio;
    Linkphase old_phase, new_phase;
    bool is_post = false;

    linkload::load tx_load = lload->get_link_load(it->first.dpsrc, it->first.sport);
    linkload::load rx_load = lload->get_link_load(it->first.dpdst, it->first.dport);
    if(tx_load.interval == 0) tx_ratio = 0;
    else tx_ratio = lload->get_link_load_ratio(it->first.dpsrc, it->first.sport);
    if(rx_load.interval == 0) rx_ratio = 0;
    else rx_ratio = lload->get_link_load_ratio(it->first.dpdst, it->first.dport);
    ratio = (tx_ratio >= rx_ratio) ? tx_ratio : rx_ratio ;

    old_phase = it->second.phase;
    if(ratio > LINKWIGHT_RATIO_CONGESTION)
      new_phase = LP_CONGESTION;
    else if(ratio > LINKWIGHT_RATIO_HIGH_MIDDLE && ratio <= LINKWIGHT_RATIO_CONGESTION)
      new_phase = LP_HIGH;
    else if(ratio > LINKWIGHT_RATIO_MIDDLE_LOW && ratio <= LINKWIGHT_RATIO_HIGH_MIDDLE)
      new_phase = LP_MIDDLE;
    else 
      new_phase = LP_LOW;

    if(old_phase != LP_CONGESTION) {
      if(new_phase == LP_CONGESTION) 
        is_post = true;
      else if(new_phase < old_phase)
        is_post = true;
    } else {
      if(new_phase < LP_HIGH)
        is_post = true;
    }

    if(is_post) {
      Linkweight new_weight = (uint64_t)(1 + ((1.0/alpha) -1) * ratio);
      if(new_phase == LP_CONGESTION) new_weight.setInfinity(1);
      
      post(new Linkpw_event(it->first.dpsrc, it->first.dpsrc, it->first.sport, it->first.dport, 
                            Linkpw_event::CHANGE, phaseweightmap[it->first].weight, new_weight));
    }
  }
  
  timeval linkphaseweight::get_next_time()
  {
    timeval tv = {0,0};
    if (phaseweightmap.size() == 0)
      tv.tv_sec = weight_interval;
    else
      tv.tv_sec = weight_interval/phaseweightmap.size();

    if (tv.tv_sec == 0)
      tv.tv_sec = 1;

    return tv;
  }
  
  REGISTER_COMPONENT(Simple_component_factory<linkphaseweight>,
             linkphaseweight);

}