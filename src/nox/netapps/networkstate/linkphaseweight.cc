#include "linkphaseweight.hh"

#include <boost/bind.hpp>
#include "discovery/link-event.hh"

#include "assert.hh"

#include "vlog.hh"

//#define UNDIRECTED 1

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
    return ((a.dpsrc == b.dpsrc && a.dpdst == b.dpdst &&
            a.sport == b.sport && a.dport == b.dport)
#ifdef UNDIRECTED
            ||(a.dpsrc == b.dpdst && a.dpdst == b.dpsrc &&
            a.sport == b.dport && a.dport == b.sport)
#endif
            );
  }
  
  void linkphaseweight::configure(const Configuration* c) 
  {
    resolve(lload);
    //Get commandline arguments
    const hash_map<string, string> argmap = \
      c->get_arguments_list();
    hash_map<string, string>::const_iterator i;
    i = argmap.find("interval");
    if (i != argmap.end())
      weight_interval = atoi(i->second.c_str());
    else
      weight_interval = lload->load_interval;  
    
    i = argmap.find("alpha");
    if (i != argmap.end())
      alpha = atof(i->second.c_str());
    else
      alpha = LINKWIGHT_DEFAULT_ALPHA; 
    
    part = 0;
    i = argmap.find("part");
    if (i != argmap.end())
      part = atof(i->second.c_str());
    if (part == 0)
      part = LINKWIGHT_DEFAULT_PART;     
       
    register_event(Linkpw_event::static_get_name());
    
  }
  
  void linkphaseweight::install()
  {
    register_handler<Link_event>
        (boost::bind(&linkphaseweight::handle_link_change, this, _1));
        
    lrm_it = lr_map.begin();
    
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
    
    Link link = {le.dpsrc, le.dpdst, le.sport, le.dport};
    
    LinkRatioMap::iterator i = lr_map.find(link); 
    
    if(le.action == Link_event::REMOVE) {
        if(i !=  lr_map.end()) {
            post(new Linkpw_event(link.dpsrc, link.dpdst, link.sport, link.dport, Linkpw_event::REMOVE, calculate_weight(lr_map[link])));
#ifdef UNDIRECTED
            post(new Linkpw_event(link.dpdst, link.dpsrc, link.dport, link.sport, Linkpw_event::REMOVE, calculate_weight(lr_map[link])));
#endif
            if(lrm_it == i) lrm_it++;
            lr_map.erase(i);            
        } else {
            VLOG_WARN(lg, "Duplicate Remove Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16") ignored!",
                le.dpsrc.as_host(), le.dpdst.as_host(), le.sport, le.dport);
        }
    } else if(le.action == Link_event::ADD) {
        if(i == lr_map.end()) {
            Link tmp;
            tmp = (lrm_it == lr_map.end()) ? link: lrm_it->first;
            lr_map.insert(make_pair(link, 0));
            lrm_it = lr_map.find(tmp);
            post(new Linkpw_event(link.dpsrc, link.dpdst, link.sport, link.dport, Linkpw_event::ADD, calculate_weight(lr_map[link])));
#ifdef UNDIRECTED
            post(new Linkpw_event(link.dpdst, link.dpsrc, link.dport, link.sport, Linkpw_event::ADD, calculate_weight(lr_map[link])));
#endif
        } else {
            VLOG_WARN(lg, "Duplicate Add Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16") ignored!",
                le.dpsrc.as_host(), le.dpdst.as_host(), le.sport, le.dport);
        }
    }
    return CONTINUE;
  }
  
  Linkweight linkphaseweight::calculate_weight(double ratio)
  {
    int s = part*( (1-alpha) + alpha * ratio );  
    Linkweight w = (Linkweight){s, 0};
    return w;
  }
  
  Linkweight linkphaseweight::get_link_weight(const Link& link)
  {
    if(lr_map.find(link) != lr_map.end()) {
        
      return calculate_weight(lr_map[link]);  
    }
    return Linkweight();
  }
  
  Linkweight linkphaseweight::get_link_weight(datapathid dpsrc, datapathid dpdst, uint16_t sport, uint16_t dport)
  {
    return get_link_weight((Link){dpsrc, dpdst, sport, dport});
  }
  
  void linkphaseweight::periodic_probe()
  {
    if (lrm_it != lr_map.end())
    {
      
      VLOG_DBG(lg, "Probe weight to Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16")",
           lrm_it->first.dpsrc.as_host(), lrm_it->first.dpdst.as_host(), lrm_it->first.sport, lrm_it->first.dport);

      updatePhaseWeight(lrm_it);
      
      if(lr_map.size() > 0) {
          lrm_it++;
          if(lrm_it == lr_map.end()) lrm_it = lr_map.begin();
      } else {
          lrm_it = lr_map.end();
      }
    }

    post(boost::bind(&linkphaseweight::periodic_probe, this), get_next_time());
  }
  
  void linkphaseweight::updatePhaseWeight(LinkRatioMap::iterator& it)
  {
    Linkweight new_weight, old_weight;

    float rx_ratio1,ratio;
    linkload::load load2 = lload->get_link_load(it->first.dpdst, it->first.dport);
    if(load2.interval == 0) rx_ratio1 = 0;
    else rx_ratio1 = lload->get_link_load_ratio(it->first.dpdst, it->first.dport, false);    
#ifdef UNDIRECTED
    float rx_ratio2;
    linkload::load load1 = lload->get_link_load(it->first.dpsrc, it->first.sport);
    if(load1.interval == 0) rx_ratio2 = 0;
    else rx_ratio2 = lload->get_link_load_ratio(it->first.dpsrc, it->first.sport, false); 
    ratio = (rx_ratio1 >= rx_ratio2) ? rx_ratio1 : rx_ratio2 ;
#else
    ratio = rx_ratio1;
#endif
    
    double diff = 1.0/part;
    double rdiff = (ratio > lr_map[it->first])? (ratio - lr_map[it->first]) : (lr_map[it->first] - ratio);
    
    if( rdiff >= diff ) {  
      old_weight = calculate_weight(lr_map[it->first]);
      new_weight = calculate_weight(ratio);
      lr_map[it->first] = ratio;
      if( new_weight != old_weight ) {
        post(new Linkpw_event(it->first.dpsrc, it->first.dpdst, it->first.sport, it->first.dport, 
                                Linkpw_event::CHANGE, old_weight, new_weight));
#ifdef UNDIRECTED
        post(new Linkpw_event(it->first.dpdst, it->first.dpsrc, it->first.dport, it->first.sport, 
                                Linkpw_event::CHANGE, old_weight, new_weight));
#endif
        VLOG_DBG(lg, "Link(%"PRIx64",%"PRIx64",%"PRIx16",%"PRIx16") weight change from %s to %s while ratio=%f",
            it->first.dpsrc.as_host(), it->first.dpdst.as_host(), it->first.sport, it->first.dport, 
            old_weight.string().c_str(), new_weight.string().c_str(), ratio);
      }
    }
  }
  
  timeval linkphaseweight::get_next_time()
  {
    timeval tv = {0,0};
    if (lr_map.size() == 0)
    {
      tv.tv_sec = weight_interval;
    }
    else
    {
      long long t = ((long long)weight_interval)*1000000/lr_map.size();
      tv.tv_sec = t/1000000;
      tv.tv_usec = t-(((long long)tv.tv_sec)*1000000);
    }

    return tv;
  }
  
  REGISTER_COMPONENT(Simple_component_factory<linkphaseweight>,
             linkphaseweight);

}
