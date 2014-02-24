#include "hostiptracker.hh"
#include <boost/bind.hpp>

namespace vigil
{
  static Vlog_module lg("hostiptracker");
  
  HostIP_location_event::HostIP_location_event(const ipaddr host_,
					   const list<hostiptracker::location> loc_,
					   enum type type_):
    Event(static_get_name()), host(host_), eventType(type_)
  {
    for (list<hostiptracker::location>::const_iterator i = loc_.begin();
	 i != loc_.end(); i++)
      loc.push_back(*(new hostiptracker::location(i->dpid,
						i->port,
						i->lastTime)));
  }

  hostiptracker::location::location(datapathid dpid_, uint16_t port_, time_t tv):
    dpid(dpid_), port(port_), lastTime(tv)
  { }

  void hostiptracker::location::set(const hostiptracker::location& loc)
  {
    dpid = loc.dpid;
    port = loc.port;
    lastTime = loc.lastTime;
  }

  void hostiptracker::configure(const Configuration* c) 
  {
    defaultnBindings = DEFAULT_HOSTIP_N_BINDINGS;
    hostTimeout = DEFAULT_HOSTIP_TIMEOUT;

    register_event(HostIP_location_event::static_get_name());
  }
  
  void hostiptracker::install()
  {
  }

  void hostiptracker::check_timeout()
  {
    if (hostlocation.size() == 0)
      return;

    time_t timenow;
    time(&timenow);

    hash_map<ipaddr,list<hostiptracker::location> >::iterator i = \
      hostlocation.find(oldest_host());
    if (i == hostlocation.end())
      return;
    
    list<hostiptracker::location>::iterator j = get_oldest(i->second);
    while (j->lastTime+hostTimeout < timenow)
    {
      //Remove old entry
      i->second.erase(j);
      if (i->second.size() == 0)
      	hostlocation.erase(i);

      //Get next oldest
      i = hostlocation.find(oldest_host());
      if (i == hostlocation.end())
	return;
      j = get_oldest(i->second);
    }

    //Post next one
    timeval tv = {get_oldest(i->second)->lastTime+hostTimeout-timenow, 0};
    post(boost::bind(&hostiptracker::check_timeout, this), tv);
  }

  const ipaddr hostiptracker::oldest_host()
  {
    ipaddr oldest((uint32_t) 0);
    time_t oldest_time = 0;
    hash_map<ipaddr,list<hostiptracker::location> >::iterator i = \
      hostlocation.begin();
    while (i != hostlocation.end())
    {
      if (oldest_time == 0 ||
	  get_oldest(i->second)->lastTime < oldest_time)
      {
	oldest_time = get_oldest(i->second)->lastTime;
	oldest = i->first;
      }
      i++;
    }

    return oldest;
  } 

  void hostiptracker::add_location(ipaddr host, datapathid dpid, 
				 uint16_t port, time_t tv, bool postEvent)
  {
    //Set default time as now
    if (tv == 0)
      time(&tv);

    add_location(host, hostiptracker::location(dpid,port,tv), postEvent);
  }

  void hostiptracker::add_location(ipaddr host, hostiptracker::location loc,
				 bool postEvent)
  {
    hash_map<ipaddr,list<hostiptracker::location> >::iterator i = \
      hostlocation.find(host);
    if (i == hostlocation.end())
    {
      //New host
      list<location> j = list<location>();
      j.push_front(loc);
      hostlocation.insert(make_pair(host,j));

      if (postEvent)
	post(new HostIP_location_event(host,j,HostIP_location_event::ADD));

      VLOG_DBG(lg, "New host %s at %"PRIx64":%"PRIx16"",
	       host.string().c_str(), loc.dpid.as_host(), loc.port);
    }
    else
    {
      //Existing host
      list<location>::iterator k = i->second.begin();
      while (k->dpid != loc.dpid || k->port != loc.port)
      {
	k++;
	if (k == i->second.end())
	  break;
      }

      if (k == i->second.end())
      {
	//New location
	while (i->second.size() >= getBindingNumber(host))
	  i->second.erase(get_oldest(i->second));
	i->second.push_front(loc);
	VLOG_DBG(lg, "Host %s at new location %"PRIx64":%"PRIx16"",
		 i->first.string().c_str(), loc.dpid.as_host(), loc.port);

	if (postEvent)
	  post(new HostIP_location_event(host,i->second,
				       HostIP_location_event::MODIFY));
      }
      else
      {
	//Update timeout
	k->lastTime = loc.lastTime;
	VLOG_DBG(lg, "Host %s at old location %"PRIx64":%"PRIx16"",
		 i->first.string().c_str(), loc.dpid.as_host(), loc.port);
      }	
    }

    VLOG_DBG(lg, "Added host %s to location %"PRIx64":%"PRIx16"",
	     host.string().c_str(), loc.dpid.as_host(), loc.port);

    //Schedule timeout if first entry
    if (hostlocation.size() == 0)
    {
      timeval tv= {hostTimeout,0};
      post(boost::bind(&hostiptracker::check_timeout, this), tv);
    }
  }

  void hostiptracker::remove_location(ipaddr host, datapathid dpid, 
				    uint16_t port, bool postEvent)
  {
    remove_location(host, hostiptracker::location(dpid,port,0), postEvent);
  }

  void hostiptracker::remove_location(ipaddr host, 
				    hostiptracker::location loc,
				    bool postEvent)
  {
    hash_map<ipaddr,list<hostiptracker::location> >::iterator i =	\
      hostlocation.find(host);
    if (i != hostlocation.end())
    {
      bool changed = false;
      list<location>::iterator k = i->second.begin();
      while (k != i->second.end())
      {
	if (k->dpid == loc.dpid || k->port == loc.port)
	{
	  k = i->second.erase(k);
	  changed = true;
	}
	else
	  k++;
      }

      if (postEvent && changed)
	post(new HostIP_location_event(host,i->second,
				     (i->second.size() == 0)?
				     HostIP_location_event::REMOVE:
				     HostIP_location_event::MODIFY));

      if (i->second.size() == 0)
	hostlocation.erase(i);	
    }
    else
      VLOG_DBG(lg, "Host %s has no location, cannot unset.",
               host.string().c_str());
  }

  const hostiptracker::location hostiptracker::get_latest_location(ipaddr host)
  {
    list<hostiptracker::location> locs = \
      (list<hostiptracker::location>) get_locations(host);
    if (locs.size() == 0)
      return hostiptracker::location(datapathid(), 0, 0);
    else
      return *(get_newest(locs));
  }

  const list<ipaddr> hostiptracker::get_hosts()
  {
    list<ipaddr> hostlist;
    hash_map<ipaddr,list<hostiptracker::location> >::iterator i = \
      hostlocation.begin();
    while (i != hostlocation.end())
    {
      hostlist.push_back(i->first);
      i++;
    }

    return hostlist;
  }

  const list<hostiptracker::location> hostiptracker::get_locations(ipaddr host)
  {
    hash_map<ipaddr,list<hostiptracker::location> >::iterator i = \
      hostlocation.find(host);
    if (i == hostlocation.end())
      return list<hostiptracker::location>();
    else
      return i->second;
  }

  list<hostiptracker::location>::iterator 
  hostiptracker::get_newest(list<hostiptracker::location>& loclist)
  {
    list<location>::iterator newest = loclist.begin();
    list<location>::iterator j = loclist.begin();
    while (j != loclist.end())
    {
      if (j->lastTime > newest->lastTime)
	newest = j;
      j++;
    }  
    return newest;
  }

  list<hostiptracker::location>::iterator 
  hostiptracker::get_oldest(list<hostiptracker::location>& loclist)
  {
    list<location>::iterator oldest = loclist.begin();
    list<location>::iterator j = loclist.begin();
    while (j != loclist.end())
    {
      if (j->lastTime < oldest->lastTime)
	oldest = j;
      j++;
    }  
    return oldest;
  }

  uint8_t hostiptracker::getBindingNumber(ipaddr host)
  {
    hash_map<ipaddr,uint8_t>::iterator i = nBindings.find(host);
    if (i != nBindings.end())
      return i->second;

    return defaultnBindings;
  }

  const list<hostiptracker::location> hostiptracker::getLocations(ipaddr host)
  {
    hash_map<ipaddr,list<hostiptracker::location> >::iterator i = \
      hostlocation.find(host);
    
    if (i == hostlocation.end())
      return list<hostiptracker::location>();
    
    return i->second;
  }

  void hostiptracker::getInstance(const Context* c,
				  hostiptracker*& component)
  {
    component = dynamic_cast<hostiptracker*>
      (c->get_by_interface(container::Interface_description
			      (typeid(hostiptracker).name())));
  }

  REGISTER_COMPONENT(Simple_component_factory<hostiptracker>,
		     hostiptracker);
} // vigil namespace
