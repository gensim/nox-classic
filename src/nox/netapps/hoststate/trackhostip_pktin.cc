#include "trackhostip_pktin.hh"
#include "assert.hh"
#include "packet-in.hh"
#include "netinet++/ethernet.hh"
#include "flow.hh"
#include <boost/bind.hpp>

namespace vigil
{
  static Vlog_module lg("trackhostip_pktin");
  
  Disposition trackhostip_pktin::handle_pkt_in(const Event& e)
  {
    const Packet_in_event& pie = assert_cast<const Packet_in_event&>(e);
 
    if (pie.flow.dl_type != ethernet::IP)
      return CONTINUE;

    if (!topo->is_internal(pie.datapath_id, pie.in_port) &&
	!pie.flow.dl_src.is_multicast() && !pie.flow.dl_src.is_broadcast() &&
	!ipaddr((uint32_t)htonl(pie.flow.nw_src)).isMulticast() && pie.flow.nw_src!=0)
      hit->add_location(htonl(pie.flow.nw_src), pie.datapath_id, pie.in_port);
    else
      VLOG_DBG(lg, "Host %"PRIx64" not registered, 'cos %s%s %s %s",
	       pie.flow.dl_src.hb_long(),
	       pie.flow.dl_src.is_multicast()?"multicast mac":"",
	       pie.flow.dl_src.is_broadcast()?"broadcast mac":"",
           ipaddr((uint32_t)pie.flow.nw_src).isMulticast()?"multicast ip":"",    
	       topo->is_internal(pie.datapath_id, pie.in_port)?"on internal port":"");

    return CONTINUE;
  } 

  void trackhostip_pktin::configure(const Configuration* c) 
  {
    resolve(hit);
    resolve(topo);

    register_handler<Packet_in_event>
      (boost::bind(&trackhostip_pktin::handle_pkt_in, this, _1));
  }
  
  void trackhostip_pktin::install()
  {
  }

  void trackhostip_pktin::getInstance(const Context* c,
				  trackhostip_pktin*& component)
  {
    component = dynamic_cast<trackhostip_pktin*>
      (c->get_by_interface(container::Interface_description
			      (typeid(trackhostip_pktin).name())));
  }

  REGISTER_COMPONENT(Simple_component_factory<trackhostip_pktin>,
		     trackhostip_pktin);
} // vigil namespace
