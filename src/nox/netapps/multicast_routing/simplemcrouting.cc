#include "simplemcrouting.hh"
#include "assert.hh"
#include "netinet++/ethernet.hh"
#include <boost/bind.hpp>

namespace vigil
{
  static Vlog_module lg("simplemcrouting");
  
  void simplemcrouting::configure(const Configuration* c) 
  {

    post_flow_record = SIMPLEMCROUTING_POST_RECORD_DEFAULT;

    //Get commandline arguments
    const hash_map<string, string> argmap = \
      c->get_arguments_list();
    hash_map<string, string>::const_iterator i = \
      argmap.find("postrecord");
    if (i != argmap.end())
    {
      if (i->second == "true")
	post_flow_record = true;
      else if (i->second == "false")
	post_flow_record = false;
      else
	VLOG_WARN(lg, "Cannot parse argument postrecord=%s", 
		  i->second.c_str());
    }
  }
  
  Disposition simplemcrouting::handle_pkt_in(const Event& e)
  {
    const Packet_in_event& pie = assert_cast<const Packet_in_event&>(e);

    // Handle only multicast flow
    ipaddr src = (uint32_t)htonl(pie.flow.nw_src);
    ipaddr dst = (uint32_t)htonl(pie.flow.nw_dst);
    if (pie.flow.dl_type != ethernet::IP || 
        pie.flow.nw_proto != ip_::proto::UDP ||
        src.isMulticast() || !dst.isMulticast())
      return CONTINUE;

    network::route rte(pie.datapath_id, pie.in_port);
    if (mri->get_multicast_tree_path(src, dst, rte))
    {
      VLOG_DBG(lg, "Install route datapath=%"PRIx64" src=%s dst=%s", 
             pie.datapath_id.as_host(), src.string().c_str(), dst.string().c_str());
      uint32_t wildcards = OFPFW_TP_SRC | OFPFW_TP_DST;      
      mri->install_route(pie.flow, rte, pie.buffer_id, wildcards);
      if (post_flow_record)
        frr->set(pie.flow, rte);
    }   

    return CONTINUE;
  }

  void simplemcrouting::install()
  {
    resolve(mri);
    resolve(frr);
    
    register_handler<Packet_in_event>
      (boost::bind(&simplemcrouting::handle_pkt_in, this, _1));
  }

  void simplemcrouting::getInstance(const Context* c,
				  simplemcrouting*& component)
  {
    component = dynamic_cast<simplemcrouting*>
      (c->get_by_interface(container::Interface_description
			      (typeid(simplemcrouting).name())));
  }

  REGISTER_COMPONENT(container::Simple_component_factory<simplemcrouting>,
		     simplemcrouting);
} // vigil namespace
