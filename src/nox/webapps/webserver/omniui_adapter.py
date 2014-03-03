from nox.coreapps.pyrt.pycomponent import *
from nox.lib.core import *

from nox.webapps.webserver import webserver
from nox.netapps.discovery import discovery
from nox.netapps.switchstats import switchstats
from nox.lib.netinet.netinet import create_datapathid_from_host
from nox.lib.pyopenflow import *

from twisted.web.resource import Resource
import json
import struct

def HostidToDpid(hid):
    idstr = "%016X" % hid
    return ":".join([idstr[i:i+2] for i in range(0,16,2)])
    

class LinkJsonRes(Resource):
    def __init__(self, component):
        Resource.__init__(self)
        self.component = component

    def render_GET(self, request):
        links = []
        for link in self.component.discovery.adjacency_list:
            src_dpid = HostidToDpid(link[0])
            src_port = link[1]
            dst_dpid = HostidToDpid(link[2])
            dst_port = link[3]
            links.append({"src-switch": src_dpid, "src-port": src_port, 
                          "dst-switch": dst_dpid, "dst-port": dst_port})
        return json.dumps(links)
        
class SwitchJsonRes(Resource):
    def __init__(self, component):
        Resource.__init__(self)
        self.component = component
        
    def render_GET(self, request):
        def migrate(a, b, akey, bkey):
            if bkey in b:
                a[akey] = b[bkey]
            else:
                a[akey] = 0                
        def port_Dict(ports, port_no):
            keymap = {"transmitPackets":    TX_PACKETS,
                      "transmitBytes":      TX_BYTES,
                      "recvPackets":        RX_PACKETS,
                      "recvBytes":          RX_BYTES}
            res = {"PortNumber": port_no}            
            for key in keymap:
                migrate(res, dp_ports[port_no], key, keymap[key])
            return res
        def flow_Dict(flow):            
            keymap1 = {"counterByte":       BYTE_COUNT,
                       "counterPacket":     PACKET_COUNT,
                       "hardTimeout":       HARD_TO,
                       "idleTimeout":       IDLE_TO,
                       "priority":          PRIORITY,
                       "tableId":           TABLE_ID}
            keymap2 = {"ingressPort":       IN_PORT,
                       "vlan":              DL_VLAN,
                       "dlType":            DL_TYPE,
                       "netProtocol":       NW_PROTO,
                       "tosBits":           NW_TOS,
                       "srcIPMask":         NW_SRC_N_WILD,
                       "dstIPMask":         NW_DST_N_WILD,
                       "srcPort":           TP_SRC,
                       "dstPort":           TP_DST}
            keymap3 = {"srcMac":            DL_SRC,
                       "dstMac":            DL_DST}
            keymap4 = {"srcIP":             NW_SRC,
                       "dstIP":             NW_DST}
            keymap5 = {OFPAT_OUTPUT:        "port",
                       OFPAT_SET_DL_SRC:    "dl_addr",
                       OFPAT_SET_DL_DST:    "dl_addr",
                       OFPAT_SET_NW_SRC:    "nw_addr",
                       OFPAT_SET_NW_DST:    "nw_addr",
                       OFPAT_SET_NW_TOS:    "nw_tos",
                       OFPAT_SET_TP_SRC:    "tp_port",
                       OFPAT_SET_TP_DST:    "tp_port"}
            res = {}
            res["duration"] = long(flow[DUR_SEC])+ (long(flow[DUR_NSEC])/1000000000)
            for key in keymap1:
                migrate(res, flow, key, keymap1[key])
            if MATCH in flow:
                res["wildcards"] = set_match(flow[MATCH]).wildcards
                for key in keymap2:
                    migrate(res, flow[MATCH], key, keymap2[key])
                for key in keymap3:
                    res[key] = str(ethernetaddr(flow[MATCH].get(keymap3[key],0)))
                for key in keymap4:
                    res[key] = str(ipaddr(flow[MATCH].get(keymap4[key],0)))
            if ACTIONS in flow:
                actions = []
                for act in flow[ACTIONS]:
                    if act["type"] in keymap5:
                        action = {}
                        action["type"] = ofp_action_type_map[act["type"]][6:]
                        value = keymap5[act["type"]]
                        if value == "dl_addr":
                            action["value"] = str(ethernetaddr(act.get(value,0)))
                        elif value == "nw_addr":
                            action["value"] = str(ipaddr(act.get(value,0)))
                        else:
                            action["value"] = act.get(value,0)
                        actions.append(action)
                res[ACTIONS] = actions
            return res
        switchs = []
        for dp in self.component.switchstats.dp_stats:
            ports = []
            if dp in self.component.switchstats.dp_port_stats:
                dp_ports = self.component.switchstats.dp_port_stats[dp]
                for port_no in dp_ports:
                    ports.append(port_Dict(dp_ports, port_no))
            flows = []
            if dp in self.component.switchstats.dp_flow_stats:
                dp_flows = self.component.switchstats.dp_flow_stats[dp]
                for f in dp_flows:
                    flows.append(flow_Dict(f))
            switch = {}
            switch["dpid"] = HostidToDpid(dp)
            switch["ports"] = ports
            switch["flows"] = flows
            switchs.append(switch)
            
        return json.dumps(switchs)

class omniui_adapter(Component):
    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.webserver = None

    def install(self):
        # Get a reference to the webserver component
        self.webserver = self.resolve(str(webserver.webserver))
        self.discovery = self.resolve(str(discovery.discovery))
        self.switchstats = self.resolve(str(switchstats.switchstats))
        self.webserver.authui_initialized = True        
        # Install a dynamically generated page        
        self.install_restapi("/wm/omniui/link/json", LinkJsonRes(self))
        self.install_restapi("/wm/omniui/switch/json", SwitchJsonRes(self))
    
    def install_restapi(self, path, res):
        if path[0] != "/":
            raise ImplementationError, "The path parameter must start with "
        path_components = path.split("/")[1:]
        parent = self.webserver.root
        for pc in path_components[:-1]:
            if parent.children.has_key(pc):
                child = parent.children[pc]
            else:
                child = Resource()
                parent.putChild(pc,child)
            parent = child
        parent.putChild(path_components[-1], res)
        
    def getInterface(self):
        return str(omniui_adapter)
        
def getFactory():
    class Factory:
        def instance(self, ctxt):
            return omniui_adapter(ctxt)

    return Factory()
    
