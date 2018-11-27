# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import subprocess
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import wifi
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types


class wifiAPP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(wifiAPP, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        mn_wifi_dir = '~/master/master/mininet-wifi/util/m'

        _ipv4 = pkt.get_protocol(ipv4.ipv4)

        if hasattr(_ipv4, 'proto'):
            if _ipv4.proto == 17:
                _udp = pkt.get_protocol(udp.udp)
                if _udp.src_port == 8000: #Client to Controller
                    _wifi = pkt.get_protocol(wifi.WiFiMsg)

                    target_rssi = int(_wifi.target_rssi)
                    rssi = int(_wifi.rssi)
                    client_id = "%01d" % (int(_wifi.client[-2:]),)
                    wifi.WiFiMsg.association['sta%s' % client_id] = _wifi.bssid

                    if _wifi.target_bssid:
                        for ap in ([_wifi.bssid, _wifi.target_bssid]):
                            ap_id = "%01d" % (int(ap[-2:]),)
                            n_clients = int(subprocess.check_output('hostapd_cli -i ap%s-wlan1 '
                                                                    'list_sta | wc -l'
                                                                    % ap_id, shell=True))
                            self.logger.info("wifi msg:: bssid %s has %s associated stations..",
                                             ap, n_clients)

                    self.logger.info("wifi msg:: client sta%s, rssi %s, bssid %s, ssid %s,"
                                     "target_bssid %s, target_rssi %s",
                                     client_id, rssi, _wifi.bssid, _wifi.ssid,
                                     _wifi.target_bssid, target_rssi)

                    if rssi < target_rssi and target_rssi > - 70:
                        print "bbbbbb"
                        if wifi.WiFiMsg.association['sta%s' % client_id] != _wifi.target_bssid:
                            os.system('%s sta%s wpa_cli -i sta%s-wlan0 scan '
                                      '>/dev/null 2>&1' % (mn_wifi_dir, client_id, client_id))
                            os.system('%s sta%s wpa_cli -i sta%s-wlan0 scan_results '
                                      '>/dev/null 2>&1' % (mn_wifi_dir, client_id, client_id))
                            wifi.WiFiMsg.association['sta%s' % client_id] = _wifi.target_bssid
                    if wifi.WiFiMsg.association['sta%s' % client_id] == _wifi.target_bssid:
                        print "sssss"
                        os.system('%s sta%s wpa_cli -i sta%s-wlan0 roam %s >/dev/null 2>&1'
                                  % (mn_wifi_dir, client_id, client_id, _wifi.target_bssid))

                        # self.logger.info("wifi msg:: number of clients associated with %s: %s",
                    #                 _wifi.bssid, n_clients)
                elif _udp.src_port == 8001: #Controller to Controller
                    _wifi = pkt.get_protocol(wifi.WiFiCtoCMsg)
                    self.logger.info("wifiCtoC msg:: client %s, bssid %s",
                                     _wifi.client, _wifi.bssid)

                    os.system('sh hostapd_cli -i ap1-wlan1 deauthenticate '
                              '%s >/dev/null 2>&1' % _wifi.client)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
