# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from ryu.lib.packet.radius import radius
import ryu.openflow.libopenflow_01 as of
from ryu.lib.addresses import IPAddr, IPAddr6, EthAddr
from ryu.lib.util import dpid_to_str
from ryu.lib.util import str_to_bool
import time


# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0


class LearningSwitch(object):
    """
    The learning switch "brain" associated with a single OpenFlow switch.

    When we see a packet, we'd like to output it on a port which will
    eventually lead to the destination.  To accomplish this, we build a
    table that maps addresses to ports.

    We populate the table by observing traffic.  When we see a packet
    from some source coming from some port, we know that source is out
    that port.

    When we want to forward traffic, we look up the desintation in our
    table.  If we don't know the port, we simply send the message out
    all ports except the one it came in on.  (In the presence of loops,
    this is bad!).

    In short, our algorithm looks like this:

    For each packet from the switch:
    1) Use source address and switch port to update address/port table
    2) Is transparent = False and either Ethertype is LLDP or the packet's
       destination address is a Bridge Filtered address?
       Yes:
          2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
              DONE
    3) Is destination multicast?
       Yes:
          3a) Flood the packet
              DONE
    4) Port for destination address in our address/port table?
       No:
          4a) Flood the packet
              DONE
    5) Is output port the same as input port?
       Yes:
          5a) Drop packet and similar ones for a while
    6) Install flow table entry in the switch so that this
       flow goes out the appopriate port
       6a) Send the packet out appropriate port
    """

    def __init__(self, connection, transparent, radius):
        # Switch we'll be adding L2 learning switch capabilities to
        self.connection = connection
        self.transparent = transparent
        self.flow_added = True
        self.radius = radius
        # Our table
        self.macToPort = {}

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)

        # We just use this to know when to log a helpful message
        self.hold_down_expired = _flood_delay == 0

        # log.debug("Initializing LearningSwitch, transparent=%s",
        #          str(self.transparent))

    def _handle_PacketIn(self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        # if self.flow_added and self.radius:
        #    for connection in core.openflow.connections: # _connections.values() before betta
        # print ("Clearing all flows from %s." % (dpid_to_str(connection.dpid),))
        #        msg = of.ofp_flow_mod()
        #        msg.priority = 65535
        #        msg.match.in_port = 2
        #        msg.match.vlan_tci = 0x0000
        #        msg.match.dl_type = 0x800
        # msg.match.dl_src = EthAddr(radius.mac[1])
        #        msg.match.nw_proto = 17
        #        msg.match.nw_tos = 0
        #        msg.match.tp_dst = 1812
        # msg.match.tp_dst = 80
        # msg.actions.append(of.ofp_action_output(port = 6))
        #        msg.actions.append(of.ofp_action_output(port = 1))
        #        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        #        connection.send(msg)
        #        self.flow_added = False

        packet = event.parsed

        # if packet.find("radius"):
        #    print ("udp found: %s", packet.find("ethernet").src)
        #    print ("udp found: %s:%s to %s:%s", packet.find("ipv4").srcip, packet.find("udp").srcport, packet.find("ipv4").dstip, packet.find("udp").dstport)
        # if packet.find("udp") and self.radius:
        #    for connection in core.openflow.connections: # _connections.values() before betta
        # connection.send(msg)
        # self.oldRule()
        #        pass

        def oldRule():
            if len(radius.mac_) == 1:
                if 'bob' == radius.rule1[radius.mac_[0]] and radius.mac_[0] not in radius.rule:
                    self.logger.info("Dropping packets from %s to h4" % radius.mac_[0])
                    msg = of.ofp_flow_mod()
                    msg.priority = 65535
                    msg.match.in_port = 2
                    msg.match.dl_type = 0x800
                    msg.match.nw_proto = 1
                    msg.match.nw_src = IPAddr("10.0.0.%s" % len(radius.rule1))
                    msg.match.nw_dst = IPAddr("192.168.0.10")
                    # connection.send(msg)
                    radius.rule.append(radius.mac_[0])
                if 'joe' == radius.rule1[radius.mac_[0]] and radius.mac_[0] not in radius.rule:
                    self.logger.info("Dropping packets from %s to h5" % radius.mac_[0])
                    msg = of.ofp_flow_mod()
                    msg.priority = 65535
                    msg.match.in_port = 2
                    msg.match.dl_type = 0x800
                    msg.match.nw_proto = 1
                    msg.match.nw_src = IPAddr("10.0.0.%s" % len(radius.rule1))
                    msg.match.nw_dst = IPAddr("192.168.0.11")
                    # connection.send(msg)
                    radius.rule.append(radius.mac_[0])
                radius.mac_ = []
                radius.name_ = []

        def flood(message=None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
                # Only flood if we've been connected for a little while...

                if self.hold_down_expired is False:
                    # Oh yes it is!
                    self.hold_down_expired = True
                    self.logger.info("%s: Flood hold-down expired -- flooding",
                             dpid_to_str(event.dpid))

                if message is not None: self.logger.debug(message)
                # log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
                # OFPP_FLOOD is optional; on some switches you may need to change
                # this to OFPP_ALL.
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            else:
                pass
                # log.info("Holding down flood for %s", dpid_to_str(event.dpid))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        def drop(duration=None):
            """
            Drops this packet and optionally installs a flow to continue
            dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration, duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port  # 1

        if not self.transparent:  # 2
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                drop()  # 2a
                return

        if packet.dst.is_multicast:
            flood()  # 3a
        else:
            if packet.dst not in self.macToPort:  # 4
                flood("Port for %s unknown -- flooding" % (packet.dst,))  # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:  # 5
                    # 5a
                    self.logger.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                                % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                    drop(10)
                    return
                # 6
                self.logger.debug("installing flow for %s.%i -> %s.%i" %
                          (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port=port))
                msg.data = event.ofp  # 6a
                self.connection.send(msg)


class l2_learning(object):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """

    def __init__(self, transparent, radius):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.radius = radius

    def _handle_ConnectionUp(self, event):
        self.logger.debug("Connection %s" % (event.connection,))
        LearningSwitch(event.connection, self.transparent, self.radius)


def launch(transparent=False, hold_down=_flood_delay, radius=False):
    """
    Starts an L2 learning switch.
    """
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")
    core.registerNew(l2_learning, str_to_bool(transparent), radius)
