'!/usr/bin/env python2'

# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import logging
import threading

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, socket, struct, time, subprocess, atexit, select, os
from datetime import datetime
from ryu.lib.packet import radius

from ryu.base import app_manager


ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = {"gray": "\033[0;37m",
              "green": "\033[0;32m",
              "orange": "\033[0;33m",
              "red": "\033[0;31m"}

global_log_level = INFO
attack = ''

def log(level, msg, color=None, showtime=True):
    if level < global_log_level: return
    if level == DEBUG and color is None: color = "gray"
    if level == WARNING and color is None: color = "orange"
    if level == ERROR and color is None: color = "red"
    print (datetime.now().strftime('[%H:%M:%S] ') if showtime else " " * 11) + COLORCODES.get(color,
                                                                                              "") + msg + "\033[1;0m"
#### Packet Processing Functions ####

class MitmSocket(L2Socket):
    def __init__(self, **kwargs):
        super(MitmSocket, self).__init__(**kwargs)

    def send(self, p):
        # Hack: set the More Data flag so we can detect injected frames (and so clients stay awake longer)
        p[Dot11].FCfield |= 0x20
        L2Socket.send(self, RadioTap() / p)

    def _strip_fcs(self, p):
        # Scapy can't handle the optional Frame Check Sequence (FCS) field automatically
        #if p[RadioTap].present & 2 != 0:
        if p.type == 0 and p.subtype == 8:
            _wireless(p)

        return p[Dot11]

    def recv(self, x=MTU):
        p = L2Socket.recv(self, x)
        if p == None or not Dot11 in p: return None

        # Hack: ignore frames that we just injected and are echoed back by the kernel
        if p[Dot11].FCfield & 0x20 != 0:
            return None

        # Strip the FCS if present, and drop the RadioTap header
        return self._strip_fcs(p)

    def close(self):
        super(MitmSocket, self).close()


#### Man-in-the-middle Code ####

class KRAckAttackFt():
    def __init__(self, interface):
        self.nic_iface = interface
        self.nic_mon = 'mon0'
        self.clientmac = scapy.arch.get_if_hwaddr(interface)

        self.sock = None
        self.reassoc = None
        self.ivs = set()
        self.next_replay = None

    def handle_rx(self):
        p = self.sock.recv()
        if p == None: return

    def run(self):
        #self.configure_interfaces()

        self.sock = MitmSocket(type=ETH_P_ALL, iface=self.nic_mon)

        # Monitor the virtual monitor interface of the client and perform the needed actions
        while True:
            sel = select.select([self.sock], [], [], 1)
            if self.sock in sel[0]: self.handle_rx()
            if self.reassoc and time.time() > self.next_replay:
                log(INFO, "Replaying Reassociation Request")
                self.sock.send(self.reassoc)
                self.next_replay = time.time() + 1

    def stop(self):
        log(STATUS, "Cleaning up ...")
        if self.sock: self.sock.close()


def cleanup():
    attack.stop()


class getAttr(object):
    iface = []
    status = 'nothing'
    app_running = False
    currentAP = ''
    client1 = '00-00-00-00-00-01'
    client2 = '00-01-00-00-00-01'
    users_telcoA = ['joe']
    users_telcoB = ['bob']
    time_ = {'00:00:00:00:00:03': '', '00:00:00:00:00:04': '', '00:00:00:00:00:05': '', '00:00:00:00:00:06': ''}
    status_ = {'00:00:00:00:00:03': '', '00:00:00:00:00:04': '', '00:00:00:00:00:05': '', '00:00:00:00:00:06': ''}


class _wireless(object):
    def __init__(self, p):
        mininet_dir = '/home/alpha/master/mininet-wifi/'
        log_dir = mininet_dir + 'data-log/sta1.log 2>&1 &'

        extra = p.notdecoded
        signal = -(256 - ord(extra[-4:-3]))
        self.do_something(p.addr1, p.addr2, p.addr3, signal, mininet_dir, log_dir)
        # t = a[i].fields['wlan.fc.type_subtype eq 8']

    def do_something(self, addr1, addr2, addr3, signal, mininet_dir, log_dir):
        case1 = True
        ping_test = False
        iperf_test = True
        http_test = False
        #print signal
        #print radius.mac_
        #print getAttr.status_
        if case1:
            if addr3 == '00:00:00:00:00:03' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and radius.rule1[
                        getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and radius.rule1[
                                getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.2' % mininet_dir)
                            if http_test:
                                os.system('pkill -f SimpleHTTPServer')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h2 python -m SimpleHTTPServer 808%s &' % (mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h2 iperf -s -i 1' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            print "222222222222222222222222222"
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 -u -b10M >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:03' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)

            if addr3 == '00:00:00:00:00:04' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and \
                                    radius.rule1[getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and \
                                            radius.rule1[getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.3' % mininet_dir)
                            # os.system('pkill -f SimpleHTTPServer')
                            if http_test:
                                os.system('pkill -f \"i sta1-wlan0\"')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h3 python -m SimpleHTTPServer 808%s &' % (
                            mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h3 iperf -s -i 1' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[
                    addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            print "333333333333333333333333"
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 -u -b10M >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:04' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)

            if addr3 == '00:00:00:00:00:05' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and radius.rule1[
                        getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and radius.rule1[
                                getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.4' % mininet_dir)
                            # os.system('pkill -f SimpleHTTPServer')
                            if http_test or iperf_test:
                                os.system('pkill -f \"i sta1-wlan1\"')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h4 python -m SimpleHTTPServer 808%s &' % (mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h4 iperf -s -i 1' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[
                    addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            print "44444444444444444444444"
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 -u -b10M >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:05' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)
            #print radius.rule1
            #print '%s----%s' %(addr3, signal)
            if addr3 == '00:00:00:00:00:06' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and \
                                    radius.rule1[getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and \
                                            radius.rule1[getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.5' % mininet_dir)
                            #os.system('ovs-ofctl add-flow s18 in_port=1,actions=set_queue:123,normal')
                            os.system('ovs-ofctl -O Openflow13 add-flow s18 in_port=1,priority=1,actions=meter:1,2')
                            os.system('ovs-ofctl -O Openflow13 add-flow s18 in_port=2,priority=1,actions=meter:1,1')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h5 python -m SimpleHTTPServer 808%s &' % (mininet_dir, len(getAttr.iface)))
                            getAttr.app_running = True
                if getAttr.status_[addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            print "55555555555555555555555"
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 -u -b10M >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:06' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)
        else:
            #print addr3
            if addr3 == '00:00:00:00:00:03' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and \
                                    radius.rule1[getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and radius.rule1[
                                getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.2' % mininet_dir)
                            if http_test:
                                os.system('pkill -f SimpleHTTPServer')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h2 python -m SimpleHTTPServer 808%s &' % (mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h2 iperf -s &' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        os.system('echo \'Generating data to %s\' >> %s' % (addr3, log_dir))
                        os.system('echo \'------------------------\'>> %s' % log_dir)
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:03' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)

            if addr3 == '00:00:00:00:00:04' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ \
                            and radius.rule1[getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and \
                                            radius.rule1[getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 ifconfig sta1-wlan0 0' % mininet_dir)
                            os.system('%sutil/m sta1 ifconfig sta1-wlan1 10.0.0.1' % mininet_dir)
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route del -host 192.168.20.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.3' % mininet_dir)
                            if http_test:
                                os.system('pkill -f SimpleHTTPServer')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h3 python -m SimpleHTTPServer 808%s &' % (
                            mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h3 iperf -s -i 1' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        os.system('echo \'Generating data to %s\' >> %s' % (addr3, log_dir))
                        os.system('echo \'------------------------\'>> %s' % log_dir)
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:04' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)

            if addr3 == '00:00:00:00:00:05' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and radius.rule1[
                        getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and radius.rule1[
                                getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route add -host 192.168.10.100 gw 10.0.0.4' % mininet_dir)
                            if http_test:
                                os.system('pkill -f SimpleHTTPServer')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h4 python -m SimpleHTTPServer 808%s &' % (
                            mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h4 iperf -s -i 1' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        os.system('echo \'Generating data to %s\' >> %s' % (addr3, log_dir))
                        os.system('echo \'------------------------\'>> %s' % log_dir)
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.10.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            os.system('%sutil/m sta1 iperf -c 192.168.10.100 -i 1 >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.10.100 -c 10 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:05' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)

            if addr3 == '00:00:00:00:00:06' and signal >= -85:
                if len(getAttr.iface) <= 1 and addr3 not in getAttr.iface:
                    if getAttr.client1 in radius.mac_ and \
                                    radius.rule1[getAttr.client1] in getAttr.users_telcoA or \
                                            getAttr.client2 in radius.mac_ and \
                                            radius.rule1[getAttr.client2] in getAttr.users_telcoA:
                        if getAttr.currentAP != addr3:
                            getAttr.time_[addr3] = time.time()
                            getAttr.status_[addr3] = ''
                            getAttr.app_running = False
                            getAttr.currentAP = addr3
                            os.system('%sutil/m sta1 route del -host 192.168.10.100' % mininet_dir)
                            os.system('%sutil/m sta1 route add -host 192.168.20.100 gw 172.16.0.254' % mininet_dir)
                            if http_test:
                                os.system('pkill -f SimpleHTTPServer')
                            #os.system('ovs-ofctl add-flow s17 in_port=3,actions=set_queue:123,normal')
                            os.system('ovs-ofctl -O Openflow13 add-flow s17 in_port=3,actions=meter:1,normal')
                            getAttr.iface.append(addr3)
                        if not getAttr.app_running:
                            if http_test:
                                os.system('%sutil/m h4 python -m SimpleHTTPServer 808%s &' % (mininet_dir, len(getAttr.iface)))
                            #if iperf_test:
                            #    os.system('%sutil/m h4 iperf -s -i 1' % mininet_dir)
                            getAttr.app_running = True
                if getAttr.status_[addr3] == '' and addr3 in getAttr.iface:
                    if time.time() - getAttr.time_[addr3] > 3:
                        os.system('echo \'Generating data to %s\' >> %s' % (addr3, log_dir))
                        os.system('echo \'------------------------\'>> %s' % log_dir)
                        if http_test:
                            os.system('%sutil/m sta1 wget http://192.168.20.100:808%s >> %s' % (mininet_dir, len(getAttr.iface), log_dir))
                        if iperf_test:
                            os.system('%sutil/m sta1 iperf -c 192.168.20.100 -i 1 -t 30 >> %s' % (mininet_dir, log_dir))
                        if ping_test:
                            os.system('%sutil/m sta1 ping 192.168.20.100 -c 30 >> %s' % (mininet_dir, log_dir))
                        getAttr.status_[addr3] = 'connected'
            elif addr3 == '00:00:00:00:00:06' and signal < -85:
                if addr3 in getAttr.iface:
                    getAttr.iface.remove(addr3)


class vanet_run(app_manager.RyuApp):
    # if __name__ == "__main__":
    def __init__(self, *args, **kwargs):
        super(vanet_run, self).__init__(*args, **kwargs)

        # TODO: Verify that we only accept CCMP?
        interface = 'sta1-wlan0'
        if not interface:
            log(ERROR, "Failed to determine wireless interface. Specify one using the -i parameter.")
            quit(1)

        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()

    def run(self, interface='sta1-wlan0'):
        global attack
        attack = KRAckAttackFt(interface)
        atexit.register(cleanup)
        attack.run()