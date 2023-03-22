package com.sniffer.utils;

import com.sniffer.handle.PackageAnalyzer;
import org.jnetpcap.packet.PcapPacket;

import java.util.HashMap;

public class FilterUtils {

    //设置过滤规则
    public static boolean IsFilter(PcapPacket packet, String filterProtocol, String filterSrcIp,
                                   String filterDesIp,String filterSrcPort,String filterDesPort) {
        HashMap<String, String> hm = new PackageAnalyzer(packet).Analyzed();
        //协议过滤
        if (filterProtocol.equals("Ethernet II")) {
            if (!hm.get("协议").equals("ETHERNET")) {
                return false;
            }
        } else if (filterProtocol.equals("IP")) {
            if (!(hm.get("协议").equals("IP4") || hm.get("协议").equals("IP6"))) {
                return false;
            }
        } else if (filterProtocol.equals("ICMP")) {
            if (!hm.get("协议").equals("ICMP")) {
                return false;
            }
        } else if (filterProtocol.equals("ARP")) {
            if (!hm.get("协议").equals("ARP")) {
                return false;
            }
        } else if (filterProtocol.equals("UDP")) {
            if (!hm.get("协议").equals("UDP")) {
                return false;
            }
        } else if (filterProtocol.equals("TCP")) {
            if (!hm.get("协议").equals("TCP")) {
                return false;
            }
        } else if (filterProtocol.equals("HTTP")) {
            if (!hm.get("协议").equals("HTTP")) {
                return false;
            }
        } else if (filterProtocol.equals("")) {

        }
        //源ip地址过滤
        if (!filterSrcIp.equals("")) {
            if (!(hm.get("源IP4").equals(filterSrcIp) || hm.get("源IP6").equals(filterSrcIp))) {
                return false;
            }
        }
        //目的ip地址过滤
        if (!filterDesIp.equals("")) {
            if (!(hm.get("目的IP4").equals(filterDesIp) || hm.get("目的IP6").equals(filterDesIp))) {
                return false;
            }
        }
        //源端口过滤
        if (!filterSrcPort.equals("")) {
            if (!(hm.get("源端口").equals(filterSrcPort))) {
                return false;
            }
        }
        //目的端口过滤
        if (!filterDesPort.equals("")) {
            if (!(hm.get("目的端口").equals(filterDesPort))) {
                return false;
            }
        }
        return true;
    }

    //设置追踪规则
    public static boolean IsTrace(PcapPacket packet, String IP, String Port) {
        //如果是默认值，默认跟踪
        if (IP.equals("") || Port.equals("")) {
            return true;
        }
        HashMap<String, String> hm = new PackageAnalyzer(packet).Analyzed();
        if (hm.get("协议").equals("TCP") &&
                (hm.get("源IP4").equals(IP) || hm.get("源IP6").equals(IP)) &&
                hm.get("源端口").equals(Port)) {
            return true;
        }
        if (hm.get("协议").equals("TCP") &&
                (hm.get("目的IP4").equals(IP) || hm.get("目的IP6").equals(IP)) &&
                hm.get("目的端口").equals(Port)) {
            return true;
        }
        if (hm.get("协议").equals("UDP") &&
                (hm.get("源IP4").equals(IP) || hm.get("源IP6").equals(IP)) &&
                hm.get("源端口").equals(Port)) {
            return true;
        }
        if (hm.get("协议").equals("UDP") &&
                (hm.get("目的IP4").equals(IP) || hm.get("目的IP6").equals(IP)) &&
                hm.get("目的端口").equals(Port)) {
            return true;
        }
        if (hm.get("协议").equals("SCTP") &&
                (hm.get("源IP4").equals(IP) || hm.get("源IP6").equals(IP)) &&
                hm.get("源端口").equals(Port)) {
            return true;
        }
        if (hm.get("协议").equals("SCTP") && (hm.get("目的IP4").equals(IP) || hm.get("目的IP6").equals(IP)) && hm.get("目的端口").equals(Port)) {
            return true;
        }

        return false;
    }
}

