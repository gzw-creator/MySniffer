package com.sniffer.utils;

import com.sniffer.handle.PackageAnalyzer;
import org.jnetpcap.packet.PcapPacket;

import java.util.HashMap;

public class FilterUtils {

    //设置过滤规则
    public static boolean IsFilter(PcapPacket packet, String FilterProtocol, String FilterSrcIp,
                                   String FilterDesIp, String FilterKey) {
        HashMap<String, String> hm = new PackageAnalyzer(packet).Analyzed();
        //协议过滤
        if (FilterProtocol.equals("Ethernet II")) {
            if (!hm.get("协议").equals("ETHERNET")) {
                return false;
            }
        } else if (FilterProtocol.equals("IP")) {
            if (!(hm.get("协议").equals("IP4") || hm.get("协议").equals("IP6"))) {
                return false;
            }
        } else if (FilterProtocol.equals("ICMP")) {
            if (!hm.get("协议").equals("ICMP")) {
                return false;
            }
        } else if (FilterProtocol.equals("ARP")) {
            if (!hm.get("协议").equals("ARP")) {
                return false;
            }
        } else if (FilterProtocol.equals("UDP")) {
            if (!hm.get("协议").equals("UDP")) {
                return false;
            }
        } else if (FilterProtocol.equals("TCP")) {
            if (!hm.get("协议").equals("TCP")) {
                return false;
            }
        } else if (FilterProtocol.equals("HTTP")) {
            if (!hm.get("协议").equals("HTTP")) {
                return false;
            }
        } else if (FilterProtocol.equals("")) {

        }
        //源ip地址过滤
        if (!FilterSrcIp.equals("")) {
            if (!(hm.get("源IP4").equals(FilterSrcIp) || hm.get("源IP6").equals(FilterSrcIp))) {
                return false;
            }
        }
        //目的ip地址过滤
        if (!FilterDesIp.equals("")) {
            if (!(hm.get("目的IP4").equals(FilterDesIp) || hm.get("目的IP6").equals(FilterDesIp))) {
                return false;
            }
        }
        //关键字过滤
        if (!FilterKey.equals("")) {
            if (!hm.get("包内容").contains(FilterKey)) {
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
        return false;
    }
}

