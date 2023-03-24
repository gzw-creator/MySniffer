package com.sniffer.utils;

import com.sniffer.handle.PackageAnalyzer;
import org.jnetpcap.packet.PcapPacket;

import java.util.HashMap;

public class FilterUtils {

    //设置过滤规则
    public static boolean IsFilter(PcapPacket packet, String filterProtocol, String filterSrcIp,
                                   String filterDesIp,String filterSrcPort,String filterDesPort) {
        HashMap<String, String> hm = new PackageAnalyzer(packet).Analyzed();
        try {
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
        }catch (NullPointerException e){
            e.printStackTrace();
        }
        return true;
    }

    //设置追踪规则
    public static boolean IsTrace(PcapPacket packet,String srcIp,String desIp,String srcPort, String desPort) {

        HashMap<String, String> hm = new PackageAnalyzer(packet).Analyzed();
        String dSrcIp = hm.get("源IP4").equals("未知") ? hm.get("源IP6") : hm.get("源IP4");
        String dDesIp = hm.get("目的IP4").equals("未知") ? hm.get("目的IP6") : hm.get("目的IP4");
        if(hm.get("源端口").equals(srcPort)&&hm.get("目的端口").equals(desPort)&&dSrcIp.equals(srcIp)&&dDesIp.equals(desIp))
            return true;

        return false;
    }
}

