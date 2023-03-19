package com.sniffer.hardware;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;



public class NetworkCard {
    //所有网卡列表
    List<PcapIf> alldevs = new ArrayList<PcapIf>();
    //报错信息
    StringBuilder errbuf = new StringBuilder();

    @Test
    public List<PcapIf> getAlldevs() {
        //读取网卡
        int r = Pcap.findAllDevs(alldevs, errbuf);
        //判断是否读取成功
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can’t read list of devices, error is %s", errbuf.toString());
            return alldevs;
        }
        System.out.println("Network devices found:");
        return alldevs;
    }
}

