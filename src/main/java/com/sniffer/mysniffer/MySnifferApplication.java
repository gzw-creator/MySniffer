package com.sniffer.mysniffer;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class MySnifferApplication {

    public static void main(String[] args) {
        SpringApplication.run(MySnifferApplication.class, args);
//        System.out.println(System.getProperty("java.library.path"));
//        List<PcapIf> devs = new ArrayList<PcapIf>();
//        StringBuilder errsb = new StringBuilder();
//        int r = Pcap.findAllDevs(devs, errsb);
//        if (r == Pcap.NOT_OK || devs.isEmpty()) {
//            System.err.println("未获取到网卡");
//        } else {
//            System.out.println("获取到网卡：");
//            System.out.println(devs);
//        }
    }
}
