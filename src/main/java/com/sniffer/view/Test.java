package com.sniffer.view;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class Test {

    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();

        // 获取所有网络接口设备列表
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        // 选择要抓取数据包的网络接口设备
        PcapIf device = alldevs.get(0); // 选择第一个设备
        System.out.printf("Selected device: %s\n", device.getName());

        // 打开网络接口设备
        int snaplen = 64 * 1024; // 捕获数据包时的最大长度
        int flags = Pcap.MODE_PROMISCUOUS; // 设置为混杂模式
        int timeout = 10 * 1000; // 超时时间，单位为毫秒
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: %s", errbuf.toString());
            return;
        }

        // 创建并启动多个抓包线程
        int numThreads = 4;
        for (int i = 0; i < numThreads; i++) {
            new PacketCaptureThread(pcap).start();
        }
    }

    // 抓包线程类
    private static class PacketCaptureThread extends Thread {
        private Pcap pcap;

        public PacketCaptureThread(Pcap pcap) {
            this.pcap = pcap;
        }

        @Override
        public void run() {
            // 创建数据包处理器
            PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
                public void nextPacket(PcapPacket packet, String user) {
                    // 解析数据包
                    Tcp tcp = new Tcp();
                    Udp udp = new Udp();
                    if (packet.hasHeader(tcp)) {
                        System.out.printf("[%s] TCP packet captured\n", Thread.currentThread().getName());
                        // 处理TCP协议数据包
                    } else if (packet.hasHeader(udp)) {
                        System.out.printf("[%s] UDP packet captured\n", Thread.currentThread().getName());
                        // 处理UDP协议数据包
                    }
                }
            };

            // 抓取数据包并处理
            pcap.loop(Pcap.LOOP_INFINITE, handler, Thread.currentThread().getName());
        }
    }
}

