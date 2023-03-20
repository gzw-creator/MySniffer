package com.sniffer.handle;

import com.sniffer.handle.InfoHandle;
import lombok.Getter;
import lombok.Setter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;


@Getter
@Setter
public class PackageCatcher implements Runnable {
    //要抓包的设备
    private PcapIf device;
    //处理器信息
    private InfoHandle infoHandle;
    //这个类是与 libpcap 和 winpcap 库实现中的原生 pcap_t 结构对等的Java类。
    // 它提供了Java 与libpcap 库方法的直接映射。
    static Pcap pcap;

    public PackageCatcher() {
    }

    public PackageCatcher(PcapIf device, InfoHandle infoHandle) {
        this.device = device;
        this.infoHandle = infoHandle;
    }

    //休眠50ms
    public void sleep(){
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        //截断此大小的数据包
        int snapLen = Pcap.DEFAULT_JPACKET_BUFFER_SIZE;
        //网卡模式：混杂模式
        int promiscuous = Pcap.MODE_PROMISCUOUS;
        //以毫秒为单位
        int timeout = 60 * 1000;
        //如果发生错误，它将保存一个错误字符串。 错误打开 Live 将返回 null
        StringBuilder errbuf = new StringBuilder();
        //抓包开启
        pcap = Pcap.openLive(device.getName(), snapLen, promiscuous, timeout, errbuf);
        if (pcap == null) {
            System.err.println("获取数据包失败：" + errbuf.toString());
            return;
        }
        //定义处理器
        MyPcapHandler<Object> myPcapHandler = new MyPcapHandler<Object>();
        // 捕获数据包计数
        int cnt = 1;
        //我们要发送到处理程序的自定义对象
//        String user = "程哥哥";
        while (true) {
            //设置抓包速率与间隔
            long startTime = System.currentTimeMillis();
//            while (startTime + 1000 >= System.currentTimeMillis()) {
            //每个数据包将被分派到抓包处理器Handler
            pcap.loop(cnt, myPcapHandler, infoHandle);
//            }
//            try {
//                Thread.sleep(0);
//            } catch (InterruptedException e) {
//                e.printStackTrace();
//            }
            System.out.println("list的大小为：" + infoHandle.packetList.size());
        }
//        pcap.close();
    }
}

