package com.sniffer.handle;

import com.sniffer.utils.FilterUtils;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class MyPcapHandler<Object> implements PcapPacketHandler<Object> {
    FilterUtils filterUtils;
    @Override
    public void nextPacket(PcapPacket packet, Object infoHandle) {
        InfoHandle Info = (InfoHandle) infoHandle;
        if (packet != null) {
            //抓到的所有包都放入
            Info.packetList.add(packet);
            //符合条件的包放入
            if(filterUtils.IsFilter(packet, Info.FilterProtocol, Info.FilterSrcIp, Info.FilterDesIp,Info.FilterSrcPort,Info.FilterDesPort)&&
                    filterUtils.IsTrace(packet, Info.TraceIP, Info.TracePort)){
                Info.analyzePacketList.add(packet);
                Info.showTable(packet);
            }
            System.out.println(packet);
        }
    }
}

