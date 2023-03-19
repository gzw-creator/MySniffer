package com.sniffer.handle;

import com.sniffer.handle.InfoHandle;
import com.sniffer.utils.FilterUtils;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;



public class MyPcapHandler<Object> implements PcapPacketHandler<Object> {
    FilterUtils filterUtils;
    @Override
    public void nextPacket(PcapPacket packet, Object infoHandler) {
        InfoHandle Info = (InfoHandle) infoHandler;
        if (packet != null) {
            //抓到的所有包都放入
            Info.packetlist.add(packet);
            //符合条件的包放入
            if(filterUtils.IsFilter(packet, Info.FilterProtocol, Info.FilterSrcip, Info.FilterDesip, Info.FilterKey)&&
                    filterUtils.Istrace(packet, Info.TraceIP, Info.TracePort)){
                Info.analyzePacketlist.add(packet);
                Info.showTable(packet);
            }
            System.out.println(packet);
        }
    }
}

