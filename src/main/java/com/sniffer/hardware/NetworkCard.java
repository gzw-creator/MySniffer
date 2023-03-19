package com.sniffer.hardware;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;



public class NetworkCard {
    //networkCard list
    List<PcapIf> allDevice = new ArrayList<PcapIf>();

    StringBuilder errInfo = new StringBuilder();

    //Test whether my network card can be detected
    @Test
    public List<PcapIf> getAllDevice() {
        //get card info
        int r = Pcap.findAllDevs(allDevice, errInfo);

        if (r == Pcap.NOT_OK || allDevice.isEmpty()) {
            System.err.printf("Can’t read list of devices, error is %s", errInfo.toString());
            return allDevice;
        }
        System.out.println("Network devices found:");
        return allDevice;
    }
}

