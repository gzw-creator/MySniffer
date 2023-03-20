package com.sniffer.handle;

import com.sniffer.handle.PackageAnalyzer;
import com.sniffer.utils.FilterUtils;

import org.jnetpcap.packet.PcapPacket;

import javax.swing.table.DefaultTableModel;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;


public class InfoHandle {
    //过滤协议
    public static String FilterProtocol = "";
    //过滤源IP
    public static String FilterSrcIp = "";
    //过滤目的IP
    public static String FilterDesIp = "";
    //过滤关键字
    public static String FilterKey = "";
    //跟踪IP
    public static String TraceIP = "";
    //跟踪端口
    public static String TracePort = "";
    //抓到的包存储
    public static ArrayList<PcapPacket> packetList = new ArrayList<PcapPacket>();
    //抓到的包分析
    public static ArrayList<PcapPacket> analyzePacketList = new ArrayList<PcapPacket>();
    //UI表模型
    public static DefaultTableModel tableModel;

    public static void setFilterProtocol(String filterProtocol) {
        FilterProtocol = filterProtocol;
    }

    public static void setFilterSrcIp(String FilterSrcIp) {
        FilterSrcIp = FilterSrcIp;
    }

    public static void setFilterDesIp(String FilterDesIp) {
        FilterDesIp = FilterDesIp;
    }

    public static void setFilterKey(String filterKey) {
        FilterKey = filterKey;
    }

    public static void setTraceIP(String traceIP) {
        TraceIP = traceIP;
    }

    public static void setTracePort(String tracePort) {
        TracePort = tracePort;
    }

    public static void setTableModel(DefaultTableModel tableModel) {
        InfoHandle.tableModel = tableModel;
    }

    //将list集合清除
    public void clearAllPackets() {
        packetList.clear();
        analyzePacketList.clear();
    }

    //过滤后数据包重新显示
    public static void ShowAfterFilter() {
        FilterUtils filterUtils = new FilterUtils();
        while (tableModel.getRowCount() > 0) {
            tableModel.removeRow(tableModel.getRowCount() - 1);
        }
        analyzePacketList.clear();
        for (int i = 0; i < packetList.size(); i++) {
            if (filterUtils.IsFilter(packetList.get(i), FilterProtocol, FilterSrcIp, FilterDesIp, FilterKey)
                    && filterUtils.Istrace(packetList.get(i), TraceIP, TracePort)) {
                analyzePacketList.add(packetList.get(i));
                showTable(packetList.get(i));
            }
        }
    }

    //将抓到包的信息添加到列表
    public static void showTable(PcapPacket packet) {
        String[] rowData = getObj(packet);
        tableModel.addRow(rowData);
    }

    //将抓的包的基本信息显示在列表上，返回信息的String[]形式
    public static String[] getObj(PcapPacket packet) {
        String[] data = new String[6];
        if (packet != null) {
            //捕获时间
            Date date = new Date(packet.getCaptureHeader().timestampInMillis());
            DateFormat df = new SimpleDateFormat("HH:mm:ss");
            data[0] = df.format(date);
            HashMap<String, String> hm = new PackageAnalyzer(packet).Analyzed();
            data[1] = hm.get("源IP4").equals("未知") ? hm.get("源IP6") : hm.get("源IP4");
            data[2] = hm.get("目的IP4").equals("未知") ? hm.get("目的IP6") : hm.get("目的IP4");
            if (hm.get("源IP4").equals("未知") && hm.get("源IP6").equals("未知")) {
                data[1] = hm.get("源MAC");
            }
            if (hm.get("目的IP4").equals("未知") && hm.get("目的IP6").equals("未知")) {
                data[2] = hm.get("目的MAC");
            }
            data[3] = hm.get("协议");
            data[4] = String.valueOf(packet.getCaptureHeader().wirelen());
        }
        return data;
    }
}

