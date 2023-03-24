package com.sniffer.utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ProcessUtils {

//    public static void main(String[] args) {
//        System.out.println(getProcessId("UDP","889","889"));
//    }
    public static String getProcessId(String protocol,String sourcePort, String destinationPort) {
        String cmd = String.format("cmd /C netstat -ano | findstr %s | findstr %s", sourcePort, destinationPort);
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] tokens = line.trim().split("\\s+");
                if (tokens.length >= 5) {
                    String pidString = tokens[4];
                    if(protocol.equals(tokens[0]))
                        return pidString;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "-1";
    }
}
