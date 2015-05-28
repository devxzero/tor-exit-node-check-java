package com.jtict.tor_exit_node_check;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Pattern;

public class ExitNodeCheck {
    private static final String ONLINE_EXIT_NODE_LIST = "https://check.torproject.org/exit-addresses";

    private static final Pattern ipPattern = Pattern.compile("\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    /**
     * Checks whether an IP address is a tor exit node by querying the Tor Project nameserver using the "Tor DNS-based Exit List" method:
     * https://trac.torproject.org/projects/tor/wiki/doc/TorDNSExitList
     *
     * Although it is named "list", there is no visible list, it's just a DNS query with a single result.
     *
     * Example: isExitNodeInTorDnsExitList("162.247.72.201", "1.1.1.1", 80)
     *
     *
     * @param exitNodeIp the IP address of the host to check whether it is a Tor Exit Node
     * @param webServerIp the IP address that the possible exitNode is trying to contact, which is usually the webserver that is running this code. An random IP address probably also works.
     * @param webServerPort the HTTP port that the possible exitNode is trying to contact. For example the default HTTP port 80.
     *
     * @exception IllegalArgumentException if the ip address is invalid
     */
    public static boolean isExitNodeInTorDnsExitList(String exitNodeIp, String webServerIp, int webServerPort) {
        assertValidIp(exitNodeIp);
        assertValidIp(webServerIp);

        String reversedExitNodeIp = reverseIpOctets(exitNodeIp);
        String reversedWebServerIp = reverseIpOctets(webServerIp);

        String dnsQuery = reversedExitNodeIp + "." + webServerPort + "." + reversedWebServerIp + "." + "ip-port.exitlist.torproject.org";
        try {
            String dnsResult = InetAddress.getByName(dnsQuery).getHostAddress();
            return "127.0.0.2".equals(dnsResult);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static String reverseIpOctets(String ip) {
        String[] ipOctets = ip.split("\\.");
        return ipOctets[3] + "." + ipOctets[2] + "." + ipOctets[1] + "." + ipOctets[0];
    }


    /**
     * Checks whether the IP address is a Tor Exit Node by looking in the online list.
     * The online list page is currently 185kbyte in size.
     *
     * @exception IllegalArgumentException if the ip address is invalid
     * @exception IllegalStateException in case of a network problem
     */
    public static boolean isExitNodeInOnlineList(String ip) {
        assertValidIp(ip);

        try (InputStream inputStream = new URL(ONLINE_EXIT_NODE_LIST).openStream()) {
            Scanner scanner = new Scanner(inputStream);
            for (String scannedIp = scanner.findWithinHorizon(ipPattern, 0); scannedIp != null; scannedIp = scanner.findWithinHorizon(ipPattern, 0)) {
                if (ip.equals(scannedIp)) {
                    return true;
                }
            }
            return false;
        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Retrieves a set of exit nodes IP-addresses from the Tor Project website.
     *
     * For more info about this list, see:
     * https://check.torproject.org/exit-addresses
     * https://check.torproject.org/cgi-bin/TorBulkExitList.py
     *
     */
    public static Set<String> retrieveOnlineExitNodes() {
        Set<String> exitNodes = new HashSet<>();
        try (InputStream inputStream = new URL(ONLINE_EXIT_NODE_LIST).openStream()) {
            Scanner scanner = new Scanner(inputStream);

            for (String scannedIp = scanner.findWithinHorizon(ipPattern, 0); scannedIp != null; scannedIp = scanner.findWithinHorizon(ipPattern, 0)) {
                exitNodes.add(scannedIp);
            }
        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return exitNodes;
    }

    private static void assertValidIp(String ip) throws IllegalStateException {
        if (ip == null || ! ipPattern.matcher(ip).matches()) {
            throw new IllegalArgumentException("Invalid ip address: " + ip);
        }
    }
}