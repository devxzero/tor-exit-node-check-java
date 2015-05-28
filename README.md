# Tor Exit Node Check Java #
## Usage ##
```
import com.jtict.tor_exit_node_check.ExitNodeCheck;
// ...

// Check using the "Tor DNS-based Exit List" method
boolean isTorExitNode1 = ExitNodeCheck.isExitNodeInTorDnsExitList("162.247.72.201", "1.1.1.1", 80);

// Check using the Tor Project online list
boolean isTorExitNode2 = ExitNodeCheck.isExitNodeInOnlineList("162.247.72.201");

// Get a set of Tor Project exit nodes IP addresses
Set<String> ips = retrieveOnlineExitNodes();
```