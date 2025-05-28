# 🧪 CompTIA Network+ (N10-009) Hands-on Practice Guide with Kali Linux, Raspberry Pi, and Routers

This guide provides hands-on exercises for each of the 5 major domains of the CompTIA Network+ (N10-009) certification. You can follow these step-by-step labs using:

* ✅ Kali Linux (latest version)
* ✅ Raspberry Pi (any model capable of running Raspberry Pi OS)
* ✅ GL.iNet AC1200 router (or similar OpenWrt-compatible router)
* ✅ TP-Link AC750 4G LTE router (or any consumer-grade router with a web interface)

Each domain includes **4 practice items** in increasing difficulty from basic to extremely challenging, designed to build your practical networking skills.

---

## 1.0 📡 Networking Concepts

This section focuses on the foundational principles of networking, including the OSI model, TCP/IP, and basic addressing.

### 1.1 🔰 Basic: Identify OSI Layers using Wireshark

This exercise will help you visualize the various layers of the OSI model by inspecting live network traffic.

```
# Update package lists and install Wireshark, a powerful network protocol analyzer.
sudo apt update && sudo apt install wireshark -y
# Add your current user to the 'wireshark' group to allow non-root packet capture.
sudo usermod -aG wireshark $USER
# You might need to log out and log back in for group changes to take effect.
```

**Instructions:**

1.  **Launch Wireshark:** Open a terminal and type `wireshark &`. The `&` detaches the process, allowing you to continue using the terminal.
2.  **Select Capture Interface:** In Wireshark, select `wlan0` (your wireless interface) for capturing live traffic. If you're using a wired connection, choose `eth0`.
3.  **Apply Filters:**
    * Type `http` in the filter bar and press Enter to see only HTTP (web Browse) traffic. Observe the application, presentation, and session layer interactions.
    * Change the filter to `dns` to see DNS (Domain Name System) queries and responses, focusing on the application layer.
    * Use `icmp` to observe ICMP (Internet Control Message Protocol) packets, typically related to `ping` commands, which operate at the network layer.

🔍 **Goal**: The objective is to identify how the theoretical OSI layers (Application, Presentation, Session, Transport, Network, Data Link, Physical) correspond to actual packet data displayed in Wireshark. Pay attention to the packet details pane in Wireshark, which breaks down the packet by its encapsulated protocols, often aligning with OSI layers.

---

### 1.2 🔁 Moderate: Examine TCP Handshake and TTL

This lab delves into the connection establishment process of TCP and the Time-to-Live (TTL) mechanism for preventing network loops.

```bash
# Capture TCP packets on your wireless interface (wlan0) with verbose output.
# '-i wlan0': Specifies the interface to capture on.
# 'tcp': Filters for TCP packets only.
# '-vvv': Increases verbosity, showing more detailed information about each packet.
sudo tcpdump -i wlan0 tcp -vvv
```

**Instructions:**

1.  **Observe TCP Handshake:** While `tcpdump` is running, open a web browser and navigate to a website (e.g., `google.com`). You will see a series of packets. Look for the three-way handshake:
    * `SYN` (Synchronize): Client initiates connection.
    * `SYN-ACK` (Synchronize-Acknowledge): Server acknowledges and synchronizes.
    * `ACK` (Acknowledge): Client acknowledges, and the connection is established.
2.  **Watch TTL Decrement:** In a *separate terminal*, run the following command. The `-t 10` sets a specific TTL value for the `ping` packets.

    ```bash
    ping -t 10 google.com
    ```
    Observe the `tcpdump` output as the `ping` packets are sent. You should see the `ttl` value in the `tcpdump` output decrease with each hop the packet traverses on its way to `google.com`.

🔍 **Goal**: The primary goal is to gain a practical understanding of the TCP three-way handshake and how the Time-to-Live (TTL) field in IP packets is used to prevent packets from endlessly looping on a network.

---

### 1.3 🌐 Hard: Configure a Private Network with Static IPs

This exercise focuses on manual IP address configuration, a fundamental skill for network administration, bypassing the need for DHCP.

* **Use `dhcpcd.conf` on Raspberry Pi:** This file is used to configure how `dhcpcd` (the DHCP client daemon) manages network interfaces. We'll tell it to use a static IP.

    ```bash
    # Open the dhcpcd.conf file for editing.
    sudo nano /etc/dhcpcd.conf
    ```

    Add the following lines to the end of the file. Ensure you're configuring the `eth0` (wired) interface.

    ```ini
    interface eth0
    static ip_address=192.168.10.10/24
    static routers=192.168.10.1
    static domain_name_servers=8.8.8.8
    ```
    * `interface eth0`: Specifies that these settings apply to the wired Ethernet interface.
    * `static ip_address=192.168.10.10/24`: Assigns the IP address `192.168.10.10` with a subnet mask of `255.255.255.0` (indicated by `/24`).
    * `static routers=192.168.10.1`: Sets the default gateway to `192.168.10.1`. This should be the IP address of your router on the `192.168.10.0/24` network.
    * `static domain_name_servers=8.8.8.8`: Configures Google's public DNS server for name resolution.

**Instructions:**

1.  **Edit `dhcpcd.conf`:** Add the provided configuration block to the file.
2.  **Reboot Raspberry Pi:** After saving changes, reboot the Raspberry Pi: `sudo reboot`. This ensures the new static IP configuration is applied.
3.  **Verify Configuration:** After reboot, log in and use `ip a` to confirm `eth0` has the `192.168.10.10` address.
4.  **Test Connectivity:** From another device on the same `192.168.10.0/24` network (e.g., your Kali Linux machine, after setting its IP in the same subnet), try to `ping 192.168.10.10`. Also, from the Raspberry Pi, try to `ping 8.8.8.8` and `ping google.com` to test internet connectivity and DNS resolution.

🔍 **Goal**: The objective is to successfully establish manual IP addressing on the Raspberry Pi without relying on DHCP, demonstrating a core networking configuration skill.

---

### 1.4 🧠 Extremely Hard: Build an IPv6 Network

This advanced lab explores the configuration of IPv6, the next generation of the Internet Protocol, including addressing, routing, and DNS.

```bash
# Assign a static IPv6 address to the eth0 interface.
# 'sudo ip -6 addr add 2001:db8::1/64 dev eth0':
#   'ip -6': Specifies IPv6 commands.
#   'addr add 2001:db8::1/64': Adds the IPv6 address '2001:db8::1' with a /64 prefix length.
#      '2001:db8::/64' is a common documentation prefix, use a unique local address (ULA) like 'fd00::/64'
#      if you need unique addresses that won't conflict with global routes.
#   'dev eth0': Applies the address to the 'eth0' interface.
sudo ip -6 addr add 2001:db8::1/64 dev eth0

# Add a default IPv6 route via a gateway.
# 'sudo ip -6 route add default via 2001:db8::fffe':
#   'route add default': Sets the default gateway for IPv6 traffic.
#   'via 2001:db8::fffe': Specifies the gateway's IPv6 address. This gateway
#      should be your router or another IPv6-enabled device on your network.
sudo ip -6 route add default via 2001:db8::fffe
```

**Instructions:**

1.  **Configure IPv6 on Kali Linux/Raspberry Pi:** Execute the provided commands. Replace `2001:db8::1` and `2001:db8::fffe` with appropriate addresses for your lab environment. If you don't have an IPv6-enabled router, you might need to use a tunneling service or simulate one with another Linux machine.
2.  **Test with `ping6`:**

    ```bash
    ping6 google.com
    ```
    This command specifically uses IPv6 to ping `google.com`. If successful, it indicates that your IPv6 addressing, routing, and DNS resolution are working.
3.  **Verify Configuration:** Use `ip -6 a` to check the assigned IPv6 address and `ip -6 route` to confirm the default route.

🔍 **Goal**: The goal is to successfully practice IPv6 addressing, routing configuration, and DNS resolution within a local network environment. This requires a deeper understanding of IPv6 concepts and potentially setting up an IPv6-enabled router or a tunnel.

---

## 2.0 ⚙️ Network Implementation

This section focuses on practical implementation of network services and technologies, including VLANs, NAT, and wireless access points.

### 2.1 🔰 Basic: Setup VLANs on OpenWrt (GL.iNet)

This exercise introduces Virtual Local Area Networks (VLANs), allowing you to segment a single physical network into multiple logical networks on a SOHO router.

**Instructions:**

1.  **Access LuCI Web UI:** Connect to your GL.iNet router's web interface (usually `192.168.8.1` or `192.168.1.1`). If prompted, log in with your credentials.
2.  **Navigate to Network > Switch:** In the LuCI interface, go to `Network` -> `Switch`. This section allows you to configure the internal switch chip of the router.
3.  **Create VLAN 10:**
    * Look for an option to "Add VLAN" or similar.
    * Enter `10` as the VLAN ID.
    * **Assign to Port:** Decide which physical LAN port you want to assign to this new VLAN. You will typically see a matrix of switch ports and VLAN IDs.
    * **Tag CPU Port:** Ensure the CPU port (which connects the router's main processor to the switch) is *tagged* for VLAN 10. This allows the router's software to manage traffic for VLAN 10.
    * **Untag Desired Port:** For the chosen physical LAN port, set it to *untagged* for VLAN 10. This means devices connected to this port will automatically be in VLAN 10 without needing to be VLAN-aware.
    * **Disable other VLANs on the port:** Ensure the chosen port is *off* or *not tagged/untagged* for other VLANs (e.g., VLAN 1, the default LAN).
4.  **Save and Apply:** Apply the changes. Your router will likely reboot or restart its network services.
5.  **Test VLAN:** Connect a device (e.g., your Raspberry Pi or Kali Linux machine) to the physical port you assigned to VLAN 10. If you have DHCP configured for VLAN 10 on the router, the device should receive an IP address from the VLAN 10 subnet. If not, you'll need to statically assign an IP address within the VLAN 10 subnet (e.g., `192.168.10.X`).

🔍 **Goal**: The goal is to understand and practically configure VLANs on a SOHO router running OpenWrt, demonstrating the ability to segment a network.

---

### 2.2 🔁 Moderate: Setup NAT on Kali Linux

This lab simulates Network Address Translation (NAT) on your Kali Linux machine, mimicking how a home router shares a single public IP address among multiple private IP addresses.

```bash
# Enable IP forwarding, which allows the kernel to route packets between interfaces.
# This is crucial for NAT to function.
sudo sysctl -w net.ipv4.ip_forward=1

# Configure iptables for NAT (specifically, masquerading).
# 'iptables': The command-line utility for configuring the Linux kernel firewall.
# '-t nat': Specifies the 'nat' table, used for Network Address Translation.
# '-A POSTROUTING': Appends a rule to the POSTROUTING chain. This chain is
#    processed just before packets leave the local system.
# '-o wlan0': Specifies the outgoing interface (your internet-facing interface).
# '-j MASQUERADE': The target action. Masquerading dynamically substitutes
#    the source IP address of outgoing packets with the IP address of the
#    'wlan0' interface, allowing multiple internal devices to share one public IP.
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
```

**Instructions:**

1.  **Connect Kali Linux:** Ensure your Kali Linux machine has two network interfaces: one connected to the internet (e.g., `wlan0`) and another (e.g., `eth0`) connected to a *private network* segment where other devices (like your Raspberry Pi) can connect.
2.  **Enable IP Forwarding:** Execute the `sysctl` command.
3.  **Configure `iptables`:** Execute the `iptables` command.
4.  **Configure Clients:** On your Raspberry Pi or another client device connected to Kali's `eth0` interface, configure its default gateway to be the IP address of Kali's `eth0` interface. You might also need to assign a static IP to Kali's `eth0` (e.g., `192.168.100.1/24`).
5.  **Test Connectivity:** From the client device, try to `ping 8.8.8.8` and access a website. If successful, your Kali Linux machine is acting as a NAT router.

🔍 **Goal**: The goal is to simulate home router NAT functionality on Kali Linux, demonstrating how internal private IP addresses are translated to a single public IP address for internet access.

---

### 2.3 🌐 Hard: Configure a Wireless Access Point on Raspberry Pi

This lab transforms your Raspberry Pi into a functional wireless access point, allowing other devices to connect to it wirelessly with WPA2 security.

```bash
# Install 'hostapd' (Host Access Point Daemon) for creating the wireless AP,
# and 'dnsmasq' for providing DHCP and DNS services to connected clients.
sudo apt install hostapd dnsmasq
```

**Instructions:**

1.  **Configure `/etc/hostapd/hostapd.conf`:** Open the file and add the following configuration. Remember to adjust `ssid` and `wpa_passphrase`.

    ```ini
    interface=wlan0
    ssid=PiAccess
    hw_mode=g
    channel=6
    auth_algs=1
    wpa=2
    wpa_passphrase=raspberrysecure
    wpa_key_mgmt=WPA-PSK
    rsn_pairwise=CCMP
    driver=nl80211
    ```
    * `interface=wlan0`: Specifies the wireless interface to use as the AP.
    * `ssid=PiAccess`: The name of your wireless network.
    * `hw_mode=g`: Sets the wireless mode to 802.11g (compatible with most devices).
    * `channel=6`: Sets the wireless channel.
    * `auth_algs=1`: Enables WPA/WPA2 authentication.
    * `wpa=2`: Uses WPA2 for security.
    * `wpa_passphrase=raspberrysecure`: Your Wi-Fi password (change this!).
    * `wpa_key_mgmt=WPA-PSK`: Uses Pre-Shared Key for authentication.
    * `rsn_pairwise=CCMP`: Specifies the cipher suite (AES).
    * `driver=nl80211`: Specifies the driver interface for `hostapd`.

2.  **Configure `/etc/dnsmasq.conf`:** This file configures DHCP and DNS for your AP. Add the following:

    ```ini
    interface=wlan0
    dhcp-range=192.168.4.10,192.168.4.200,255.255.255.0,24h
    server=8.8.8.8
    ```
    * `interface=wlan0`: Dnsmasq will listen for DHCP requests on this interface.
    * `dhcp-range`: Defines the IP address range for DHCP clients and the subnet mask.
    * `server=8.8.8.8`: Sets Google's public DNS server as the DNS resolver for clients.

3.  **Configure Static IP for `wlan0`:** You need to give your Pi's `wlan0` interface a static IP address for the AP. Edit `/etc/dhcpcd.conf` (or directly using `ip addr` if you understand temporary settings):

    ```ini
    interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
    ```

4.  **Enable IP Forwarding (if connecting to the Internet):** If you want devices connected to your Pi AP to access the internet, enable IP forwarding (see Section 2.2). You'll also need to set up NAT.

5.  **Start Services:**

    ```bash
    sudo systemctl unmask hostapd
    sudo systemctl enable hostapd
    sudo systemctl start hostapd
    sudo systemctl enable dnsmasq
    sudo systemctl start dnsmasq
    ```
    Ensure `hostapd` and `dnsmasq` are running. Check their status with `sudo systemctl status hostapd` and `sudo systemctl status dnsmasq`.

6.  **Test AP:** From another device, scan for Wi-Fi networks. You should see "PiAccess". Connect to it using "raspberrysecure" as the password. Verify you get an IP address from the 192.168.4.x range and can access the internet (if NAT is configured).

🔍 **Goal**: The goal is to successfully turn the Raspberry Pi into a full-fledged wireless access point with WPA2 security, providing network access to other devices.

---

### 2.4 🧠 Extremely Hard: BGP Setup with Containers (FRRouting)

This advanced lab provides an introduction to enterprise routing protocols by using Docker containers to simulate routers running BGP (Border Gateway Protocol) with FRRouting.

```bash
# Pull the FRRouting Docker image.
sudo docker pull frrouting/frr

# Run a Docker container named 'frr1' in interactive mode.
# '--name frr1': Assigns a name to the container.
# '-it': Runs in interactive mode with a pseudo-TTY.
# 'frrouting/frr': The Docker image to use.
# 'bash': The command to execute inside the container (starts a bash shell).
sudo docker run --name frr1 -it frrouting/frr bash
```

**Instructions:**

1.  **Launch FRRouting Containers:** You'll need at least two containers to simulate a BGP peering. Repeat the `docker run` command to create `frr2`.
2.  **Configure Networking between Containers:** This is a crucial step. You'll need to create a Docker network that allows your FRR containers to communicate.

    ```bash
    sudo docker network create --subnet=172.18.0.0/24 frr_net
    sudo docker network connect frr_net frr1
    sudo docker network connect frr_net frr2
    ```
    Then, assign IP addresses to the virtual interfaces within the containers (e.g., `ip addr add 172.18.0.10/24 dev eth0` in `frr1`, and `172.18.0.20/24` in `frr2`).
3.  **Configure BGP inside Container:**
    * Once inside the `frr1` container's bash shell, enter the FRR command-line interface: `vtysh`.
    * Enable configuration mode: `conf t`
    * Configure BGP:

        ```
        router bgp 65001 # Your Autonomous System number
        neighbor 172.18.0.20 remote-as 65002
        network 1.1.1.0/24 # Advertise a dummy network
        exit
        write mem
        ```
    * Repeat similar steps for `frr2`, peering with `frr1` and using a different AS number (e.g., `65002`).
4.  **Verify BGP Peering:** Use `show ip bgp summary` in `vtysh` in both containers to verify that the BGP sessions are established. Try `ping` between the container IPs.

🔍 **Goal**: The goal is to successfully emulate enterprise routing protocols, specifically BGP, using containerization, providing hands-on experience with routing concepts often seen in large networks.

---

## 3.0 🧭 Network Operations

This section focuses on the day-to-day management, monitoring, and documentation of network infrastructure.

### 3.1 🔰 Basic: Document the Physical Network

Network documentation is critical for understanding, troubleshooting, and expanding network infrastructure.

**Instructions:**

1.  **Install Diagramming Software:**
    * **draw.io (online/desktop):** Access `app.diagrams.net` in your web browser or download the desktop application.
    * **Dia (Linux):** `sudo apt install dia`
2.  **Identify Components:** Physically identify the following devices in your lab setup:
    * **Routers:** Your GL.iNet and TP-Link routers. Note their models and primary IP addresses.
    * **Raspberry Pi:** Note its IP address and primary function (e.g., AP, server).
    * **Kali Linux:** Note its IP address and current role (e.g., client, attacker).
3.  **Map Connections:** Trace the physical cables connecting these devices (e.g., Kali Linux `eth0` to GL.iNet LAN port, Raspberry Pi `wlan0` to GL.iNet Wi-Fi). Note if connections are wired or wireless.
4.  **Create Diagram:** Using your chosen software, draw a clear and concise diagram. Use standard network icons (rectangles for devices, lines for connections). Label IP addresses, interface names (e.g., `eth0`, `wlan0`), and any specific roles.

🔍 **Goal**: The goal is to create basic, accurate network topology diagrams that visually represent the physical layout and connections of your lab environment.

---

### 3.2 🔁 Moderate: Monitor Network with `iftop`

`iftop` is a command-line utility that displays network bandwidth usage in real-time, helping you identify bandwidth hogs.

```bash
# Install iftop from your system's package repositories.
sudo apt install iftop
# Run iftop on your wireless interface (wlan0) to monitor traffic.
# '-i wlan0': Specifies the interface to monitor.
sudo iftop -i wlan0
```

**Instructions:**

1.  **Run `iftop`:** Execute the command.
2.  **Generate Traffic:** While `iftop` is running, perform some network-intensive activities:
    * Download a large file.
    * Stream a video.
    * Browse several websites.
    * Run a `ping` command to a remote server.
3.  **Observe Output:**
    * `iftop` will show a list of connections, their source and destination IP addresses, and the real-time bandwidth usage (Tx and Rx).
    * Pay attention to the peak and average bandwidth columns.
    * Use `p` to toggle port display, `s` to sort by source, `d` to sort by destination.

🔍 **Goal**: The goal is to observe and understand real-time traffic volume per network connection, enabling you to identify which hosts and services are consuming bandwidth.

---

### 3.3 🌐 Hard: Setup `ntopng` for Flow Analysis

`ntopng` is a powerful network traffic analysis tool that provides flow-based monitoring, offering detailed insights into protocols, applications, and hosts.

```bash
# Install ntopng. It often brings in its dependencies, including nDPI.
sudo apt install ntopng
# Enable ntopng to start automatically on boot.
sudo systemctl enable ntopng
# Start the ntopng service immediately.
sudo systemctl start ntopng
```

**Instructions:**

1.  **Install and Start:** Execute the commands to install and enable/start `ntopng`.
2.  **Access Web UI:** Open a web browser and navigate to `http://localhost:3000`. The default username is `admin` and the default password is `admin`. You will be prompted to change it on the first login.
3.  **Configure Interface:** In the ntopng web UI, you might need to select the network interface you want to monitor (e.g., `wlan0` or `eth0`).
4.  **Explore Data:** Generate network traffic and then explore the various dashboards in `ntopng`:
    * **Hosts:** See which hosts are most active.
    * **Interfaces:** Get an overview of traffic on your selected interface.
    * **Protocols:** See the breakdown of traffic by application protocol (e.g., HTTP, DNS, SSL/TLS).
    * **Flows:** Examine individual network connections and their characteristics.

🔍 **Goal**: The goal is to successfully set up `ntopng` and utilize its features for flow-based analysis of network protocols, applications, and hosts, providing deeper insights than simple bandwidth monitoring.

---

### 3.4 🧠 Extremely Hard: Build Your Own SIEM (Wazuh + ELK)

This highly challenging lab simulates an enterprise Security Information and Event Management (SIEM) system by integrating Wazuh for security monitoring with the ELK Stack (Elasticsearch, Logstash, Kibana) for log aggregation and visualization.

**Instructions:**

1.  **Install Wazuh Manager on Raspberry Pi:**
    * Follow the official Wazuh documentation for installing the Manager on Debian/Ubuntu, which Raspberry Pi OS is based on. This involves adding the Wazuh repository and installing packages.
    * The Manager is the central component that collects, analyzes, and correlates alerts from agents.
2.  **Install Filebeat on Raspberry Pi (as an agent):**
    * Filebeat is a lightweight shipper for forwarding logs. You'll configure Filebeat to send system logs from the Raspberry Pi to your ELK stack.
    * Follow Wazuh's guide for installing Filebeat as an agent on Linux.
3.  **Forward Logs to ELK Stack on Kali or VM:**
    * **Install ELK Stack on Kali Linux or a dedicated VM:** This is a resource-intensive step. You'll need Elasticsearch (for data storage and search), Logstash (for log processing and forwarding), and Kibana (for visualization). Use a machine with at least 8GB RAM for a smooth experience.
    * **Configure Logstash:** Create a Logstash configuration file to receive logs from Filebeat (sent by the Wazuh agent on the Raspberry Pi) and output them to Elasticsearch.
    * **Configure Kibana:** Access Kibana's web UI (usually `http://localhost:5601`).
    * **Integrate Wazuh with Kibana:** Install the Wazuh Kibana plugin to visualize security alerts and data from your Wazuh Manager.
4.  **Generate and Observe Logs:** Trigger some events on your Raspberry Pi (e.g., failed SSH logins, user creation, package installations). Observe how these logs are collected by the Wazuh agent, forwarded by Filebeat, processed by Logstash, stored in Elasticsearch, and visualized in Kibana and the Wazuh plugin.

🔍 **Goal**: The goal is to successfully emulate enterprise log correlation and security event management by building a basic SIEM system with Wazuh and the ELK stack, demonstrating an advanced understanding of security operations.

---

## 4.0 🔐 Network Security

This section covers essential network security practices, from basic device hardening to advanced threat detection and access control.

### 4.1 🔰 Basic: Change Router Default Passwords

This fundamental security practice protects your network from unauthorized access by preventing attackers from using well-known default credentials.

**Instructions:**

1.  **Login to Router UI:**
    * **GL.iNet:** Access the web interface (usually `192.168.8.1`). The default password for new GL.iNet routers is often `goodlife`.
    * **TP-Link:** Access the web interface (usually `192.168.0.1` or `192.168.1.1`). Default credentials are often `admin/admin`.
2.  **Navigate to Admin Settings:** Look for sections like "System," "Administration," "Management," or "Security" within the router's web UI.
3.  **Change Passwords:** Locate the option to change the administrator password. Choose a strong, unique password that includes a mix of uppercase and lowercase letters, numbers, and symbols.
4.  **Disable Remote Administration (if enabled and not needed):** If your router has a feature for remote management (accessing the UI from outside your local network), ensure it is disabled unless you specifically require it for remote access, as it can be a security risk.

🔍 **Goal**: The goal is to apply basic device hardening by changing default router passwords and disabling unnecessary remote administration, improving the overall security posture of your network devices.

---

### 4.2 🔁 Moderate: Enable WPA3 + Disable WPS

This lab focuses on implementing modern wireless security standards and mitigating vulnerabilities associated with older, less secure features.

**Instructions:**

1.  **Check Router Firmware:**
    * **GL.iNet:** Many newer GL.iNet models support WPA3. Ensure your router's firmware is up to date, as WPA3 support is often added in later versions.
    * **TP-Link:** Check your specific TP-Link model's specifications and firmware updates for WPA3 support. If not supported, use WPA2-Enterprise or WPA2-PSK (AES) as the strongest available option.
2.  **Access Router UI:** Log in to your GL.iNet or TP-Link router's web interface.
3.  **Navigate to Wireless Settings:** Go to the "Wireless" or "Wi-Fi" section.
4.  **Enable WPA3 (or WPA2-AES):**
    * Look for "Security Mode" or "Encryption Type."
    * If WPA3 is an option, select "WPA3-Personal" or "WPA3-SAE."
    * If WPA3 is not available, ensure you select "WPA2-PSK" with "AES" (often called "WPA2-PSK [AES]" or "WPA2/WPA3 Mixed Mode"). Avoid TKIP.
5.  **Disable WPS:**
    * Look for a section related to "WPS" (Wi-Fi Protected Setup).
    * Disable this feature. WPS is known to have security vulnerabilities that can allow attackers to brute-force your Wi-Fi password.
6.  **Save and Apply:** Save the changes. Your router's Wi-Fi network will likely restart, and you'll need to reconnect your devices.

🔍 **Goal**: The goal is to enforce modern wireless encryption standards (WPA3 or strong WPA2) and disable the vulnerable WPS feature, significantly enhancing the security of your wireless network.

---

### 4.3 🌐 Hard: Detect Rogue AP with Kali Linux

This exercise teaches you how to identify rogue access points (APs) or "evil twin" attacks, where an attacker sets up a fake AP to trick users into connecting.

```bash
# Put the wireless interface into monitor mode.
# 'sudo airmon-ng start wlan0': Sets the wlan0 interface to monitor mode,
#    often creating a new monitor interface (e.g., wlan0mon).
sudo airmon-ng start wlan0

# Start airodump-ng to capture raw 802.11 frames and identify APs and clients.
# 'sudo airodump-ng wlan0mon': Scans for wireless networks using the monitor interface.
sudo airodump-ng wlan0mon
```

**Instructions:**

1.  **Prepare Kali Linux:** Ensure your Kali Linux machine has a compatible wireless adapter that supports monitor mode.
2.  **Start Monitor Mode:** Execute `sudo airmon-ng start wlan0`. Note the name of the new monitor interface (e.g., `wlan0mon`).
3.  **Scan for APs:** Execute `sudo airodump-ng wlan0mon`.
4.  **Look for Rogue APs:**
    * Observe the `airodump-ng` output. It lists detected APs (BSSIDs) and their SSIDs.
    * **Scenario 1 (Rogue AP):** If you see an SSID that is not yours but appears to be part of your network (e.g., a "free Wi-Fi" network that you didn't set up), it could be a rogue AP.
    * **Scenario 2 (Evil Twin):** Look for duplicate SSIDs with *different BSSIDs (MAC addresses)*. An evil twin attack involves an attacker creating an AP with the same SSID as a legitimate one to trick users. The different MAC address is the key indicator.
5.  **Analysis:** For any suspicious SSIDs, note their BSSID, channel, and encryption. Further investigation might involve deauthentication attacks or client probing to identify the source.

🔍 **Goal**: The goal is to practically detect rogue access points or "evil twin" attacks by using Kali Linux's `airmon-ng` and `airodump-ng` tools to identify duplicate SSIDs with different MAC addresses, a common indicator of such threats.

---

### 4.4 🧠 Extremely Hard: Implement 802.1X with FreeRADIUS

This highly advanced lab introduces enterprise-grade network access control using 802.1X authentication with FreeRADIUS, providing centralized authentication for wired and wireless clients.

**Instructions:**

1.  **Use Raspberry Pi as FreeRADIUS server:**
    * **Install FreeRADIUS:** `sudo apt install freeradius`
    * **Configure Clients:** Edit `/etc/freeradius/3.0/clients.conf` to define your router(s) as RADIUS clients, including a shared secret.
    * **Configure Users:** Edit `/etc/freeradius/3.0/users` to define test user accounts and their passwords (e.g., `testuser Cleartext-Password := "testpass"`). In a real environment, you'd integrate with a directory like LDAP or Active Directory.
    * **Configure EAP (for WPA-Enterprise):** If you're setting up WPA2-Enterprise, you'll need to configure the EAP module (e.g., PEAP or TTLS) and potentially generate certificates if you're using a secure EAP type.
    * **Start FreeRADIUS:** `sudo systemctl start freeradius` and `sudo systemctl status freeradius`. You can also run in debug mode: `sudo freeradius -X` to see authentication attempts.
2.  **Configure Router with RADIUS Backend:**
    * **GL.iNet/OpenWrt:** Log in to your router's LuCI web UI.
    * Navigate to your Wi-Fi settings (or wired LAN settings if applicable).
    * Change the security mode to "WPA2-Enterprise" (or "WPA3-Enterprise" if supported).
    * Enter the IP address of your Raspberry Pi (FreeRADIUS server) as the RADIUS server, the authentication port (typically `1812`), and the shared secret you configured in `clients.conf`.
3.  **Test 802.1X Authentication:**
    * From a client device (e.g., Kali Linux, another PC), try to connect to the Wi-Fi network.
    * When prompted for credentials, enter the username and password you defined in `users` file on the FreeRADIUS server.
    * Monitor the FreeRADIUS debug output to see the authentication requests and responses. A successful connection indicates correct configuration.

🔍 **Goal**: The goal is to emulate enterprise access control by successfully implementing 802.1X authentication using a Raspberry Pi as a FreeRADIUS server and configuring a router to use this RADIUS backend for client authentication.

---

## 5.0 🛠️ Network Troubleshooting

This section provides hands-on experience with common network troubleshooting methodologies and tools.

### 5.1 🔰 Basic: Check IP Config and Link Status

This fundamental troubleshooting step involves verifying local network interface configurations and physical link integrity.

```bash
# Display IP addresses, network masks, and broadcast addresses for all interfaces.
ip a
# Show statistics and status for a specific Ethernet interface (eth0).
# This provides details like link speed, duplex mode, and cable detection.
ethtool eth0
# Send ICMP echo requests to Google's public DNS server (8.8.8.8) to check basic internet connectivity.
ping 8.8.8.8
```

**Instructions:**

1.  **Check IP Configuration:** On your Kali Linux machine or Raspberry Pi, run `ip a`.
    * Verify that your interfaces (`eth0`, `wlan0`) have expected IP addresses (e.g., within the correct subnet).
    * Check the subnet mask (`/24` for `255.255.255.0`).
    * Ensure the interface status is `UP`.
2.  **Check Link Status:** If using a wired connection, run `ethtool eth0` (replace `eth0` with your wired interface name).
    * Look for "Link detected: yes".
    * Verify "Speed" and "Duplex" settings match your network (e.g., 1000Mb/s, Full).
3.  **Test Basic Connectivity:** Run `ping 8.8.8.8`.
    * Successful pings indicate that your device has an IP address, a default gateway, and can reach the internet at least to the DNS server.
    * If `ping` fails, it suggests issues with IP configuration, gateway, or upstream connectivity.

🔍 **Goal**: The goal is to identify common configuration issues and verify basic network connectivity by checking IP addresses, link status, and performing simple pings.

---

### 5.2 🔁 Moderate: Use Traceroute to Detect Routing Issues

`traceroute` is a utility that displays the path (hops) a packet takes to reach a destination, helping to pinpoint where network latency or routing problems occur.

```bash
# Trace the route to google.com, showing each router (hop) the packet traverses.
traceroute google.com
```

**Instructions:**

1.  **Run `traceroute`:** Execute the command from your Kali Linux machine or Raspberry Pi.
2.  **Analyze Output:**
    * Each numbered line in the output represents a "hop" (a router or gateway).
    * The IP address shown is the address of the device at that hop.
    * The three time values (e.g., `1.234 ms 2.345 ms 3.456 ms`) represent the round-trip time for three probes sent to that hop.
    * **Identify Delays:** Notice any significant increases in RTT values at a particular hop, which could indicate congestion or a problem with that router.
    * **Identify Routing Issues:** If `traceroute` stops responding or shows `* * *` for multiple hops, it suggests a routing problem or a firewall blocking ICMP.
    * Compare the path to your expectations.

🔍 **Goal**: The goal is to understand path traversal and detect routing issues or network delays by using `traceroute` to identify the sequence of hops and their respective response times.

---

### 5.3 🌐 Hard: Analyze Logs with `journalctl` and `syslog`

Log analysis is crucial for troubleshooting as system and application messages often contain clues about network problems.

```bash
# Display all journal entries, including detailed information (-x) and follow (-e) to the end.
# 'journalctl': A utility for querying and displaying logs from the systemd journal.
# '-x': Adds explanations for relevant log entries (e.g., error codes).
# '-e': Shows the end of the journal (most recent entries).
journalctl -xe

# Continuously display the last lines of the syslog file.
# 'tail -f': Continuously outputs new data appended to a file.
# '/var/log/syslog': The standard system log file on many Linux distributions.
sudo tail -f /var/log/syslog
```

**Instructions:**

1.  **Inspect `journalctl`:** Run `journalctl -xe`.
    * Look for "red" or "yellow" entries indicating errors, warnings, or failed services.
    * Search for terms related to networking (e.g., `network`, `dhcp`, `wlan0`, `eth0`, `failed`, `error`).
    * You can also filter by service: `journalctl -u network-manager.service` or `journalctl -u dhcpcd.service`.
2.  **Monitor `syslog`:** In a separate terminal, run `sudo tail -f /var/log/syslog`.
    * While monitoring, perform some network actions (e.g., disconnect/reconnect Wi-Fi, try to get a DHCP lease).
    * Observe the log entries in real-time. Look for messages related to network interface state changes, DHCP lease attempts, or connection failures.
3.  **Correlate Events:** Try to correlate events in the logs with network issues you're experiencing. For example, if a device isn't getting an IP address, check `syslog` for DHCP-related errors.

🔍 **Goal**: The goal is to effectively use `journalctl` and `tail -f /var/log/syslog` to analyze system and application logs, enabling log-based issue detection for network problems.

---

### 5.4 🧠 Extremely Hard: Use Wireshark to Diagnose DHCP Failures

This advanced troubleshooting lab uses Wireshark for deep packet inspection to diagnose complex DHCP (Dynamic Host Configuration Protocol) client failures.

**Instructions:**

1.  **Launch Wireshark:** Open Wireshark on your Kali Linux machine or Raspberry Pi.
2.  **Capture on Relevant Interface:** Start capturing on the interface that is attempting to get a DHCP lease (e.g., `eth0` or `wlan0`).
3.  **Filter for DHCP Traffic:** In the Wireshark filter bar, use `bootp` or `dhcp` (DHCP is built on BOOTP).
4.  **Simulate DHCP Failure (if possible):**
    * If you have a device that's failing to get an IP, initiate a DHCP request (e.g., `sudo dhclient -r eth0 && sudo dhclient eth0` to release and renew the lease).
    * Alternatively, you can intentionally misconfigure your DHCP server (if you have one) or your client to simulate a failure.
5.  **Inspect DHCP Offer/Request:**
    * **DHCP Discover:** Client broadcasts a `DHCP Discover` packet.
    * **DHCP Offer:** DHCP server responds with a `DHCP Offer` (proposing an IP address).
    * **DHCP Request:** Client requests the offered IP.
    * **DHCP ACK:** Server acknowledges the request.
    * **Troubleshooting Scenarios:**
        * **No DHCP Offer:** The client sends a `Discover`, but no `Offer` is received. This could mean the DHCP server is down, on a different VLAN/subnet, or a firewall is blocking the traffic.
        * **Offer but no Request:** The client receives an `Offer` but doesn't send a `Request`. This might indicate an IP conflict or an issue with the client's network stack.
        * **Request but no ACK:** The client sends a `Request`, but no `ACK` is received. This could be a misconfigured DHCP server, an IP address pool exhaustion, or a routing issue preventing the ACK from reaching the client.
    * Examine the detailed information within each DHCP packet in Wireshark's packet details pane. Look for error messages, incorrect options, or unexpected values.

🔍 **Goal**: The goal is to perform a deep analysis of misconfigured DHCP scenarios using Wireshark, understanding the DHCP four-way handshake (Discover, Offer, Request, ACK) and pinpointing the exact point of failure based on packet inspection.

---

## 🧩 Suggestions for Extension

* **Integrate Docker Compose for lab orchestration:** Use `docker-compose.yml` files to define and run multi-container Docker applications, simplifying the setup of complex labs like the BGP or SIEM environments. This allows you to bring up and tear down entire network topologies with a single command.
* **Use GNS3 for simulating full virtual networks:** GNS3 (Graphical Network Simulator-3) is a powerful tool for simulating complex network topologies. You can integrate real operating systems (like Kali Linux or Raspberry Pi OS as VMs) and virtual routers/switches, allowing you to design and test large-scale network designs without physical hardware.
* **Build GitHub Actions to validate lab submissions automatically:** For educators or self-learners, create automated tests using GitHub Actions. For example, a student submits their `dhcpcd.conf` file, and a GitHub Action VM spins up, applies the config, and pings a target to ensure connectivity, providing instant feedback on their lab success.
```
