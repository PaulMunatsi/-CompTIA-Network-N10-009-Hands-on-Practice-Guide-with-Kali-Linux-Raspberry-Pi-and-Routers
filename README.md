# 🧪 CompTIA Network+ (N10-009) Hands-on Practice Guide with Kali Linux, Raspberry Pi, and Routers

This guide provides hands-on exercises for each of the 5 major domains of the CompTIA Network+ (N10-009) certification. You can follow these step-by-step labs using:

* ✅ Kali Linux (latest version)
* ✅ Raspberry Pi
* ✅ GL.iNet AC1200 router
* ✅ TP-Link AC750 4G LTE router

Each domain includes **4 practice items** in increasing difficulty from basic to extremely challenging.

---

## 1.0 📡 Networking Concepts

### 1.1 🔰 Basic: Identify OSI Layers using Wireshark

```bash
# Install Wireshark
sudo apt update && sudo apt install wireshark -y
sudo usermod -aG wireshark $USER
```

* Launch Wireshark: `wireshark &`
* Capture on `wlan0`
* Use filters: `http`, `dns`, `icmp`

🔍 **Goal**: Identify how OSI layers correspond to actual packet data.

---

### 1.2 🔁 Moderate: Examine TCP Handshake and TTL

```bash
# Capture packets with tcpdump
sudo tcpdump -i wlan0 tcp -vvv
```

* Observe `SYN`, `SYN-ACK`, `ACK`
* Watch TTL decrement across hops with:

```bash
ping -t 10 google.com
```

🔍 **Goal**: Understand TCP state and TTL behavior.

---

### 1.3 🌐 Hard: Configure a Private Network with Static IPs

* Use `dhcpcd.conf` on Raspberry Pi:

```bash
sudo nano /etc/dhcpcd.conf
```

```ini
interface eth0
static ip_address=192.168.10.10/24
static routers=192.168.10.1
static domain_name_servers=8.8.8.8
```

🔍 **Goal**: Establish manual IP addressing without DHCP.

---

### 1.4 🧠 Extremely Hard: Build an IPv6 Network

```bash
# Assign static IPv6
sudo ip -6 addr add 2001:db8::1/64 dev eth0
sudo ip -6 route add default via 2001:db8::fffe
```

* Test with `ping6 google.com`

🔍 **Goal**: Practice IPv6 addressing, routing, and DNS.

---

## 2.0 ⚙️ Network Implementation

### 2.1 🔰 Basic: Setup VLANs on OpenWrt (GL.iNet)

* Go to LuCI web UI → **Network > Switch**
* Create VLAN 10 and assign to port
* Tag CPU port, untag desired port

🔍 **Goal**: Understand VLANs in SOHO routers.

---

### 2.2 🔁 Moderate: Setup NAT on Kali Linux

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Configure iptables NAT
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
```

🔍 **Goal**: Simulate home router NAT functionality.

---

### 2.3 🌐 Hard: Configure a Wireless Access Point on Raspberry Pi

```bash
# Install hostapd and dnsmasq
sudo apt install hostapd dnsmasq
```

Configure `/etc/hostapd/hostapd.conf`:

```ini
interface=wlan0
ssid=PiAccess
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=raspberrysecure
wpa_key_mgmt=WPA-PSK
```

🔍 **Goal**: Turn Pi into a full AP with WPA2.

---

### 2.4 🧠 Extremely Hard: BGP Setup with Containers (FRRouting)

```bash
# Use Docker to emulate routers with FRRouting
sudo docker run --name frr1 -it frrouting/frr bash
```

* Configure BGP inside container

🔍 **Goal**: Emulate enterprise routing protocols.

---

## 3.0 🧭 Network Operations

### 3.1 🔰 Basic: Document the Physical Network

* Use `draw.io` or `Dia` to map:

  * Routers
  * Raspberry Pi
  * Kali Linux

🔍 **Goal**: Create basic network topology diagrams.

---

### 3.2 🔁 Moderate: Monitor Network with `iftop`

```bash
sudo apt install iftop
sudo iftop -i wlan0
```

🔍 **Goal**: Observe traffic volume per connection.

---

### 3.3 🌐 Hard: Setup `ntopng` for Flow Analysis

```bash
sudo apt install ntopng
sudo systemctl enable ntopng
```

Access: `http://localhost:3000`

🔍 **Goal**: Flow-based analysis of protocols and hosts.

---

### 3.4 🧠 Extremely Hard: Build Your Own SIEM (Wazuh + ELK)

* Install Wazuh Manager + Filebeat on Pi
* Forward logs to ELK stack on Kali or VM

🔍 **Goal**: Emulate enterprise log correlation.

---

## 4.0 🔐 Network Security

### 4.1 🔰 Basic: Change Router Default Passwords

* Login to GL.iNet or TP-Link UI
* Navigate to Admin Settings
* Change passwords, disable remote admin

🔍 **Goal**: Apply device hardening.

---

### 4.2 🔁 Moderate: Enable WPA3 + Disable WPS

* GL.iNet supports WPA3 (if upgraded)
* Disable WPS in router UI

🔍 **Goal**: Enforce modern encryption.

---

### 4.3 🌐 Hard: Detect Rogue AP with Kali Linux

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
```

Look for duplicate SSIDs with different MACs

🔍 **Goal**: Find evil twin attacks.

---

### 4.4 🧠 Extremely Hard: Implement 802.1X with FreeRADIUS

* Use Raspberry Pi as FreeRADIUS server
* Configure router with RADIUS backend

🔍 **Goal**: Emulate enterprise access control.

---

## 5.0 🛠️ Network Troubleshooting

### 5.1 🔰 Basic: Check IP Config and Link Status

```bash
ip a
ethtool eth0
ping 8.8.8.8
```

🔍 **Goal**: Identify common config issues.

---

### 5.2 🔁 Moderate: Use Traceroute to Detect Routing Issues

```bash
traceroute google.com
```

🔍 **Goal**: Understand path traversal and delays.

---

### 5.3 🌐 Hard: Analyze Logs with `journalctl` and `syslog`

```bash
journalctl -xe
sudo tail -f /var/log/syslog
```

🔍 **Goal**: Log-based issue detection.

---

### 5.4 🧠 Extremely Hard: Use Wireshark to Diagnose DHCP Failures

* Filter for `bootp`, `dhcp`, and inspect Offer/Request

🔍 **Goal**: Deep analysis of misconfigured DHCP.

---

> ✅ **Pro Tip**: Save this guide as a `README.md` on your GitHub repo. Track each activity with checkboxes and commit changes to show progress.

---

## 🧩 Suggestions for Extension

* Integrate Docker Compose for lab orchestration
* Use GNS3 for simulating full virtual networks
* Build GitHub Actions to validate lab submissions automatically

---

**Authored for:** *Kali Linux, Raspberry Pi, OpenWrt/TP-Link* environments
**Based on:** CompTIA Network+ N10-009 + Professor Messer Notes
