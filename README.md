# netRo

Here’s the updated `README.md` with detailed instructions on how to install all the required dependencies and your email added:

---

# netRo: System Dashboard and Advanced Network Tool

**netRo** is a powerful Bash script that combines a **System Dashboard** and an **Advanced Network Tool** into one seamless interface. It provides real-time system monitoring, health checks, and a suite of network diagnostic utilities, making it an essential tool for system administrators and network enthusiasts.

---

## Features

### System Dashboard
- **System Information**: Displays hostname, OS, and kernel version.
- **Network Information**: Shows IP addresses and network interfaces.
- **Storage Information**: Provides disk usage statistics.
- **Security Information**: Checks for suspicious processes, open ports, unauthorized users, and file integrity.
- **Real-Time Updates**: Refreshes system information at regular intervals.

### Advanced Network Tool
- **Ping a Host**: Test connectivity to a remote host.
- **Port Scanning**: Scan open ports on a target IP or hostname using Nmap.
- **Network Connections**: View active network connections.
- **Traceroute**: Trace the route to a remote host.
- **DNS Lookup**: Perform DNS queries for a domain.
- **Advanced Nmap Scans**: Perform intense, OS detection, version detection, and custom Nmap scans.
- **Network Interface Check**: Display network interface details.
- **Public IP Check**: Fetch the system's public IP address.
- **Device Listing**: List all devices on the local network.
- **Device Blocking**: Block or unblock a device using IP tables.
- **Save Scan Results**: Save scan results to a file.
- **Device Details**: Fetch detailed information about a specific device.

---

## Installation

### Prerequisites
To run **netRo**, ensure the following tools are installed on your system:
- **Bash**: The script is written in Bash and requires a Bash shell.
- **Nmap**: For port scanning and advanced network diagnostics.
- **Traceroute**: For route tracing.
- **Net-tools**: For network interface checks (optional, depending on your system).
- **Curl**: For fetching the public IP address.

### Step-by-Step Installation

#### 1. Install Required Dependencies
On **Debian/Ubuntu-based systems**, run:
```bash
sudo apt update
sudo apt install bash nmap traceroute net-tools curl
```

On **Red Hat/CentOS-based systems**, run:
```bash
sudo yum install bash nmap traceroute net-tools curl
```

On **Arch Linux-based systems**, run:
```bash
sudo pacman -S bash nmap traceroute net-tools curl
```

#### 2. Clone the Repository
Clone the **netRo** repository to your local machine:
```bash
git clone https://github.com/ALSRKAL/netRo.git
cd netRo
```

#### 3. Make the Script Executable
Make the script executable:
```bash
chmod +x netRo.sh
```

#### 4. Run the Script
Start **netRo**:
```bash
./netRo.sh
```

---

## Usage

### System Dashboard
1. Launch the script:
   ```bash
   ./netRo.sh
   ```

2. Use the menu to navigate through the options:
   - **1**: Show System Information
   - **2**: Show Network Information
   - **3**: Show Storage Information
   - **4**: Show Security Information
   - **5**: Show All Information
   - **6**: Launch Advanced Network Tool
   - **7**: Exit

### Advanced Network Tool
1. From the System Dashboard, select **Option 6** to launch the Advanced Network Tool.

2. Use the menu to perform network-related tasks:
   - **1**: Ping a Host
   - **2**: Scan Ports with Nmap
   - **3**: Check Network Connections
   - **4**: Trace Route to a Host
   - **5**: DNS Lookup
   - **6**: Check Open Ports on a Host
   - **7**: Advanced Nmap Scan
   - **8**: Check Network Interfaces
   - **9**: Check Public IP Address
   - **10**: Get IP Address
   - **11**: List All Devices on the Network
   - **12**: Block/Unblock a Device
   - **13**: Save Scan Results to File
   - **14**: Show Device Details
   - **15**: Exit

---

## Screenshots

### System Dashboard
![System Dashboard](screenshots/system_dashboard.png)

### Advanced Network Tool
![Advanced Network Tool](screenshots/network_tool.png)

---

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments
- Inspired by various system monitoring and network diagnostic tools.
- Thanks to the open-source community for providing the tools and libraries used in this project.

---

## Contact

For questions or feedback, feel free to reach out:
- **GitHub**: [ALSRKAL](https://github.com/ALSRKAL)
- **Email**: [mohammedalsrkal@gmail.com](mailto:mohammedalsrkal@gmail.com)

---

Enjoy using **netRo**! 🚀

---

