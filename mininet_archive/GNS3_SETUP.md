# GNS3 Setup for SDN-ML

Since Docker/Mininet proved unstable on this specific Windows configuration, GNS3 offers a more robust, GUI-based alternative using a dedicated VM for network emulation.

## 1. Installation

1.  **Download GNS3:** [https://www.gns3.com/software/download](https://www.gns3.com/software/download)
2.  **Install GNS3 All-in-One:** Follow the wizard.
3.  **GNS3 VM:** (Highly Recommended) Download the GNS3 VM for your hypervisor (VMware Workstation Player or VirtualBox). This prevents the kernel issues we faced with Docker.

## 2. Setting up the Topology

1.  **Open GNS3** and create a new project `SDN_ML_Topo`.
2.  **Add an Open vSwitch (OVS):**
    - If not present, go to **Marketplace** -> **Appliances** -> **Open vSwitch**.
    - Import it into GNS3.
3.  **Add a Cloud Node:**
    - Drag the **Cloud** node to the canvas.
    - Right-click -> **Configure**.
    - Under **Ethernet Interfaces**, select the adapter that corresponds to your Windows IP (likely `Wi-Fi` or a `VMnet` adapter). **Do not use localhost (127.0.0.1)** inside GNS3, as that refers to the GNS3 VM, not your PC.
    - _Tip:_ Your host IP is likely `192.168.x.x` (Check `ipconfig` on Windows).

## 3. Wiring & Configuration

1.  **Connect:**
    - Connect the **OVS** `eth0` port to the **Cloud** node.
    - Add 4 **VPCS** (Virtual PCs) and connect them to OVS `eth1` through `eth4`.
2.  **Start the Topology:** Click the **Play** button.
3.  **Configure OVS to use Floodlight:**
    - Right-click the OVS -> **Console**.
    - Run the command:
      ```bash
      ovs-vsctl set-controller br0 tcp:<YOUR_WINDOWS_IP>:6653
      ```
      _Replace `<YOUR_WINDOWS_IP>` with the IP found in step 2 (e.g., 192.168.1.15)._

## 4. Running the Experiment

1.  **Start Floodlight:** On Windows, run `run_floodlight.bat`.
2.  **Verify Connection:**
    - In the Floodlight console (Windows CMD), you should see `Switch Connected`.
    - In GNS3 OVS Console: `ovs-vsctl show` should report `is_connected: true`.
3.  **Generate Traffic:**
    - Open VPCS consoles.
    - `ping 10.0.0.2` (from PC1).
4.  **Collect Data:**
    - Run `python src/collect_live_data.py` on Windows.
