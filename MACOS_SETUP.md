# macOS Setup & Usage Guide

Since you are moving to macOS, the networking stack (Docker Desktop for Mac) is much more robust than WSL2 for this type of simulation.

## 1. Prerequisites

### Install Docker Desktop

Download and install Docker Desktop for Mac (Apple Silicon or Intel) from the Docker website.
Ensure it is running.

### Install Containerlab

Open Terminal and run:

```bash
sudo bash -c "$(curl -sL https://get.containerlab.dev)"
```

### Install Java (for Floodlight)

You need Java 8 or 11.

```bash
brew install openjdk@11
```

## 2. Running the Simulation

### Step 1: Start Floodlight Controller

Open a terminal tab:

```bash
cd SDN-ML
chmod +x run_floodlight.sh
./run_floodlight.sh
```

_Wait until you see "Listening for switch connections"._

### Step 2: Run the Attack Simulation

Open a **new** terminal tab:

```bash
cd SDN-ML
# Edit the script if you need to change SUDO_PASS or remove it and run as root manually
sudo bash simulate_attack.sh
```

## 3. What will happen?

1.  **Containerlab** will deploy the topology (`complex_topology.clab.yml`).
2.  **Floodlight** will detect the switch.
3.  **Tcpdump** will start capturing traffic to `pcaps/`.
4.  **Attack**: Host `h4` will spoof `h1`'s MAC address.
5.  **Defense**: If TopoGuard is active (it is configured), it should log alerts or block traffic.
6.  **Cleanup**: The script automatically destroys the lab after 20 minutes (or if you press Ctrl+C).

## 4. Key Files

- `simulate_attack.sh`: The main automation script.
- `complex_topology.clab.yml`: The network definition.
- `floodlight_with_topoguard/src/main/resources/floodlightdefault.properties`: Controller config.
