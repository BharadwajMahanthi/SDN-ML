# Containerlab Setup (WSL2)

This guide executes the SDN-ML topology using **Containerlab** inside your WSL2 authentication.

## 1. Prerequisites (WSL2)

Open your **Windows Terminal** (Ubuntu/WSL) and run:

```bash
# Install Docker (if not installed in WSL)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Containerlab
bash <(curl -sL https://containerlab.dev/setup)
```

## 2. Deploy Topology

Navigate to the project folder (Windows files are mounted in `/mnt/c/`):

```bash
cd /mnt/c/Users/mbpd1/Downloads/SDN-ML
sudo containerlab deploy -t sdn_ml.clab.yml
```

## 3. Verify

Once deployed, the `s1` switch will automatically try to connect to your Windows Floodlight controller.

- **Floodlight/Windows:** Ensure `run_floodlight.bat` is running.
- **Verify Switch:**
  ```bash
  docker exec clab-sdn-ml-s1 ovs-vsctl show
  ```
  Should show `is_connected: true`.
- **Generate Traffic:**
  ```bash
  docker exec clab-sdn-ml-h1 ping 10.0.0.2
  ```

## 4. Cleanup

To stop the lab:

```bash
sudo containerlab destroy -t sdn_ml.clab.yml
```
