# SDN Attack Lab - Quick Start

## Automated Full Pipeline

This runs everything automatically: deploy lab, generate traffic, simulate attacks, collect data.

### Step 1: Start Floodlight (Windows)

```powershell
cd C:\Users\mbpd1\Downloads\SDN-ML
.\run_floodlight.bat
```

### Step 2: Run Pipeline (WSL)

```bash
cd /mnt/c/Users/mbpd1/Downloads/SDN-ML
bash run_full_pipeline.sh
```

### Step 3: Start Data Collector (Windows - separate terminal)

```powershell
python collect_training_data.py
```

The collector will automatically:

- Wait for normal traffic (60s)
- Collect normal flows
- Wait for attack simulation (30s)
- Collect attack flows
- Save combined dataset to `ml_dataset/sdn_training_data_TIMESTAMP.csv`

## Manual Control

If you want to run steps individually:

```bash
# Deploy
sudo containerlab deploy -t sdn_topology.clab.yml

# Generate normal traffic
bash generate_normal_traffic.sh

# Simulate attack
bash simulate_attack.sh

# Cleanup
sudo containerlab destroy -t sdn_topology.clab.yml
```

## Files Generated

- `ml_dataset/normal_flows.csv` - Normal traffic flows
- `ml_dataset/attack_flows.csv` - Attack traffic flows
- `ml_dataset/sdn_training_data_TIMESTAMP.csv` - Combined labeled dataset
