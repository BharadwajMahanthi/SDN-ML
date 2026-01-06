# SDN-ML TopoGuard (Windows/GNS3)

This project implements an SDN Security system using **Floodlight** (Controller) and Machine Learning (SVM, Random Forest) to detect TopoGuard attacks.
The network simulation is handled by **GNS3** (Windows).

## Project Structure

- `src/`: Core Python modules for ML (Data Processing, Models, Evaluation).
- `floodlight_with_topoguard/`: Custom Floodlight Controller (Java).
- `ml_dataset/`: Training and testing data.
- `plots/`: Generated visualizations.
- `mininet_archive/`: Archived Mininet/Docker scripts (Deprecated).

## Setup

1.  **Floodlight:** Compiled using `ant`. Runs locally on Port 6653.
2.  **GNS3:** Connect Open vSwitch (OVS) appliances to host `127.0.0.1:6653`.
3.  **ML:** Run `python main.py` to train/evaluate models.
