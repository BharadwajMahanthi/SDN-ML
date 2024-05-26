# SDN-ML

Welcome to the SDN-ML Dissertation Project repository! This project is part of a Master's dissertation conducted at the University of Surrey, focusing on securing Software-Defined Networking (SDN) against various cyber threats.

This repository contains research and implementation details related to securing Software-Defined Networking (SDN) against various types of cyber attacks. The focus is on identifying and mitigating threats using advanced techniques, including machine learning.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Setup](#setup)
- [Usage](#usage)
- [Directory Structure](#directory-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Introduction

Software-Defined Networking (SDN) centralizes network control, allowing for dynamic, programmable network management. While SDN offers significant advantages, it also presents unique security challenges, such as Host Hijacking, ARP Poisoning, and DDoS attacks. This repository explores these vulnerabilities and proposes solutions, including the use of machine learning to enhance SDN security.

This project utilizes the [Floodlight controller](https://github.com/successlab/topoguard-floodlight?tab=readme-ov-file), which integrates TopoGuard for enhanced security monitoring of the network topology. For the topology creation and management, we used the [Mininet](https://github.com/mininet/mininet) software by Bob Lantz.

## Features

- **Centralized Network Management:** Simplifies configuration and management of network resources.
- **Network Slicing Support:** Essential for 5G networks, enabling multiple virtual networks on a shared infrastructure.
- **Quality of Service (QoS) Management:** Ensures optimal performance for diverse applications.
- **Security Mechanisms:** Implementation of TopoGuard and TopoGuard Plus for network topology integrity.
- **Machine Learning Integration:** Advanced threat detection and mitigation.

## Setup

### Prerequisites

- Java 8 (required for Floodlight)
- Apache Ant
- Python 3.8+
- pip
- mininet (for network simulation and testing)
- Virtual environment (optional but recommended)

### Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/BharadwajMahanthi/SDN-ML.git
   cd SDN-ML
   ```

2. **Setup Floodlight Controller:**

   ```sh
   git clone https://github.com/successlab/topoguard-floodlight.git
   cd topoguard-floodlight
   ant
   cd ..
   ```

3. **Create a virtual environment:**

   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

4. **Install Python dependencies:**

   ```sh
   pip install -r requirements.txt
   ```

## Usage (preferred in VM)

1. **Run the Floodlight controller:**

   ```sh
   java -jar topoguard-floodlight/target/floodlight.jar
   ```
   init the floodlight controller by following the instructions from their website [Floodlight controller](https://github.com/successlab/topoguard-floodlight?tab=readme-ov-file)
   
3. **clone the mininet:**
   ```sh
   https://github.com/mininet/mininet.git
   ```
   create the topology and start an attack on the network
   

3. **Create the dataset:**

   Capture the dataset using either Wireshark or the preferred mode of network data capturing and use that data to train your ML model to protect your SDN
   

4. **Training machine learning models:**

   ```sh
   code.ipynb
   ```

4. **Testing and evaluating security mechanisms:**

   ```sh
   code.ipynb
   ```

## Directory Structure

```
.
├── .github/workflows/
│   └── python-app.yml
├── attacker/
│   └── 1.1.html
├── tests/
│   └── test_example.py
│── Final Report - 6671703.pdf
│── Dissertation Final.ipynb
│── environment.yml
├── LICENSE
├── README.md
├── code.ipynb
├── dataset_sdn.csv
├── floodlight_with_topoguard-master.zip
├── mininet_tcp_hijacking-master.zip
├── meta.yml
├── requirements.txt
└── se.py

```

- **dataset_sdn.csv/**: Contains raw and processed data.
- **notebooks/**: Jupyter notebooks for exploratory analysis and model development.
- **attacker/**: Source code and directory for the attacker.
- **topoguard-floodlight/**: Floodlight controller with TopoGuard integration.

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

We would like to thank the open-source community for their valuable tools and resources, and the researchers whose work has contributed to the field of SDN security. Special thanks to the developers of the [Floodlight controller](https://github.com/successlab/topoguard-floodlight?tab=readme-ov-file) for their foundational work on TopoGuard. Also we thank mininet for their valuable resources, Special thanks to the developers of the [Mininet](https://github.com/mininet/mininet)

---

For any queries or issues, please open an [issue](https://github.com/BharadwajMahanthi/SDN-ML/issues) on GitHub.
