# Paper-code

## A Hybrid DDoS Detection Architecture Based on Entropy and Machine Learning Deployed on P4 Programmable Switches

This repository contains the code and data for our project on hybrid DDoS detection, which combines entropy-based anomaly detection and machine learning classification deployed on P4 programmable switches.

## File Structure

- HELM.p4: Main P4 program implementing hybrid DDoS detection (entropy + ML) on the data plane.

- Makefile: Automates compilation and execution of the P4 program using BMv2 and Mininet.

control_rules_base.txt: Base rules for switch setup (register initialization, basic routing entries, entropy term mappings).

My_method_entries.txt: Machine learning–derived rules mapped into feature tables, code tables, and voting tables.

control_rule.sh: Shell script to automatically load both base rules and ML rules into the switch via simple_switch_CLI.

Monitoring & Traffic Control – Runtime monitoring and traffic replay:

ow_monitor.py: Python script that monitors observation window (OW) counters, triggers traffic replay (tcpreplay) on hosts, and logs register states to the result/ folder.

Runtime & Topology Configurations – Environment setup for BMv2 and Mininet:

s1-runtime.json: Switch runtime configuration, including default actions for ipv4_lpm and ipv4_dpi_lpm.

topology.json: Mininet topology definition (hosts, switch, links, runtime bindings).
## Enviroment
-This project is based on the BMv2 software switch, and the environment is built using the official P4 VM files. To use this project, please put `HELM_Github` into `p4lang/tutorials/exercises/`, and the official VMs can be downloaded here:

👉 [https://github.com/jafingerhut/p4-guide/blob/master/bin/README-install-troubleshooting.md](#)

## Dataset
You can download the datasets:

👉 [https://iotanalytics.unsw.edu.au/attack-data.html](#)

👉 [https://www.unb.ca/cic/datasets/ddos-2019.html](#)


## Usage Instructions

### 1. Data Preprocessing
- Run the script to preprocess the dataset and split it into training and testing sets.`Fragment.py`

### 2.Train the Machine Learning Model

- Use the provided `HELM.ipynb` to train the Random Forest classifier on the dataset (e.g., CICDDoS2019).

- After training, export the model as a `.sav` file.

### 3. Convert Model to P4 Rules

- Run `HELM_convert_RF_to_table_entries.ipynb`.

- This maps the trained model’s decision boundaries into P4 match-action table entries.

- The output will be a CLI command file (e.g., HELM_entries.txt).

### 4.Start the P4 Program

- Navigate to the exercise directory (e.g., exercises/HELM/).

- Run:`make run`

### 5.Load Rules into the Switch

- Run the provided shell script:

- Run:`./control_rule.sh`

### 6.Run Experiments

- Send background traffic, flash-event traffic, or attack traffic using `tcpreplay`.
