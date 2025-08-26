# Paper-code

## A Hybrid DDoS Detection Architecture Based on Entropy and Machine Learning Deployed on P4 Programmable Switches

This repository contains the code and data for our project on intrusion detection using GAN and XAI in a multi-layer edge computing and IoT environment.

---

## Dataset
You can download the datasets:
👉 [https://iotanalytics.unsw.edu.au/attack-data.html](#)

👉 [https://www.unb.ca/cic/datasets/ddos-2019.html](#)


## Usage Instructions

### 1. Data Preprocessing
Run the script to preprocess the dataset and split it into training and testing sets.`Fragment.py`

### 2.Train RF Model
Using Google Colab run the script to preprocess the dataset and split it into training and testing sets.`HELM.ipynb`

### 3. Convert
Using Google Colab run the script to convert the RF model’s decision boundaries into executable rules for the data plane.`HELM_convert_RF_to_table_entries.ipynb`
