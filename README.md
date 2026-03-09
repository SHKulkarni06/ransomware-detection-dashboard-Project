# Early Ransomware Detection Using Network Traffic and Machine Learning

## Project Overview
This project aims to detect ransomware **at an early stage** by monitoring **network traffic behavior** instead of scanning files. Ransomware often communicates with external servers before encrypting files, and abnormal network behavior can be detected early using a hybrid approach of **rule-based logic** and **machine learning (Isolation Forest)**.  

This approach allows real-time detection and preventive action before files are encrypted, making it suitable for modern network security environments.

---

## Key Features
- Early ransomware detection at the network level  
- Hybrid detection: Rule-based + Machine Learning  
- Risk scoring and explainable alerts  
- Permission-based preventive actions (block suspicious traffic)  
- Real-time monitoring and logging  
- Optional visualization of network traffic and anomalies  

---

## Technologies Used
- **Python 3.x** – Core programming language  
- **PyShark** – Live network packet capture  
- **Wireshark** – Packet analysis and validation  
- **Pandas & NumPy** – Data processing and feature extraction  
- **Scikit-learn** – Machine learning (Isolation Forest)  
- **Matplotlib / Streamlit** – Visualization (optional)  
- **Python logging module** – Event logging and reporting  

---

## Project Structure
Early-Ransomware-Detection/
│
├── data/ # Datasets, captured packets
├── capture/ # Packet capture scripts
├── features/ # Feature extraction logic
├── detection/ # Rule-based + ML detection
├── models/ # Trained ML models
├── logs/ # Log files
├── visualization/ # Graphs and dashboards (optional)
├── main.py # Project entry point
└── README.md # Project explanation


---

## How it Works
1. Capture live network traffic using PyShark  
2. Extract key features such as packet size, connection frequency, encrypted traffic, and unknown IPs  
3. Clean and normalize the data  
4. Apply rule-based detection for fast alerts  
5. Apply Isolation Forest to detect anomalies  
6. Generate a risk score and classify activity (Low / Medium / High)  
7. Raise alert and explain reason  
8. Ask user/admin permission to block suspicious traffic  
9. Log all events for auditing and analysis  

---

## Getting Started

1. Clone this repository (private, for practice):
```bash
git clone https://github.com/SHKulkarni06/Early-Ransomware-Detection-
Navigate to project folder and create a virtual environment:

cd Early-Ransomware-Detection
python -m venv venv
venv\Scripts\activate
Install required packages:

pip install pyshark pandas numpy scikit-learn matplotlib
Run main program:

python main.py
Future Enhancements
Add a dashboard using Streamlit for live visualization

Implement adaptive thresholds for dynamic anomaly detection

Integrate with MITRE ATT&CK framework for advanced threat classification

Author
Sanchita Kulkarni

Email / LinkedIn: sanchitakulkarni28@gmail.com


# Early-Ransomware-Detection-
Early Ransomware Detection using Network Traffic &amp; ML
