# AI-Enabled Firewall  
### Real-Time Network Anomaly Detection and Adaptive Blocking

**Authors:**  
- Sen Ivan
- Maksym Dzoban

📽 **Demo:** https://youtu.be/H6gI0c7M0h0

---

## 📌 Overview

This project implements an **AI-enabled firewall** capable of detecting anomalous network behavior in real time and automatically applying blocking rules.

Traditional firewalls and IDS systems rely on static rules and signatures, which makes them ineffective against:
- zero-day attacks,
- low-and-slow activity,
- anomalous user behavior caused by human error.

Our solution focuses on **behavior-based anomaly detection** using machine learning, integrated directly into the firewall control plane.

---

## 🎯 Goals

The AI Firewall is designed to:

- detect anomalous network behavior in real time;
- reduce the risk of zero-day attacks;
- automatically update firewall rules;
- visualize per-user network activity for administrators;
- operate with low computational overhead;
- predict future user activity patterns.

---

## 🧠 Key Concepts

- **Firewall** — filters network traffic based on predefined rules  
- **IDS (Intrusion Detection System)** — detects unauthorized or suspicious activity  
- **Deep Packet Inspection (DPI)** — inspects packet payload and metadata  
- **Control Plane** — makes decisions on traffic handling  
- **Data Plane** — executes packet forwarding and filtering  
- **iptables** — Linux kernel firewall and packet filtering framework  

---

## 🏗 System Architecture

Network traffic is **passively intercepted** using a DPI-based sniffer.
Only metadata is processed — no payload inspection for ML inference.

### Processing Pipeline


### Flow Logic

1. Packets are aggregated into flows and sessions.
2. Each session is converted into a `TrafficEvent`.
3. Rule Engine decides:
   - **Allow** (known safe traffic),
   - **Block** (matches deny rules or blocklists),
   - **Send to ML** (unknown or suspicious behavior).
4. ML module outputs an **anomaly score [0, 1]**.
5. Firewall rules are dynamically synchronized via `iptables`.

---

## 📊 Dataset

The dataset was collected by emulating a **small office network**:
- 5 client machines,
- Wi-Fi and Ethernet connections,
- centralized router.

Each record represents a **network session** and includes:
- traffic direction and timestamps,
- IP / MAC addresses and ports,
- transport protocol and TCP flags,
- nDPI application labels,
- destination geolocation,
- firewall decision (allow / block).

Unlike CIC-IDS2017, this dataset preserves **user–service–time relationships**, which is critical for **User Behavior Analytics (UBA)**.

---

## 🧩 Models Evaluated

### Classical Methods
- Isolation Forest  
- Local Outlier Factor (LOF)  
- One-Class SVM  

### Latent-Space Methods
- Dense Autoencoder (AE)  
- Variational Autoencoder (VAE)  
- K-Means in AE latent space  

### Sequential Models
- LSTM Autoencoder (sliding window sequences)

---

## ⚔ Synthetic Attack Scenarios

To evaluate robustness, we generated realistic attack patterns:
- beaconing & low-and-slow activity,
- DNS / TLS tunneling,
- port spraying,
- data exfiltration.

---

## 📈 Evaluation Metric

We use **ROC-AUC** as the primary metric:
- `1.0` — perfect detection,
- `0.5` — random guessing.

---

## 🧪 Results

### ROC-AUC Scores

| Model | ROC-AUC |
|------|--------|
| Isolation Forest | 0.662 |
| Local Outlier Factor (LOF) | 0.998 |
| One-Class SVM | 0.709 |
| K-Means (AE latent space) | 0.839 |
| Dense Autoencoder | 0.998 |
| Variational Autoencoder | 0.997 |
| **LSTM Autoencoder** | **0.999** |

**Key observation:**  
Sequential models (LSTM) outperform classical detectors, especially for stealthy attacks.

---

## 🔮 User Activity Prediction

In addition to anomaly detection, we implemented a **next-website prediction model**.

### Model Architecture
- Embedding layer (domain → vector),
- LSTM layer (temporal modeling),
- output layer with probability distribution over domains.

### Input
- sequence of 8 previously visited domains.

### Output
- Top-K most probable next websites.

---

### Prediction Accuracy (Top-K)

| Dataset Size | Top-1 | Top-3 | Top-5 | Top-10 |
|------------|-------|-------|-------|--------|
| 1 hour logs | 0.347 | 0.537 | 0.634 | 0.722 |
| 6 hours logs | 0.473 | 0.652 | 0.734 | 0.803 |
| 21 hours logs | 0.489 | 0.685 | 0.771 | 0.826 |

Increasing data volume significantly improves prediction quality.

---

## 📚 References

- Zhong et al., *A Survey on Graph Neural Networks for IDS*, 2023  
- Čisar, *EWMA Statistic in Adaptive Threshold Algorithms*, 2007  
- CIC-IDS2017 Dataset (UNB CIC)  
- UNSW-NB15 Dataset  
- Centralized traffic filtering practices (e.g., Great Firewall of China)

---

## ✅ Conclusions

- AI-based methods significantly outperform traditional IDS approaches.
- LSTM models achieve near-perfect detection of complex and stealthy attacks.
- The system adapts naturally to specific network environments.
- The approach is scalable and suitable for real-time deployment.

---
## 🚀 Run project

All components are launched manually.
write all text in markdown

## 🚀 Run project

Run the main application as a **Uvicorn** app:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

2. Start the packet sniffer (Data Plane)
   
Run the sniffer on the local network interface (LAN port, not WAN):
```
./sniffer <local_port>
```

4. Start the ML model
   
Launch the anomaly detection model:

```
python3 model.py
```

Runtime flow: The sniffer captures network traffic metadata. Data is forwarded to the Control Plane. The ML model computes anomaly scores.Firewall rules are dynamically updated via iptables.

