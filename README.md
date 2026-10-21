# AIR-DS (Automated Incident Response & Deep Learning Defense Shield)

AIR-DS is an autonomous security operations center (SOC) and incident response platform designed to bridge high-performance threat detection with automated mitigation playbooks. Built for rapid deployment during hackathons, it combines an asynchronous **FastAPI decision engine** with a real-time **cyber-themed SOC dashboard**.

---

##  Key Features

* **Asynchronous FastAPI Backend (`main.py`):** Acts as the primary telemetry router and decision engine for handling incoming security events, alerts, and automated playbooks.
* **Deep Neural Network (DNN) Anomaly Detection:** Real-time analysis of system metrics (CPU, RAM, GPU, and network packets) using Mean Squared Error (MSE) reconstruction loss simulation.
* **File Integrity Monitoring (FIM):** Cryptographic hash auditing to detect unauthorized modifications or tampering of critical system files.
* **Automated Security Playbooks:** Modular response scripts designed to isolate assets, log anomalies, and trigger defensive reactions.
* **Interactive SOC Dashboard:** A fully responsive, dark-mode cyber interface equipped with real-time Chart.js analytics and custom UI modals.

---

##  Project Architecture

```text
air-ds/
├── app/
│   ├── main.py              # Core FastAPI application, telemetry routes, and decision engine
│   ├── config.py            # Centralized system configurations and threat thresholds
│   ├── dashboard/
│   │   └── index.html       # Cyber-themed SOC frontend interface
│   ├── playbooks/
│   │   ├── anomaly_dnn.py   # Deep learning threat detection module
│   │   └── fim.py           # File integrity monitoring engine
│   └── receivers/           # Alert telemetry ingestion receivers
├── requirements.txt         # Python project dependencies
└── README.md                # Project documentation



git clone [https://github.com/Lunzzx414/air-ds.git](https://github.com/Lunzzx414/air-ds.git)
cd air-ds

pip install -r requirements.txt

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Once running, the API decision engine will be live at http://localhost:8000.

You can verify the engine health check endpoint directly at http://localhost:8000/.

Launch the SOC Dashboard
Open the interactive frontend interface:

Navigate to app/dashboard/index.html on your local machine.

Double-click the file or open it directly in your web browser to view the real-time cyber telemetry dashboard, interactive charts, and incident management modals.
