import os

# CONFIG
# =========================================================

# Update these paths to be compatible with Docker container file system
PCAP_FOLDER = "resources/pcap"  # Path inside the container
CSV_FOLDER = "resources/output"
PREDICTED_FOLDER = "resources/predicted"
TRAFFIC_MODEL_PATH = "resources/model/ETA/Hybrid_model.pkl"
#ANOMALY_MODEL_PATH = "resources/model/anomaly/RF_model.pkl"#anomaly detection
RF_MODEL_PATH = "resources/model/anomaly/RF_model.pkl"
KNN_MODEL_PATH = "resources/model/anomaly/KNN_model.pkl"
XGB_MODEL_PATH = "resources/model/anomaly/XGB_model.pkl"
SVM_MODEL_PATH = "resources/model/anomaly/SVM_model.pkl"
TRAFFIC_FEATURES_PATH = "resources/model/ETA/RF_features.pkl"
ANOMALY_FEATURES_PATH = "resources/model/anomaly/RF_features.pkl"  #anomaly detection
TRAFFIC_ENCODER_PATH = "resources/model/ETA/ETA_labelencoder.pkl"
ANOMALY_ENCODER_PATH = "resources/model/anomaly/label_encoder.pkl" #anomaly detection
CLASSIFICATION_MODEL_PATH = "resources/model/Classification/RF_model.pkl"
CLASSIFICATION_FEATURES_PATH = "resources/model/Classification/RF_features.pkl"
CLASSIFICATION_ENCODER_PATH = "resources/model/Classification/label_encoder.pkl"
# CICFLOWMETER_CMD = r"networkflows\Scripts\cicflowmeter.exe"
CICFLOWMETER_CMD = "cicflowmeter"

# Maximum PCAP files to keep in folder
MAX_PCAP_FILES = 10
API_URL = "http://127.0.0.1:8018/predict/"  # IMPORTANT: trailing slash
POLL_INTERVAL = 5
MAX_RESULTS = 5000
JSONL_FILE_PATH = "resources/flows.json"  # Absolute path inside the container
Malicious_JSONL_FILE_PATH = "resources/malicious_flows.json" 
