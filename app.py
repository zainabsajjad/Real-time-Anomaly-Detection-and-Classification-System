import os
import time
import glob
import uuid
import json
import logging
import threading
import subprocess
from queue import Queue
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
import constants as C
from datetime import timedelta, datetime

# Logging

logging.basicConfig(level=logging.INFO,format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Ensure Directories Exist
os.makedirs(C.PCAP_FOLDER, exist_ok=True)
os.makedirs(C.CSV_FOLDER, exist_ok=True)
os.makedirs(C.PREDICTED_FOLDER, exist_ok=True)

os.makedirs(os.path.dirname(C.JSONL_FILE_PATH),exist_ok=True)
os.makedirs(os.path.dirname(C.Malicious_JSONL_FILE_PATH),exist_ok=True)

# FastAPI App

app = FastAPI(title="Network Traffic Prediction API",version="1.0")

processing_queue = Queue()
processed_pcaps = set()
queued_pcaps = set()
rf_model = None
knn_model = None
xgb_model = None
svm_model = None
anomaly_features = None
anomaly_label_encoder = None
classification_model = None
classification_features = None
classification_encoder = None

# Load Models / Artifacts
def load_artifacts():

    global rf_model
    global knn_model
    global xgb_model
    global svm_model
    global anomaly_features
    global anomaly_label_encoder
    global classification_model
    global classification_features
    global classification_encoder

    try:
        rf_model = joblib.load(C.RF_MODEL_PATH)
        knn_model = joblib.load(C.KNN_MODEL_PATH)
        xgb_model = joblib.load(C.XGB_MODEL_PATH)
        svm_model = joblib.load(C.SVM_MODEL_PATH)
        classification_model = joblib.load(C.CLASSIFICATION_MODEL_PATH)
        logger.info("[+] Anomaly models loaded")
    except Exception as e:
        logger.error(f"Anomaly models load failed: {e}")
        
    try:
        anomaly_features = list(joblib.load(C.ANOMALY_FEATURES_PATH))
        classification_features = list(joblib.load(C.CLASSIFICATION_FEATURES_PATH))
    except Exception as e:
        logger.error(f"Anomaly features load failed: {e}")
        anomaly_features = []
        classification_features = []
    try:
        anomaly_label_encoder = joblib.load(C.ANOMALY_ENCODER_PATH)
        classification_encoder = joblib.load(C.CLASSIFICATION_ENCODER_PATH)
    except:
        anomaly_label_encoder = None

load_artifacts()

# Helper Functions

def wait_for_file_stability( path, checks=2, delay=1):
    last_size = -1
    stable = 0

    while stable < checks:

        if not os.path.exists(path):
            return False
        current_size = os.path.getsize(path)

        if current_size > 24 and current_size == last_size:
            stable += 1
        else:
            stable = 0
            last_size = current_size

        time.sleep(delay)

    return True

def is_valid_pcap(path):
    return ( os.path.exists(path) and os.path.getsize(path) > 24 )

def prepare_dataframe(df, features):
    df = df.copy()
    for feature in features:
        if feature not in df.columns:
            df[feature] = 0
    df = df[features]
    for col in df.columns:
      df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.replace( [np.inf, -np.inf], 0 )
    df = df.fillna(0)
    return df

# CICFlowMeter

def run_cicflowmeter( pcap_path, output_csv ):
    try:
        time_now = datetime.now()
        
        result = subprocess.run(
            [ C.CICFLOWMETER_CMD, "-f", pcap_path, "-c", output_csv ],
            capture_output=True,
            text=True
        )
        print(result)
        after_processing = datetime.now()
        processing_duration = after_processing - time_now
        duration = processing_duration.total_seconds()
        if result.returncode != 0:
            logger.error( f"CICFlowMeter Error: {result.stderr}" )
            return False, 0, time_now, after_processing

        logger.info( f"CICFlowMeter completed: {pcap_path} "
            f"in {duration:.2f} seconds"
        )
        return True, duration, time_now, after_processing
    except Exception as e:
        logger.error( f"CICFlowMeter Exception: {e}" )
        now = datetime.now()
        return False, 0, now, now

# Prediction Pipeline

def process_csv(csv_path):

    try:

        df = pd.read_csv(csv_path)
        df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

        if df.empty:
            logger.warning( f"Empty CSV: {csv_path}" )
            return None
        df_anomaly = prepare_dataframe( df, anomaly_features)
        df_classification = prepare_dataframe(df, classification_features)
        # Predictions
   
        rf_prob = rf_model.predict_proba(df_anomaly)[:, 1]
        knn_prob = knn_model.predict_proba(df_anomaly)[:, 1]
        xgb_prob = xgb_model.predict_proba(df_anomaly)[:, 1]
        svm_prob = svm_model.predict_proba(df_anomaly)[:, 1]
        
        overall = (rf_prob + knn_prob + xgb_prob + svm_prob) / 4
        THRESHOLD = 0.7
        anomaly_pred = np.where(overall > THRESHOLD,1,0)
        classification_pred = classification_model.predict(df_classification)
        # Decode Labels
        if anomaly_label_encoder:
            anomaly_pred = ( anomaly_label_encoder .inverse_transform(anomaly_pred))
            classification_pred = (classification_encoder.inverse_transform(classification_pred))
        
        # Add Predictions
        
        df["RF_ProbClass1"] = rf_prob
        df["KNN_ProbClass1"] = knn_prob
        df["XGB_ProbClass1"] = xgb_prob
        df["SVM_ProbClass1"] = svm_prob
        df["Overall"] = overall
        df["Traffic_Behaviour"] = anomaly_pred
        df["Traffic_Type"] = classification_pred
        logger.info(f"Traffic Behaviour: {pd.Series(anomaly_pred).value_counts().to_dict()}")
        logger.info(f"Traffic Type: {pd.Series(classification_pred).value_counts().to_dict()}")

        # Save Prediction CSV

        logger.info(f"CSV Columns = {list(df.columns)}")
        output_csv = os.path.join(
            C.PREDICTED_FOLDER,
            os.path.basename( csv_path ).replace( ".csv", "_pred.csv" ))
        df.to_csv( output_csv, index=False )
        logger.info( f"[+] Prediction saved: {output_csv}" )

        # Append JSONL

        records = df.to_dict( orient="records" )
        with open(C.JSONL_FILE_PATH, "a") as f:
            for record in records:
                f.write(json.dumps(record)+ "\n")
        logger.info(f"[+] Appended predictions to JSONL: {C.JSONL_FILE_PATH}")

        # Save Malicious Flows

        malicious_df = df[ df["Traffic_Behaviour"]== 1 ]
        if not malicious_df.empty:
            malicious_records = ( malicious_df.to_dict( orient="records" ) )
            with open( C.Malicious_JSONL_FILE_PATH, "a" ) as f: 
                for record in malicious_records: 
                    f.write( json.dumps(record) + "\n" )   
            logger.info(f"[+] Appended predictions to JSONL: {C.Malicious_JSONL_FILE_PATH}")

            logger.info( f"[+] Malicious flows saved: " f"{len(malicious_df)}" )
        return output_csv
    except Exception as e:
        logger.error( f"Prediction error: {e}" )
        return None

# Worker Thread

def worker():
    while True:
        #initializing a queue for pcap files
        pcap_file = processing_queue.get()
        if pcap_file is None:
            break
        try:
            csv_name = ( os.path.basename( pcap_file ).replace( ".pcap", ".csv" ) )
            csv_path = os.path.join( C.CSV_FOLDER, csv_name )
            logger.info(f"[PROCESSING] {pcap_file}")
            cic_status, duration, time_now, after_processing = run_cicflowmeter(pcap_file, csv_path)
            if cic_status:
                logger.info( f"[+] Flow extraction completed: " f"{pcap_file}" )
                # here I am performing prediction from csv file.
                process_csv(csv_path)
                logger.info(f"[COMPLETED] {pcap_file}")
            try:
                file_size_bytes = os.path.getsize(pcap_file)
            except OSError:
                file_size_bytes = 0
            file_size_kb = file_size_bytes / 1024

            log_line = (
                f"Filename: {os.path.basename(pcap_file)} | "
                f"Start: {time_now.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"End: {after_processing.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"Duration: {duration:.2f}s | "
                f"Size: {file_size_kb:.2f} KB\n"
            )
            with open("pcap_logging.txt", "a") as f:
                f.write(log_line)
        
            # if run_cicflowmeter( pcap_file, csv_path ):
            #     logger.info( f"[+] Flow extraction completed: " f"{pcap_file}" )
            #     process_csv(csv_path)
            #     logger.info(f"[COMPLETED] {pcap_file}")

            processed_pcaps.add(pcap_file)
            queued_pcaps.discard(pcap_file)
        except Exception as e:
            logger.error( f"Worker error: {e}" )
        finally:
            processing_queue.task_done()

# Watch PCAP Folder

def watch_pcap_folder():
    while True:
        try:
            pcaps = glob.glob( os.path.join( C.PCAP_FOLDER, "*.pcap" ) )
            for pcap in pcaps:
                if pcap in processed_pcaps:
                    continue
                if not wait_for_file_stability( pcap ):
                    continue
                if not is_valid_pcap( pcap ):
                    continue
                if pcap not in queued_pcaps:
                    processing_queue.put(pcap)
                    queued_pcaps.add(pcap)
                    logger.info(f"[QUEUED] {pcap}")
            time.sleep(1)
        except Exception as e:
            logger.error( f"Watcher error: {e}" )

# Cleanup Old PCAPs

def cleanup_old_pcaps():
    while True:
        try:
            time.sleep(60)

            pcaps = glob.glob( os.path.join( C.PCAP_FOLDER, "*.pcap" ) )
            if len(pcaps) <= C.MAX_PCAP_FILES:
                continue
            pcaps.sort( key=os.path.getmtime )
            old_pcaps = pcaps[ :-C.MAX_PCAP_FILES ]
            for pcap in old_pcaps:
                if pcap not in processed_pcaps:
                    continue
                try:
                    os.remove(pcap)
                    processed_pcaps.discard( pcap )
                    logger.info( f"[+] Deleted: {pcap} from the queue" )
                except Exception as e:
                    logger.error( f"**Error occurred while deleting pcap from the queue: {e}" )
        except Exception as e:
            logger.error( f"Cleanup error: {e}" )

# API Endpoints

@app.post("/predict/")
async def predict( file: UploadFile = File(...) ):
    temp_csv = os.path.join( C.CSV_FOLDER, f"{uuid.uuid4().hex}_" f"{file.filename}" )
    with open( temp_csv, "wb" ) as f:
        f.write( await file.read() )
    output = process_csv( temp_csv )
    if output:
        return { "message": f"/download/" f"{os.path.basename(output)}" }
    return { "error": "processing failed" }


@app.get("/download/{filename}")
async def download( filename: str ):
    path = os.path.join( C.PREDICTED_FOLDER, filename )
    if os.path.exists(path):
        return FileResponse(path)
    return {
        "error": "not found"
    }

# Startup

@app.on_event("startup")
def startup_event():
    threading.Thread( target=worker, daemon=True ).start()

    threading.Thread( target=watch_pcap_folder, daemon=True ).start()

    threading.Thread( target=cleanup_old_pcaps, daemon=True ).start()

    logger.info( "[+] Background threads started" )

# Main
if __name__ == "__main__":
    import uvicorn # type: ignore
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=9018,
        reload=False
    )
