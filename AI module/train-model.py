#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Trainer')

DATASET_FILE = "webshell_dataset.csv" 
MODEL_DIR = "/home/imlampham/snort-ai/models/" 
os.makedirs(MODEL_DIR, exist_ok=True)

def train():
    if not os.path.exists(DATASET_FILE):
        logger.error(f"Không tìm thấy file {DATASET_FILE}. Hãy chạy crawl_data.py trước!")
        return

    logger.info(f"Đang tải dữ liệu từ {DATASET_FILE}...")
    df = pd.read_csv(DATASET_FILE)
    
    if df.empty:
        logger.error("Dataset trống! Không thể huấn luyện.")
        return

    # Tách đặc trưng (X) và nhãn (y)
    X = df.drop('label', axis=1)
    y = df['label']
    
    feature_count = X.shape[1]
    logger.info(f"Dữ liệu nạp vào có {feature_count} đặc trưng và {X.shape[0]} mẫu.")

    # Chia tập dữ liệu (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    logger.info(f"Đang thực hiện chuẩn hóa {feature_count} đặc trưng...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Huấn luyện RandomForest (Phát hiện Web Shell/Rev Shell)
    logger.info("Đang huấn luyện RandomForestClassifier...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
    rf_model.fit(X_train_scaled, y_train)

    # Huấn luyện IsolationForest (Phát hiện bất thường)
    logger.info("Đang huấn luyện IsolationForest trên dữ liệu sạch...")
    # Chỉ dùng dữ liệu nhãn 0 (Benign) đã chuẩn hóa để mô hình học hành vi bình thường
    X_benign_scaled = X_train_scaled[y_train == 0]
    if len(X_benign_scaled) > 0:
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        iso_forest.fit(X_benign_scaled)
    else:
        logger.warning("Không có đủ mẫu Benign để huấn luyện IsolationForest.")
        iso_forest = None

    logger.info("--- BÁO CÁO ĐÁNH GIÁ ---")
    y_pred = rf_model.predict(X_test_scaled)
    logger.info(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(classification_report(y_test, y_pred))

    logger.info(f"Đang lưu các file model vào {MODEL_DIR}...")
    try:
        joblib.dump(rf_model, os.path.join(MODEL_DIR, 'rf_classifier.pkl'))
        joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
        if iso_forest:
            joblib.dump(iso_forest, os.path.join(MODEL_DIR, 'isolation_forest.pkl'))
        logger.info("✓ Quá trình huấn luyện và lưu trữ hoàn tất thành công!")
    except Exception as e:
        logger.error(f"Lỗi khi lưu mô hình: {e}")

if __name__ == "__main__":
    train()