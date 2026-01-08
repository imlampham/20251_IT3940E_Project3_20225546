import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Trainer')

DATASET_FILE = "webshell_dataset.csv"
MODEL_DIR = "snort-ai/models/"
os.makedirs(MODEL_DIR, exist_ok=True)

def train():
    if not os.path.exists(DATASET_FILE):
        logger.error(f"Không tìm thấy file {DATASET_FILE}. Hãy chạy crawl_dataset.py trước!")
        return

    logger.info(f"Đang tải dữ liệu từ {DATASET_FILE}...")
    df = pd.read_csv(DATASET_FILE)
    
    # Tách đặc trưng (X) và nhãn (y)
    X = df.drop('label', axis=1)
    y = df['label']
    
    logger.info(f"Dữ liệu nạp vào có {X.shape[1]} đặc trưng và {X.shape[0]} mẫu.")

    # Chia tập dữ liệu (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    logger.info("Đang thực hiện chuẩn hóa đặc trưng (Scaling)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Huấn luyện RandomForest (Phát hiện Web Shell/Rev Shell)
    logger.info("Đang huấn luyện RandomForestClassifier...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
    rf_model.fit(X_train_scaled, y_train)

    # Huấn luyện IsolationForest (Phát hiện bất thường trên dữ liệu sạch)
    logger.info("Đang huấn luyện IsolationForest...")
    # Chỉ dùng dữ liệu nhãn 0 (Benign) đã chuẩn hóa để học phân bố bình thường
    X_benign_scaled = X_train_scaled[y_train == 0]
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    iso_forest.fit(X_benign_scaled)

    logger.info("--- BÁO CÁO ĐÁNH GIÁ ---")
    y_pred = rf_model.predict(X_test_scaled)
    print(classification_report(y_test, y_pred))

    logger.info(f"Đang lưu các file model vào {MODEL_DIR}...")
    joblib.dump(rf_model, os.path.join(MODEL_DIR, 'rf_classifier.pkl'))
    joblib.dump(iso_forest, os.path.join(MODEL_DIR, 'isolation_forest.pkl'))
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    
    logger.info("Quá trình huấn luyện và lưu trữ hoàn tất thành công!")

if __name__ == "__main__":
    train()