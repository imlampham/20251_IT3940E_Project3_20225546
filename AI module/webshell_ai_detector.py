import re
import logging
import joblib
import numpy as np
import os
import base64
import binascii
import urllib.parse
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import Counter

log_path = '/var/log/snort/webshell_ai.log'
os.makedirs(os.path.dirname(log_path), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('WebshellDetector')

class WebShellDetector:
    def __init__(self):
        self.rf_classifier = None
        self.isolation_forest = None
        self.scaler = None

        self.webshell_patterns = [
            r'eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)',
            r'(?:system|exec|shell_exec|passthru|assert)\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'preg_replace\s*\(.*\/e',
            r'create_function\s*\(',
            r'\$_(?:FILES|GET|POST|REQUEST|COOKIE)\[.*?\]\[.*?\]',
            r'move_uploaded_file\s*\(',
            r'(?:file_put_contents|fwrite|fputs)\s*\(.*\$_',
            r'socket_(?:create|connect|listen)',
            r'fsockopen\s*\(',
            r'\\x[0-9a-fA-F]{2}',
            r'chr\s*\(\s*\d+\s*\)',
            r'\$\{["\']\\x[0-9a-f]{2}'
        ]
        
        self.compiled_webshell = [re.compile(p, re.IGNORECASE) for p in self.webshell_patterns]

    def calculate_entropy(self, data):
        if not data: return 0.0
        counter = Counter(data)
        length = len(data)
        return -sum((count/length) * np.log2(count/length) for count in counter.values())

    def is_base64_encoded(self, data):
        try:
            if len(data) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
                base64.b64decode(data, validate=True)
                return True
        except: pass
        return False

    def _deobfuscate_payload(self, payload):
        try:
            current = urllib.parse.unquote(payload)
            b64_pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
            matches = re.findall(b64_pattern, current)
            for m in matches:
                try:
                    decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                    if any(kw in decoded.lower() for kw in ['system', 'eval', 'exec', 'sh']):
                        current += " " + decoded
                except: continue
            return current
        except: return payload
    
    def should_analyze(self, payload):
        if not payload or len(payload) < 10:
            return False

        if self.is_http_response(payload):
            return False

        if isinstance(payload, bytes):
            if len(payload) >= 4 and payload[:4] == b'\x89PNG':
                return False
            if len(payload) >= 3 and payload[:3] == b'\xFF\xD8\xFF':
                return False
            if len(payload) >= 6 and payload[:6] in (b'GIF87a', b'GIF89a'):
                return False
            if len(payload) >= 2 and payload[:2] == b'BM':
                return False
        
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else payload
        except:
            return True
    
        payload_lower = payload_str.lower()
    
        skip_types = ['content-type: image/', 'content-type: video/', 'content-type: audio/']
        for skip_type in skip_types:
            if skip_type in payload_lower:
                return False
    
        return True

    def is_http_response(self, payload):
        try:
            payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else payload
            header = payload_str[:100]
        
            if header.startswith('HTTP/'):
                logger.debug("HTTP response: HTTP/ prefix")
                return True
        
            if re.match(r'HTTP/\d\.\d\s+\d{3}', header):
                logger.debug("HTTP response: status pattern")
                return True
        
            for h in ['Content-Type:', 'Content-Length:', 'Server:', 'X-Powered-By:']:
                if h in header[:50]:
                    logger.debug(f"HTTP response: {h}")
                    return True
        
            first_200 = payload_str[:200].lower()
            count = sum(1 for h in ['content-type:', 'content-length:', 'x-powered-by:', 'server:', 'set-cookie:'] 
                    if h in first_200)
        
            if count >= 2:
                logger.debug(f"HTTP response: {count} headers")
                return True
        
            return False
        except:
            return False

    def extract_features(self, payload):
        payload = self._deobfuscate_payload(payload)
        if not payload: return np.zeros(29)
        
        p_lower = payload.lower()
        length = len(payload)
        lines = payload.split('\n')
        
        f = []
        # Nhóm 1: Basic
        f.append(length)
        f.append(self.calculate_entropy(payload))
        f.append(sum(1 for c in payload if not c.isalnum()) / length if length > 0 else 0)
        f.append(p_lower.count('base64'))

        # Nhóm 2: Dangerous Funcs 
        for func in ['eval', 'exec', 'system', 'shell_exec', 'passthru', 'assert']:
            f.append(p_lower.count(func))

        # Nhóm 3: Input/Obfuscation 
        f.append(payload.count('$_GET') + payload.count('$_POST') + payload.count('$_REQUEST'))
        f.append(len(re.findall(r'\\x[0-9a-fA-F]{2}', payload)))
        f.append(p_lower.count('chr(') + p_lower.count('ord('))
        f.append(1 if re.search(r'[A-Za-z0-9+/]{30,}', payload) else 0)
        f.append(1 if self.is_base64_encoded(payload) else 0)

        # Nhóm 4: Network/File 
        for func in ['socket', 'fsockopen', 'curl', 'fopen', 'file_get_contents']:
            f.append(p_lower.count(func))

        # Nhóm 5: Char Analysis 
        f.append(payload.count('(') + payload.count('[') + payload.count('{'))
        f.append(payload.count('|'))
        f.append(payload.count(';'))
        f.append(sum(1 for c in payload if c.isupper()) / length if length > 0 else 0)
        f.append(length / len(lines) if lines else 0)
        words = re.findall(r'\b\w+\b', payload)
        f.append(max(len(w) for w in words) if words else 0)

        # Nhóm 6: Upload 
        for ind in ['multipart/form-data', 'filename=', 'content-disposition']:
            f.append(1 if ind in p_lower else 0)

        return np.array(f[:29])

    def signature_detection(self, payload):
        detections = {'webshell': False, 'matched_patterns': []}
        for pattern in self.compiled_webshell:
            if pattern.search(payload):
                detections['webshell'] = True
                detections['matched_patterns'].append(pattern.pattern)
        return detections

    def predict(self, payload):
        sig_result = self.signature_detection(payload)
        try:
            if self.scaler is None: raise Exception("Models not loaded")
            
            features = self.extract_features(payload).reshape(1, -1)
            features_scaled = self.scaler.transform(features)
            
            rf_pred = self.rf_classifier.predict(features_scaled)[0]
            rf_proba = self.rf_classifier.predict_proba(features_scaled)[0][1]
            iso_pred = self.isolation_forest.predict(features_scaled)[0]
            
            is_malicious = bool(rf_pred == 1 or sig_result['webshell'])
            
            result = {
                'is_malicious': is_malicious,
                'confidence': float(rf_proba),
                'is_anomaly': bool(iso_pred == -1),
                'signature_detection': sig_result,
                'detection_method': []
            }
            
            if rf_pred == 1: result['detection_method'].append('ML_RandomForest')
            if iso_pred == -1: result['detection_method'].append('ML_AnomalyDetection')
            if sig_result['webshell']: result['detection_method'].append('Signature_WebShell')
            
            return result
        except Exception as e:
            logger.error(f"Prediction Error: {e}")
            return {'is_malicious': sig_result['webshell'], 'confidence': 0.0, 'signature_detection': sig_result, 'detection_method': ['Signature_Only']}

    def load_model(self, path='/home/imlampham/snort-ai/models/'):
        try:
            self.rf_classifier = joblib.load(f'{path}rf_classifier.pkl')
            self.isolation_forest = joblib.load(f'{path}isolation_forest.pkl')
            self.scaler = joblib.load(f'{path}scaler.pkl')
            logger.info("✓ AI models and 29-feature Scaler loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False

detector = WebShellDetector()

def analyze_http_payload(payload, src_ip, dst_ip, dst_port):
    if not payload: return None

    if not detector.should_analyze(payload): return None
    
    payload_str = payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else str(payload)
    
    webshell_result = detector.predict(payload_str)
    
    return {
        'timestamp': logging.Formatter().formatTime(logging.LogRecord('', 0, '', 0, '', (), None)),
        'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port,
        'webshell_detection': webshell_result,
        'alert_level': 'CRITICAL' if webshell_result['is_malicious'] else 'INFO'
    }