import os
import re
import requests
import hashlib
import math
import time
import pandas as pd
import logging
import numpy as np
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('DataProcessor')

class WebShellDataFactory:
    def __init__(self, github_token=None):
        self.headers = {"Authorization": f"token {github_token}"} if github_token else {}
        self.unique_hashes = set()
        self.features_list = []
        
    def calculate_entropy(self, data):
        if not data: return 0
        counter = Counter(data)
        length = len(data)
        return -sum((count/length) * math.log2(count/length) for count in counter.values())

    def is_base64_encoded(self, data):
        try:
            if len(data) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
                import base64
                base64.b64decode(data, validate=True)
                return True
        except: pass
        return False

    def extract_features(self, payload, label):
        if not payload: return None
        
        features = []
        
        features.append(len(payload))

        features.append(self.calculate_entropy(payload))

        special_chars = sum(1 for c in payload if not c.isalnum())
        features.append(special_chars / len(payload) if len(payload) > 0 else 0)

        features.append(payload.count('base64'))
        
        dangerous_funcs = ['eval', 'exec', 'system', 'shell_exec', 'passthru', 'assert']
        for func in dangerous_funcs:
            features.append(payload.lower().count(func))
        
        features.append(payload.count('$_GET') + payload.count('$_POST') + payload.count('$_REQUEST'))

        features.append(len(re.findall(r'\\x[0-9a-fA-F]{2}', payload)))
        

        lines = payload.split('\n')
        features.append(sum(len(line) for line in lines) / len(lines) if lines else 0)

        features.append(payload.count('chr(') + payload.count('ord('))

        features.append(1 if self.is_base64_encoded(payload) else 0)
        
        network_funcs = ['socket', 'fsockopen', 'curl', 'fopen', 'file_get_contents']
        for func in network_funcs:
            features.append(payload.lower().count(func))
            
        features.append(payload.count('%'))

        features.append(payload.count('(') + payload.count('[') + payload.count('{'))

        upper_ratio = sum(1 for c in payload if c.isupper()) / len(payload) if len(payload) > 0 else 0
        features.append(upper_ratio)

        words = re.findall(r'\b\w+\b', payload)
        features.append(max(len(w) for w in words) if words else 0)
        
        features.append(payload.count(';'))

        features.append(payload.count('|'))
        
        upload_indicators = ['multipart/form-data', 'filename=', 'Content-Disposition']
        for indicator in upload_indicators:
            features.append(1 if indicator in payload else 0)
            
        while len(features) < 50:
            features.append(0)
            
        feat_dict = {f'f_{i}': val for i, val in enumerate(features)}
        feat_dict['label'] = label
        return feat_dict

    def crawl_and_process(self, owner, repo, path="", is_malicious=True):
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        try:
            response = requests.get(api_url, headers=self.headers, timeout=15)
            if response.status_code != 200: return

            items = response.json()
            for item in items:
                if item['type'] == 'dir':
                    self.crawl_and_process(owner, repo, item['path'], is_malicious)
                elif item['type'] == 'file':
                    if item['name'].lower().endswith(('.php', '.sh', '.py', '.pl', '.asp', '.jsp', '.txt')):
                        res = requests.get(item['download_url'], timeout=10)
                        if res.status_code == 200:
                            content = res.text
                            content_hash = hashlib.md5(content.encode()).hexdigest()
                            if content_hash not in self.unique_hashes and len(content) > 50:
                                self.unique_hashes.add(content_hash)
                                label = 1 if is_malicious else 0
                                feat = self.extract_features(content, label)
                                if feat:
                                    self.features_list.append(feat)
                                    if len(self.features_list) % 100 == 0:
                                        logger.info(f"Processed {len(self.features_list)} samples...")
            time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error: {e}")

    def export_csv(self, filename="webshell_dataset.csv"):
        df = pd.DataFrame(self.features_list)
        df.to_csv(filename, index=False)
        logger.info(f"--- ĐÃ XUẤT DATASET: {len(df)} mẫu vào {filename} ---")

if __name__ == "__main__":
    factory = WebShellDataFactory(github_token="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")

    logger.info("--- ĐANG THU THẬP MÃ ĐỘC ---")
    factory.crawl_and_process("tennc", "webshell")

    logger.info("--- ĐANG THU THẬP MÃ SẠCH ---")
    factory.crawl_and_process("WordPress", "WordPress", path="wp-includes", is_malicious=False)
    factory.crawl_and_process("torvalds", "linux", path="scripts", is_malicious=False)
    factory.crawl_and_process("ansible", "ansible", path="lib/ansible/modules/system", is_malicious=False)
    factory.crawl_and_process("ohmyzsh", "ohmyzsh", path="tools", is_malicious=False)

    factory.export_csv("webshell_dataset.csv")