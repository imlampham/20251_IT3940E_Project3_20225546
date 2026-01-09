import os, re, requests, hashlib, math, time, logging, pandas as pd
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Recrawler')

class WebShellDataFactory:
    def __init__(self, github_token=None):
        self.headers = {"Authorization": f"token {github_token}"} if github_token else {}
        self.unique_hashes = set()
        self.features_list = []
        self.malicious_count = 0
        self.benign_count = 0

    def calculate_entropy(self, data):
        if not data: return 0.0
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
        if not payload or len(payload) == 0: return None
        
        p_lower = payload.lower()
        length = len(payload)
        lines = payload.split('\n')
        
        f = {}
        # Nhóm 1: Basic 
        f['length'] = length
        f['entropy'] = self.calculate_entropy(payload)
        f['special_char_ratio'] = sum(1 for c in payload if not c.isalnum()) / length if length > 0 else 0
        f['b64_keyword'] = p_lower.count('base64')

        # Nhóm 2: Dangerous Functions 
        for func in ['eval', 'exec', 'system', 'shell_exec', 'passthru', 'assert']:
            f[f'{func}_cnt'] = p_lower.count(func)

        # Nhóm 3: Obfuscation 
        f['user_input'] = payload.count('$_GET') + payload.count('$_POST') + payload.count('$_REQUEST')
        f['hex_enc'] = len(re.findall(r'\\x[0-9a-fA-F]{2}', payload))
        f['chr_ord'] = p_lower.count('chr(') + p_lower.count('ord(')
        f['long_b64'] = 1 if re.search(r'[A-Za-z0-9+/]{30,}', payload) else 0
        f['is_b64_logic'] = 1 if self.is_base64_encoded(payload) else 0

        # Nhóm 4: Network/File 
        for func in ['socket', 'fsockopen', 'curl', 'fopen', 'file_get_contents']:
            f[f'{func}_cnt'] = p_lower.count(func)

        # Nhóm 5: Char Analysis 
        f['brackets'] = payload.count('(') + payload.count('[') + payload.count('{')
        f['pipe'] = payload.count('|')
        f['semicolon'] = payload.count(';')
        f['upper_ratio'] = sum(1 for c in payload if c.isupper()) / length if length > 0 else 0
        f['avg_line_len'] = length / len(lines) if lines else 0
        words = re.findall(r'\b\w+\b', payload)
        f['max_word_len'] = max(len(w) for w in words) if words else 0

        # Nhóm 6: Upload 
        for ind in ['multipart/form-data', 'filename=', 'content-disposition']:
            f[f'has_{ind[:5]}'] = 1 if ind in p_lower else 0

        f['label'] = label
        return f

    def crawl_repo(self, owner, repo, path="", is_malicious=True, max_files=1500):
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        try:
            response = requests.get(api_url, headers=self.headers, timeout=15)
            if response.status_code != 200: return

            for item in response.json():
                if item['type'] == 'dir':
                    self.crawl_repo(owner, repo, item['path'], is_malicious, max_files)
                elif item['type'] == 'file' and item['name'].lower().endswith(('.php', '.sh', '.py', '.txt')):
                    current_count = self.malicious_count if is_malicious else self.benign_count
                    if current_count >= max_files: return

                    res = requests.get(item['download_url'], timeout=10)
                    if res.status_code == 200:
                        content = res.text
                        c_hash = hashlib.md5(content.encode()).hexdigest()
                        if c_hash not in self.unique_hashes and len(content) > 50:
                            self.unique_hashes.add(c_hash)
                            feat = self.extract_features(content, 1 if is_malicious else 0)
                            if feat:
                                self.features_list.append(feat)
                                if is_malicious: self.malicious_count += 1
                                else: self.benign_count += 1
            time.sleep(0.05)
        except Exception as e: logger.error(f"Error: {e}")

    def export_csv(self):
        df = pd.DataFrame(self.features_list)
        df.to_csv("webshell_dataset.csv", index=False)
        logger.info(f"--- ĐÃ XUẤT DATASET: {len(df)} mẫu, 29 features ---")

if __name__ == "__main__":
    factory = WebShellDataFactory(github_token="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")

    logger.info("--- ĐANG THU THẬP MÃ ĐỘC ---")
    factory.crawl_repo("tennc", "webshell")

    logger.info("--- ĐANG THU THẬP MÃ SẠCH ---")
    factory.crawl_repo("WordPress", "WordPress", path="wp-includes", is_malicious=False)
    factory.crawl_repo("torvalds", "linux", path="scripts", is_malicious=False)
    factory.crawl_repo("ansible", "ansible", path="lib/ansible/modules/system", is_malicious=False)
    factory.crawl_repo("ohmyzsh", "ohmyzsh", path="tools", is_malicious=False)

    factory.export_csv()