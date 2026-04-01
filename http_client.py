import requests
import time
from typing import Dict, Any, Tuple

class FuzzerHttpClient:
    def __init__(self, base_url: str, delay: float = 0.2):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.delay = delay
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
        })

    def send_request(self, method: str, path: str, payload: Dict[str, Any]) -> Tuple[int, Dict, str, float]:
        full_url = f"{self.base_url}{path}"
        
        start_time = time.time()
        try:
            time.sleep(self.delay)
            response = self.session.request(method, full_url, json=payload, timeout=15, verify=False)
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            return response.status_code, response.headers, response.text, duration_ms
        except requests.exceptions.RequestException as e:
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            return 0, {}, str(e), duration_ms