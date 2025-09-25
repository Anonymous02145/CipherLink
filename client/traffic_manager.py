from include import *

class AnonymousTrafficManager:
    def __init__(self):
        self.traffic_queue = Queue()
        self.is_active = False
        self.obfuscation_thread = None

    def start_traffic_obfuscation(self):
        self.is_active = True
        self.obfuscation_thread = threading.Thread(
            target=self._traffic_obfuscation_loop, daemon=True
        )
        self.obfuscation_thread.start()

    def stop_traffic_obfuscation(self):
        self.is_active = False
        if self.obfuscation_thread:
            self.obfuscation_thread.join(timeout=5)

    def _traffic_obfuscation_loop(self):
        while self.is_active:
            try:
                time.sleep(random.uniform(0.1, 2.0))
                dummy_data = os.urandom(random.randint(50, 200))
            except Exception:
                break
