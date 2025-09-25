import time

class Logger:
    @staticmethod
    def log_event(event_type: str, message: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(f"[{timestamp}] [{event_type}] {message}")
Logger.log_event("INFO", "Client initialized.")