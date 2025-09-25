from include import *

class BidirectionalChatInterface:
    def __init__(self, client):
        self.client = client
        self.chat_history = []
        self.lock = threading.Lock()

    def display_chat(self):
        os.system("clear")
        print("=== Chat ===")
        for message in self.chat_history[-50:]:
            ts = message.get("timestamp")
            time_str = time.strftime("%H:%M", time.localtime(ts)) if ts else "--:--"
            sender = "You" if message["sender"] == "self" else message["sender"]
            print(f"[{time_str}] {sender}: {message['content']}")
        print("\nType your message below:")

    def add_message(self, sender, content):
        with self.lock:
            self.chat_history.append({"sender": sender, "content": content, "timestamp": time.time()})
        self.display_chat()

    def send_message(self, connection_id, message):
        self.client.send_message(connection_id, message)
        self.add_message("self", message)

    def receive_message(self, sender, message):
        self.add_message(sender, message)
