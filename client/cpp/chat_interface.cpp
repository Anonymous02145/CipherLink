#include "chat_interface.h"
#include <cstdlib>

namespace anon {

BidirectionalChatInterface::BidirectionalChatInterface(std::shared_ptr<IClient> client)
    : client_(std::move(client)) {}

void BidirectionalChatInterface::add_message(const std::string& sender, const std::string& content) {
    double ts = epoch_seconds_now_double();
    {
        std::lock_guard<std::mutex> guard(lock_);
        chat_history_.push_back(ChatMessage{sender, content, ts});
    }
    display_chat();
}

void BidirectionalChatInterface::send_message(const std::string& connection_id, const std::string& message) {
    if (client_) {
        client_->send_message(connection_id, message);
    }
    add_message("self", message);
}

void BidirectionalChatInterface::receive_message(const std::string& sender, const std::string& message) {
    add_message(sender, message);
}

void BidirectionalChatInterface::display_chat(size_t last_n) const {
    std::lock_guard<std::mutex> guard(lock_);

    // Clear console (platform dependent; works on Linux/macOS)
    std::system("clear");

    std::cout << "=== Chat ===\n";
    size_t start_idx = chat_history_.size() > last_n ? chat_history_.size() - last_n : 0;
    for (size_t i = start_idx; i < chat_history_.size(); ++i) {
        const auto& message = chat_history_[i];
        std::time_t t = static_cast<std::time_t>(message.timestamp);
        std::tm tm = *std::localtime(&t);
        std::ostringstream time_ss;
        time_ss << std::setw(2) << std::setfill('0') << tm.tm_hour
                << ":" << std::setw(2) << std::setfill('0') << tm.tm_min;

        std::string sender_name = (message.sender == "self") ? "You" : message.sender;
        std::cout << "[" << time_ss.str() << "] " << sender_name << ": " << message.content << "\n";
    }
    std::cout << "\nType your message below:\n";
}

} // namespace anon
