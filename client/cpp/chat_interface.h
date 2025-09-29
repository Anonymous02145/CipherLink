#pragma once
#include "include.h"

#include <vector>
#include <string>
#include <mutex>
#include <memory>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace anon {

struct ChatMessage {
    std::string sender;
    std::string content;
    double timestamp; // epoch seconds
};

// Abstract client interface for sending messages
class IClient {
public:
    virtual ~IClient() = default;
    virtual void send_message(const std::string& connection_id, const std::string& message) = 0;
};

class BidirectionalChatInterface {
public:
    explicit BidirectionalChatInterface(std::shared_ptr<IClient> client);
    ~BidirectionalChatInterface() = default;

    // Add a message from sender (thread-safe) and display chat
    void add_message(const std::string& sender, const std::string& content);

    // Send a message to a connection ID and add to history
    void send_message(const std::string& connection_id, const std::string& message);

    // Receive a message from another user and add to history
    void receive_message(const std::string& sender, const std::string& message);

    // Display the last N messages (default last 50)
    void display_chat(size_t last_n = 50) const;

private:
    std::shared_ptr<IClient> client_;
    mutable std::mutex lock_;
    std::vector<ChatMessage> chat_history_;
};

} // namespace anon
