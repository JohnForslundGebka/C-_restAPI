#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <iostream>
#include <memory>
#include <string>
#include <mutex>
#include <thread>
#include "nlohmann/json.hpp"
#include <fstream>

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;   // from <boost/beast/http.hpp>
namespace net = boost::asio;    // from <boost/asio.hpp>
using tcp = net::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

nlohmann::json json_data;
std::mutex json_data_mutex;

void load_json_data() {
    std::lock_guard<std::mutex> lock(json_data_mutex);
    std::ifstream json_file("/Users/John/CLionProjects/Cpp_restAPI/data.json");
    if (json_file.is_open()) {
        try {
            json_file >> json_data;
            std::cout << "JSON data loaded successfully." << std::endl;
        } catch (nlohmann::json::parse_error& e) {
            std::cerr << "JSON parsing error: " << e.what() << std::endl;
            json_data = nlohmann::json::object();
        }
        json_file.close();
    } else {
        std::cerr << "Failed to open data.json file." << std::endl;
        json_data = nlohmann::json::object();
    }
}

// This function produces an HTTP response for the given request.
http::response<http::string_body> handle_request(http::request<http::string_body> const& req) {
    if (req.method() == http::verb::get) {
        std::string target(req.target());
        if (target == "/api/magical_items") {
            // Serve all magical items
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::server, "Beast");
            res.set(http::field::content_type, "application/json");
            res.keep_alive(req.keep_alive());

            {
                std::lock_guard<std::mutex> lock(json_data_mutex);
                res.body() = json_data.dump();
            }

            res.prepare_payload();
            return res;

        } else if (target.find("/api/magical_items/") == 0) {
            // Serve a specific magical item
            std::string article_number = target.substr(std::string("/api/magical_items/").length());

            nlohmann::json item;
            bool found = false;

            {
                std::lock_guard<std::mutex> lock(json_data_mutex);
                for (const auto& it : json_data["magical_items"]) {
                    if (it["article_number"] == article_number) {
                        item = it;
                        found = true;
                        break;
                    }
                }
            }

            if (found) {
                // Return the found item
                http::response<http::string_body> res{http::status::ok, req.version()};
                res.set(http::field::server, "Beast");
                res.set(http::field::content_type, "application/json");
                res.keep_alive(req.keep_alive());
                res.body() = item.dump();
                res.prepare_payload();
                return res;
            } else {
                // Item not found
                http::response<http::string_body> res{http::status::not_found, req.version()};
                res.set(http::field::server, "Beast");
                res.set(http::field::content_type, "application/json");
                res.keep_alive(req.keep_alive());
                res.body() = "{\"error\":\"Item not found\"}";
                res.prepare_payload();
                return res;
            }
        }
    }

    // Default response for unsupported methods or endpoints
    http::response<http::string_body> res{http::status::bad_request, req.version()};
    res.set(http::field::server, "Beast");
    res.set(http::field::content_type, "application/json");
    res.keep_alive(req.keep_alive());
    res.body() = "{\"error\":\"Unsupported request\"}";
    res.prepare_payload();
    return res;
}

// This class handles an HTTP server connection.
class Session : public std::enable_shared_from_this<Session> {
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;

public:
    explicit Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void run() {
        do_read();
    }

private:
    void do_read() {
        auto self(shared_from_this());
        http::async_read(socket_, buffer_, req_, [this, self](beast::error_code ec, std::size_t) {
            if (!ec) {
                do_write(handle_request(req_));
            }
        });
    }

    void do_write(http::response<http::string_body> res) {
        auto self(shared_from_this());
        auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));
        http::async_write(socket_, *sp, [this, self, sp](beast::error_code ec, std::size_t) {
            socket_.shutdown(tcp::socket::shutdown_send, ec);
        });
    }
};

// This class accepts incoming connections and launches the sessions.
class Listener : public std::enable_shared_from_this<Listener> {
    net::io_context& ioc_;
    tcp::acceptor acceptor_;

public:
    Listener(net::io_context& ioc, tcp::endpoint endpoint)
            : ioc_(ioc), acceptor_(net::make_strand(ioc)) {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            std::cerr << "Open error: " << ec.message() << std::endl;
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            std::cerr << "Set option error: " << ec.message() << std::endl;
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if (ec) {
            std::cerr << "Bind error: " << ec.message() << std::endl;
            return;
        }

        // Start listening for connections
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            std::cerr << "Listen error: " << ec.message() << std::endl;
            return;
        }
    }
    void run() {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(net::make_strand(ioc_), [this](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<Session>(std::move(socket))->run();
            }
            do_accept();
        });
    }
};

int main() {

    load_json_data();
    try {
        auto const address = net::ip::make_address("0.0.0.0");
        unsigned short port = 8080;

        net::io_context ioc{1};

        auto listener = std::make_shared<Listener>(ioc, tcp::endpoint{address, port});
        listener->run();

        ioc.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}