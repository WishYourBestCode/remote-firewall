#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <nlohmann/json.hpp>
#include <boost/config.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <memory>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;
using namespace std::chrono_literals;
using namespace std;

std::string get_private_ip() {
    std::string ip_address = "127.0.0.1"; // Default to localhost in case of error

    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        std::cerr << "Error creating socket\n";
        return ip_address;
    }

    try {
        // Connect to a non-existent external server (Google's DNS 8.8.8.8 on port 80)
        sockaddr_in remote_addr;
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(80); // Port 80
        inet_pton(AF_INET, "8.8.8.8", &remote_addr.sin_addr); // Convert IP to binary format

        // Connect the socket
        if (connect(sock, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
            std::cerr << "Error connecting to remote server\n";
            close(sock);
            return ip_address;
        }

        // Get the local IP address from the socket
        sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) == -1) {
            std::cerr << "Error getting local IP address\n";
            close(sock);
            return ip_address;
        }

        // Convert the local IP address to human-readable form
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, ip, sizeof(ip));
        ip_address = std::string(ip); // Assign to the string

    } catch (...) {
        std::cerr << "An error occurred\n";
    }

    // Close the socket
    close(sock);

    return ip_address;
}

string forward_to_python(const string& data) {
    try {
        std::cout << "Forwarding to Python server: " << data << std::endl;

        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);
        boost::asio::connect(socket, resolver.resolve(get_private_ip(), "65432"));

        // Send data in chunks
        size_t chunk_size = 1024;
        for (size_t i = 0; i < data.size(); i += chunk_size) {
            std::string chunk = data.substr(i, chunk_size);
            boost::asio::write(socket, boost::asio::buffer(chunk));
        }

        // Prepare to receive the response
        std::array<char, 1024> buffer;
        boost::system::error_code error;
        std::string python_response;

        // Read response in chunks
        while (true) {
            size_t reply_length = socket.read_some(boost::asio::buffer(buffer), error);

            if (error == boost::asio::error::eof) {
                break;  // Connection closed cleanly by the server
            } else if (error) {
                throw boost::system::system_error(error);  // Other errors
            }

            python_response.append(buffer.data(), reply_length);
        }

        std::cout << "Received response from Python server: " << python_response << std::endl;
        return python_response;
    }
    catch (std::exception& e) {
        std::cerr << "Python server communication error: " << e.what() << std::endl;
        return "Error communicating with Python server";
    }
}



class session : public std::enable_shared_from_this<session> {
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::string user_manual = "Default user manual information";
    net::steady_timer timer_; // Timer for managing timeouts

public:
    explicit session(tcp::socket socket)
        : socket_(std::move(socket)), timer_(socket_.get_executor()) {}

    void run() {
        std::cout << "New connection established from: " << socket_.remote_endpoint() << std::endl;
        start_timer();
        do_read();
    }

private:
    void start_timer() {
        timer_.expires_after(30s);
        auto self(shared_from_this());
        timer_.async_wait([self](beast::error_code ec) {
            if (!ec) {
                std::cerr << "Closing connection due to inactivity\n";
                self->socket_.close();
            }
        });
    }

    void reset_timer() {
        timer_.expires_after(30s);
    }

    void do_read() {
        auto self(shared_from_this());
        http::async_read(socket_, buffer_, req_,
            [self](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(bytes_transferred);
                self->reset_timer(); // Reset timer on activity
                if (!ec) {
                    std::cout << "Received message: " << self->req_.body() << std::endl;
                    self->handle_request();
                } else {
                    std::cerr << "Error during read: " << ec.message() << std::endl;
                    self->socket_.close(); // Close the socket on error
                }
            });
    }

    void handle_request() {
        http::response<http::string_body> res;

        if (req_.method() == http::verb::get) {
            handle_get(res);

        } else if (req_.method() == http::verb::post) {
            handle_post(res);
        } else if (req_.method() == http::verb::options) {
            // Respond to OPTIONS preflight request
            res.result(http::status::no_content);
            res.set(http::field::access_control_allow_origin, "*");
            res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
            res.set(http::field::access_control_allow_headers, "Content-Type");
        } else {
            handle_bad_request(res);

            res.set(http::field::access_control_allow_origin, "*");
            res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
            res.set(http::field::access_control_allow_headers, "Content-Type");

            send_response(res);
        }
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        send_response(res);
    }

    void handle_get(http::response<http::string_body>& res) {
 std::string user_manual = R"(
    {
      "message": {
        "General_Guidelines": "Your input should clearly define the action (e.g., block, drop, reject) and the source and/or destination IP addresses. You can include optional information such as ports and protocols (e.g., TCP, UDP, ICMP). The input can be flexible in its structure, but it must adhere to certain patterns to be parsed correctly.",
        "Input_Patterns_and_Examples": {
          "A_Full_Pattern": {
            "Description": "Source and Destination IPs with Optional Ports. Use this pattern when you want to specify both a source and a destination IP address, optionally with ports.",
            "Input_Format": "[Action] [direction1] [source IP] on port[source port:optional] [direction2] [destination IP] on port [destination port:optional]",
            "Examples": [
              "Allow from 192.168.0.12 on port 1234 to 192.168.0.13 on port 5432 using TCP.",
              "Drop from on port 1234 to 192.168.0.12 on port 5432 using UDP.",
              "Reject from 192.168.0.12 to 192.168.0.14 on port 5432 using UDP."
            ]
          },
          "B_Single_Pattern": {
            "Description": "Use this pattern when specifying actions from a single side using a protocol (e.g., TCP, UDP).",
            "Input_Format": "[Action] [direction1] IP [source|destination IP] on port [source|destination port:optional] using [protocol]",
            "Examples": [
              "Allow from 192.168.0.12 using TCP.",
              "Drop from 192.168.0.12 on port 1234 using TCP.",
              "Reject from on port 1234 using UDP."
            ]
          },
          "C_ICMP_Pattern": {
            "Description": "Actions Targeting Specific Incoming IP and Port using the ICMP protocol",
            "Input_Format": "[Action] from [Source IP] using ICMP",
            "Examples": [
              "Allow from 192.168.0.12 using TCP.",
              "Drop limited Echo Requests using ICMP.",
              "Allow limited traffic using ICMP."
            ]
          }
        }
      }
    })";


    // Set up the HTTP response
    res.result(http::status::ok);
    res.version(req_.version());
    res.set(http::field::content_type, "application/json");
    res.body() = user_manual;
    res.prepare_payload();
    }

    void handle_post(http::response<http::string_body>& res) {
        std::string python_response = forward_to_python(req_.body());
        user_manual = req_.body();

        // Create a JSON object
        nlohmann::json json_response;
        json_response["message"] = python_response;  // Add the Python response to the JSON object

        res.result(http::status::ok);
        res.version(req_.version());
        res.set(http::field::content_type, "application/json");
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type");
        // Convert the JSON object to a string and set it as the response body
        res.body() = json_response.dump();
        res.prepare_payload();

    }

    void handle_bad_request(http::response<http::string_body>& res) {
        res.result(http::status::bad_request);
        res.version(req_.version());
        res.set(http::field::content_type, "text/plain");
        res.body() = "Invalid Request";
        res.prepare_payload();
    }

    void send_response(http::response<http::string_body>& res) {
        auto self(shared_from_this());

        // Ensure the response object stays alive until the async write completes
        auto res_ptr = std::make_shared<http::response<http::string_body>>(std::move(res));

        http::async_write(socket_, *res_ptr,
            [self, res_ptr](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(bytes_transferred);
                if (!ec) {
                    std::cout << "Sent response to " << self->req_.target() << ": " << self->req_.body() << std::endl;
                } else {
                    std::cerr << "Error during write: " << ec.message() << std::endl;
                }

                // Gracefully close the socket
                beast::error_code shutdown_ec;
                self->socket_.shutdown(tcp::socket::shutdown_send, shutdown_ec);
                if (shutdown_ec) {
                    std::cerr << "Error during shutdown: " << shutdown_ec.message() << std::endl;
                }

                // Ensure the connection is properly closed
                self->socket_.close();
                self->timer_.cancel(); // Cancel the timer as we're done with this session
            });
    }
};

class listener : public std::enable_shared_from_this<listener> {
    tcp::acceptor acceptor_;

public:
    listener(net::io_context& ioc, tcp::endpoint endpoint)
        : acceptor_(ioc) {
        beast::error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        acceptor_.bind(endpoint, ec);
        acceptor_.listen(net::socket_base::max_listen_connections, ec);

        std::cout << "Server is listening on " << endpoint.address() << ":" << endpoint.port() << std::endl;
    }

    void start_accepting() {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<session>(std::move(socket))->run();
                } else {
                    std::cerr << "Error during accept: " << ec.message() << std::endl;
                }
                self->do_accept(); // Continue accepting new connections
            });
    }
};

int main(int argc, char* argv[]) {
    try {
        cout<< get_private_ip() << endl;
        auto const address = net::ip::make_address(get_private_ip() );
        auto const port = static_cast<unsigned short>(12345);
        auto const threads = std::max<int>(1, std::thread::hardware_concurrency());

        net::io_context ioc{ threads };

        auto listener_ptr = std::make_shared<listener>(ioc, tcp::endpoint{ address, port });
        listener_ptr->start_accepting();  // Start accepting connections

        std::vector<std::thread> v;
        v.reserve(threads);
        for (auto i = 0; i < threads; ++i) {
            v.emplace_back([&ioc] {
                ioc.run();
            });
        }

        // Join all threads to ensure they complete before main thread exits
        for (auto& t : v) {
            if (t.joinable()) {
                t.join();
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
