// WebSocket relay: clients connect to /ws?room=<name> and frames fan out to the
// other participants in that room. A GET /health endpoint returns "ok".

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <thread>
#include <memory>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/version.hpp>

using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;
namespace websocket = boost::beast::websocket;

struct WsSession; // fwd

static std::unordered_map<std::string, std::vector<std::weak_ptr<WsSession>>> g_rooms;
static std::mutex g_rooms_mtx;

struct WsSession : public std::enable_shared_from_this<WsSession> {
  websocket::stream<tcp::socket> ws;
  std::string room;

  explicit WsSession(tcp::socket s) : ws(std::move(s)) {}

  void do_run(std::string room_name) {
    room = std::move(room_name);
    {
      std::lock_guard<std::mutex> lk(g_rooms_mtx);
      auto& vec = g_rooms[room];
      // clean expired
      vec.erase(std::remove_if(vec.begin(), vec.end(),
               [](auto& w){ return w.expired(); }), vec.end());
      vec.push_back(this->shared_from_this());
    }
    // Read loop (blocking, simple)
    boost::system::error_code ec;
    ws.set_option(websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
    ws.binary(true);

    for (;;) {
      boost::beast::flat_buffer buffer;
      ws.read(buffer, ec);
      if (ec == websocket::error::closed || ec == boost::asio::error::eof) break;
      if (ec) { std::cerr << "[ws] read error: " << ec.message() << "\n"; break; }

      // broadcast to others in the room
      std::vector<std::shared_ptr<WsSession>> peers;
      {
        std::lock_guard<std::mutex> lk(g_rooms_mtx);
        auto it = g_rooms.find(room);
        if (it != g_rooms.end()) {
          for (auto& w : it->second) {
            if (auto p = w.lock()) {
              if (p.get() != this) peers.push_back(p);
            }
          }
          // also drop dead weak_ptrs
          it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
                [](auto& w){ return w.expired(); }), it->second.end());
        }
      }
      for (auto& p : peers) {
        boost::system::error_code wec;
        p->ws.binary(true);
        p->ws.write(buffer.data(), wec);
        if (wec) {
          std::cerr << "[ws] write error: " << wec.message() << "\n";
        }
      }
    }

    // on exit: remove self from room
    {
      std::lock_guard<std::mutex> lk(g_rooms_mtx);
      auto it = g_rooms.find(room);
      if (it != g_rooms.end()) {
        it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
              [&](auto& w){ return w.expired() || w.lock().get() == this; }), it->second.end());
        if (it->second.empty()) g_rooms.erase(it);
      }
    }
  }
};

static std::string url_decode(const std::string& s) {
  std::string out; out.reserve(s.size());
  for (size_t i=0;i<s.size();++i){
    if (s[i]=='%' && i+2<s.size()){
      unsigned int x=0; std::stringstream ss; ss<<std::hex<<s.substr(i+1,2); ss>>x;
      out.push_back(static_cast<char>(x)); i+=2;
    } else if (s[i]=='+') out.push_back(' ');
    else out.push_back(s[i]);
  }
  return out;
}

static std::string get_query_value(const std::string& target, const std::string& key) {
  auto qpos = target.find('?'); if (qpos==std::string::npos) return {};
  auto query = target.substr(qpos+1);
  size_t pos=0;
  while (pos<query.size()){
    size_t amp = query.find('&', pos);
    auto part = query.substr(pos, amp==std::string::npos?std::string::npos:amp-pos);
    size_t eq = part.find('=');
    auto k = url_decode(eq==std::string::npos?part:part.substr(0,eq));
    auto v = url_decode(eq==std::string::npos?std::string():part.substr(eq+1));
    if (k == key) return v;
    if (amp==std::string::npos) break;
    pos = amp + 1;
  }
  return {};
}

void do_http(tcp::socket socket) {
  boost::beast::flat_buffer buffer;
  http::request<http::string_body> req;
  boost::system::error_code ec;

  http::read(socket, buffer, req, ec);
  if (ec) { /* ignore */ }

  // health
  if (req.method()==http::verb::get && req.target()=="/health") {
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::content_type, "text/plain");
    res.body() = "ok";
    res.prepare_payload();
    http::write(socket, res);
    socket.shutdown(tcp::socket::shutdown_send, ec);
    return;
  }

  // if websocket upgrade requested
  if (websocket::is_upgrade(req)) {
    std::string target = std::string(req.target());
    if (target.rfind("/ws", 0) != 0) {
      // reject
      http::response<http::string_body> res{http::status::bad_request, req.version()};
      res.set(http::field::content_type, "text/plain");
      res.body() = "use /ws?room=<name>";
      res.prepare_payload();
      http::write(socket, res);
      socket.shutdown(tcp::socket::shutdown_send, ec);
      return;
    }
    std::string room = get_query_value(target, "room");
    if (room.empty()) room = "default";

    auto session = std::make_shared<WsSession>(std::move(socket));
    // Accept handshake
    session->ws.accept(req, ec);
    if (ec) { std::cerr << "[ws] accept: " << ec.message() << "\n"; return; }
    std::thread([session, room]{ session->do_run(room); }).detach();
    return;
  }

  // default 404
  http::response<http::string_body> res{http::status::not_found, req.version()};
  res.set(http::field::content_type, "text/plain");
  res.body() = "not found";
  res.prepare_payload();
  http::write(socket, res);
  socket.shutdown(tcp::socket::shutdown_send, ec);
}

int main(int argc, char* argv[]) {
  try {
    unsigned short port = 8080;
    if (argc >= 2) port = static_cast<unsigned short>(std::atoi(argv[1]));
    boost::asio::io_context ioc{1};
    tcp::acceptor acc{ioc, tcp::endpoint(tcp::v4(), port)};
    std::cout << "[relay] Listening on port " << port << " (/ws?room=<name>)\n";
    for (;;) {
      tcp::socket socket{ioc};
      acc.accept(socket);
      std::thread(&do_http, std::move(socket)).detach();
    }
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
