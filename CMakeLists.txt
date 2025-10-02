cmake_minimum_required(VERSION 3.14)
project(PQC_Messenger_Phase5_6 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- Dependencies ----
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED Crypto SSL)
find_package(Boost 1.71 REQUIRED COMPONENTS system)
find_package(Protobuf REQUIRED)
find_package(absl CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OQS REQUIRED IMPORTED_TARGET liboqs)

# Qt (Widgets + Network + WebSockets)
# If CMake can't find it, configure with: -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/qt"
find_package(Qt6 COMPONENTS Widgets Network WebSockets REQUIRED)

# Enable Qt's automoc for targets that use Qt
set(CMAKE_AUTOMOC ON)

# ---- Protobuf (messages, envelope, handshake) ----
set(PROTO_FILES
  ${CMAKE_SOURCE_DIR}/messages.proto
  ${CMAKE_SOURCE_DIR}/envelope.proto
  ${CMAKE_SOURCE_DIR}/handshake.proto
)

if (COMMAND protobuf_generate_cpp)
  protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
else()
  PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
endif()

add_library(messages_proto ${PROTO_SRCS} ${PROTO_HDRS})
if (TARGET protobuf::libprotobuf)
  target_link_libraries(messages_proto PUBLIC protobuf::libprotobuf)
elseif (TARGET Protobuf::protobuf)
  target_link_libraries(messages_proto PUBLIC Protobuf::protobuf)
else()
  target_link_libraries(messages_proto PUBLIC ${Protobuf_LIBRARIES})
endif()
target_link_libraries(messages_proto PUBLIC
  absl::log absl::check absl::log_internal_check_op absl::strings absl::base
)
target_include_directories(messages_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

# ---- Engine hooks (transport/session) ----
add_library(engine
  tcp_transport.cpp
  tcp_transport.h
  transport.h
  session.h
  connection_engine.cpp
  connection_engine.h
  beast_ws_transport.cpp
  beast_ws_transport.h
)
target_link_libraries(engine PUBLIC
  Boost::system
  Threads::Threads
  messages_proto
  identity
  pqc_kem
  OpenSSL::SSL OpenSSL::Crypto
)
target_include_directories(engine PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# ---- PQC KEM + HKDF ----
add_library(pqc_kem
  kem_kyber.cpp
  kem_kyber.h
  hkdf.cpp
  hkdf.h
)
target_link_libraries(pqc_kem PUBLIC PkgConfig::OQS OpenSSL::Crypto)
target_include_directories(pqc_kem PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---- Identity (Ed25519 + encrypted keystore) ----
add_library(identity
  identity.cpp
  identity.h
)
target_link_libraries(identity PUBLIC OpenSSL::Crypto)
target_include_directories(identity PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---- Common deps for console apps ----
add_library(common_deps INTERFACE)
target_link_libraries(common_deps INTERFACE
  messages_proto
  engine
  pqc_kem
  identity
  OpenSSL::Crypto
)
target_include_directories(common_deps INTERFACE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# ---- Console apps (dev/testing) ----
add_executable(pqc_server server.cpp)
target_link_libraries(pqc_server PRIVATE common_deps)
set_target_properties(pqc_server PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

add_executable(pqc_client client.cpp)
target_link_libraries(pqc_client PRIVATE common_deps)
set_target_properties(pqc_client PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

# ---- GUI target (Relay-ready) ----
option(BUILD_GUI "Build the Qt GUI app" ON)
if (BUILD_GUI)
  set(GUI_DIR ${CMAKE_SOURCE_DIR}/gui)
  set(GUI_SOURCES
    ${GUI_DIR}/main.cpp
    ${GUI_DIR}/MainWindow.cpp
    ${GUI_DIR}/EngineWorker.cpp
    ws_transport.cpp          # WebSocket transport source
    ws_transport.h            # header (for IDE convenience)
  )
  set(GUI_HEADERS
    ${GUI_DIR}/MainWindow.h
    ${GUI_DIR}/EngineWorker.h
  )

  add_executable(e2ee_chat_gui ${GUI_SOURCES} ${GUI_HEADERS})
  target_link_libraries(e2ee_chat_gui PRIVATE
    Qt6::Widgets Qt6::Network Qt6::WebSockets
    common_deps
  )
  # On recent macOS, AGL is unavailable. Ensure no OpenGL is pulled in implicitly.
  target_compile_definitions(e2ee_chat_gui PRIVATE QT_NO_OPENGL)
  target_include_directories(e2ee_chat_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

# ---- Relay server (WebSocket) ----
# Minimal relay that forwards binary frames between clients in the same /ws?room=...
add_executable(relay_server relay_server.cpp)
target_link_libraries(relay_server PRIVATE Boost::system Threads::Threads)
# Ensure no Qt automoc runs on this non-Qt target:
set_target_properties(relay_server PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

# ---- Relay CLI (WebSocket) ----
add_executable(relay_cli relay_cli.cpp)
target_link_libraries(relay_cli PRIVATE common_deps)
set_target_properties(relay_cli PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

# Optional sanitizers (opt-in)
option(ENABLE_SANITIZERS "Build with Address/Undefined sanitizers" OFF)
if (ENABLE_SANITIZERS)
  foreach(tgt IN ITEMS relay_cli pqc_client pqc_server engine_loopback_test)
    if (TARGET ${tgt})
      target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endif()
  endforeach()
  target_compile_options(engine PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(engine PRIVATE -fsanitize=address,undefined)
endif()

# ---- In-memory engine loopback test (no sockets) ----
add_executable(engine_loopback_test tools/engine_loopback_test.cpp)
target_link_libraries(engine_loopback_test PRIVATE common_deps)
set_target_properties(engine_loopback_test PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
