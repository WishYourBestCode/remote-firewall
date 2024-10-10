cmake_minimum_required(VERSION 3.29)
project(BridgeServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Boost libraries
find_package(Boost 1.65 REQUIRED COMPONENTS system thread)

# Include directories for Boost and WebSocket++
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/websocketpp)

# Find Boost libraries
find_package(Boost 1.65 REQUIRED COMPONENTS system thread)



# FetchContent module to download nlohmann/json
include(FetchContent)
FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.2  # Replace with the latest version or desired version
)
FetchContent_MakeAvailable(json)

# Add your executable
add_executable(BridgeServer main.cpp)

# Link Boost and nlohmann::json to your executable
target_link_libraries(BridgeServer Boost::system Boost::thread pthread nlohmann_json::nlohmann_json)
