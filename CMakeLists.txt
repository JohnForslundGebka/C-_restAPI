cmake_minimum_required(VERSION 3.29)
project(RESTfullAPI)

set(CMAKE_CXX_STANDARD 20)


# Find the nlohmann/json and Boost libraries
find_package(nlohmann_json REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem)

add_executable(RESTfullAPI main.cpp)

# Link the libraries to your executable
target_link_libraries(RESTfullAPI nlohmann_json::nlohmann_json Boost::boost Boost::filesystem Boost::system)