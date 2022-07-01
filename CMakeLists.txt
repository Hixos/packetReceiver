cmake_minimum_required(VERSION 3.4)

project(packetReceiver VERSION 1.0
                  DESCRIPTION "Receive UDP mutlicast packets from packetSender"
                  LANGUAGES CXX)
                  
add_compile_options(-Wall -Wextra -pedantic -Werror)
add_executable(packetReceiver src/packetReceiver.cpp)
