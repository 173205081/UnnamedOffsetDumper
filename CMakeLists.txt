﻿cmake_minimum_required(VERSION 3.8)

project("UnnamedOffsetDumper")
add_executable(${PROJECT_NAME} "main.cpp")

if(CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
endif()
