cmake_minimum_required(VERSION 3.16)
project(znc-ircv3 LANGUAGES CXX)

# Out-of-tree ZNC modules: soju-style bouncer-networks and IRCv3 drafts.
# Build against an installed ZNC (>= 1.10):
#   cmake -S . -B build -DZNC_DIR=/prefix/share/znc/cmake
# Each module is a separate .so that goes into ZNC's module directory or
# <datadir>/modules.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(ZNC REQUIRED)

add_compile_options(-Wall -Wextra -Wno-unused-parameter)
option(IRCV3_STRICT "Treat warnings as errors" OFF)
if(IRCV3_STRICT)
  add_compile_options(-Werror)
endif()

set(IRCV3_MODULES "" CACHE INTERNAL "")
function(ircv3_module name)
  add_library(${name} MODULE modules/${name}.cpp)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
  znc_setup_module(TARGET ${name} NAME ${name})
  set(IRCV3_MODULES ${IRCV3_MODULES} ${name} CACHE INTERNAL "")
endfunction()

ircv3_module(ircv3base)
ircv3_module(bouncernetworks)
ircv3_module(readmarker)
ircv3_module(chathistory)
ircv3_module(labeled)
ircv3_module(multiline)
ircv3_module(websocket)
ircv3_module(webpush)
target_link_libraries(webpush PRIVATE OpenSSL::Crypto)
target_compile_definitions(webpush PRIVATE OPENSSL_SUPPRESS_DEPRECATED)

install(TARGETS ${IRCV3_MODULES} LIBRARY DESTINATION lib/znc)
