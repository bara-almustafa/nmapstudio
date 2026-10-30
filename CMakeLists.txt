cmake_minimum_required(VERSION 3.15)
project(nmapstudio C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ------------------------------------------------------------------ options
option(EMBED_WEB "Embed the web UI into the binary (single-file deploy)" ON)

# ------------------------------------------------------------- embed web UI
set(EMB_HEADER "${CMAKE_BINARY_DIR}/embedded_web.h")
if(EMBED_WEB)
  add_custom_command(
    OUTPUT  "${EMB_HEADER}"
    COMMAND ${CMAKE_COMMAND}
            -DSRCDIR=${CMAKE_SOURCE_DIR} -DOUT=${EMB_HEADER}
            -P ${CMAKE_SOURCE_DIR}/cmake/embed.cmake
    DEPENDS ${CMAKE_SOURCE_DIR}/web/index.html
            ${CMAKE_SOURCE_DIR}/web/app.js
            ${CMAKE_SOURCE_DIR}/web/style.css
            ${CMAKE_SOURCE_DIR}/cmake/embed.cmake
    COMMENT "Embedding web UI assets")
  add_custom_target(genweb DEPENDS "${EMB_HEADER}")
endif()

# ------------------------------------------------------------------ sources
set(SOURCES
  src/main.c
  src/util.c
  src/platform.c
  src/mqueue.c
  src/model.c
  src/xml.c
  src/scan.c
  src/db.c
  src/catalog.c
  src/server.c
  third_party/mongoose.c
  third_party/sqlite3.c)

add_executable(nmapstudio ${SOURCES})

target_include_directories(nmapstudio PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party
  ${CMAKE_BINARY_DIR})

if(EMBED_WEB)
  add_dependencies(nmapstudio genweb)
  target_compile_definitions(nmapstudio PRIVATE NS_HAVE_EMBEDDED_WEB=1)
endif()

# SQLite tuning: drop features we don't need, keep it lean & fast
target_compile_definitions(nmapstudio PRIVATE
  SQLITE_THREADSAFE=1
  SQLITE_OMIT_LOAD_EXTENSION
  SQLITE_DEFAULT_MEMSTATUS=0
  SQLITE_DQS=0)

# Mongoose: plain TCP (we only bind to localhost), no TLS dependency
target_compile_definitions(nmapstudio PRIVATE MG_ENABLE_TLS=0)

if(MSVC)
  target_compile_definitions(nmapstudio PRIVATE _CRT_SECURE_NO_WARNINGS _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

# ------------------------------------------------------------------ linking
if(WIN32)
  target_link_libraries(nmapstudio PRIVATE ws2_32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(nmapstudio PRIVATE Threads::Threads ${CMAKE_DL_LIBS} m)
endif()

# Slightly louder warnings for our own code only would be ideal; keep simple.
if(NOT MSVC)
  target_compile_options(nmapstudio PRIVATE -O2 -Wall -Wno-unused-parameter)
endif()

install(TARGETS nmapstudio RUNTIME DESTINATION bin)
