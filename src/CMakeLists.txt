find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)
if (GLIB_PKG_FOUND)
  include_directories(${GLIB_PKG_INCLUDE_DIRS})
endif()
add_executable(IdentifyIP sniff.c lookup.c monitor.c queue.c)
target_link_libraries(IdentifyIP pthread pcap pthread maxminddb ${GLIB_PKG_LIBRARIES})
