# crypto/CMakeLists.txt
set(ROOT src)
set(LIBNAME personal)

message(STATUS "[${ROOT}/${LIBNAME}] Module Processing...")

# Find OpenSSL for production-grade cryptography
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "[${ROOT}/${LIBNAME}] OpenSSL found: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "[${ROOT}/${LIBNAME}] OpenSSL not found. Please install OpenSSL.")
endif()

# Collect files without having to explicitly list each header and source file
file(GLOB LIB_HEADERS
  "${CMAKE_CURRENT_SOURCE_DIR}/header/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/header/*.hpp")

file(GLOB LIB_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")

# Create named folders for the sources within the project
source_group("header" FILES ${LIB_HEADERS})
source_group("src" FILES ${LIB_SOURCES})

# Set Properties->General->Configuration Type to Dynamic Library (.dll/.so/.dylib)
add_library(${LIBNAME} STATIC ${LIB_HEADERS} ${LIB_SOURCES}) # for dynamic library use SHARED

target_include_directories(${LIBNAME} PUBLIC
						   ${CMAKE_CURRENT_SOURCE_DIR}/../utility/header
						   ${CMAKE_CURRENT_SOURCE_DIR}/header
						   ${OPENSSL_INCLUDE_DIR})

# Windows MSVC runtime library settings
if(MSVC)
    set_target_properties(${LIBNAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()

# Add any dependencies or compile options specific to crypto
if(SQLite3_FOUND)
    target_link_libraries(${LIBNAME} PRIVATE utility SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(${LIBNAME} PRIVATE USE_SYSTEM_SQLITE3)
elseif(USE_SQLITE3_AMALGAMATION)
    target_link_libraries(${LIBNAME} PRIVATE utility sqlite3 OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(${LIBNAME} PRIVATE ${CMAKE_SOURCE_DIR}/src/sqlite3)
else()
    target_link_libraries(${LIBNAME} PRIVATE utility OpenSSL::SSL OpenSSL::Crypto)
endif()

# creates preprocessor definition used for library exports
add_compile_definitions("CORUH_personal_LIB_EXPORTS")

install(TARGETS ${LIBNAME}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin )
		
# Copy required header to the installation include folder		
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/header/personal.h
        DESTINATION include)

# Export the crypto target so other modules can use it
# export(TARGETS ${LIBNAME} FILE ${LIBNAME}Targets.cmake)

message(STATUS "[${ROOT}/${LIBNAME}] Added library target: ${LIBNAME}")
