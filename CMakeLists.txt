CMAKE_MINIMUM_REQUIRED (VERSION 3.6)

PROJECT (php-trace)

SET(CMAKE_INSTALL_PREFIX              /usr     CACHE PATH               "default install location"   FORCE)
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE     CACHE BOOL               "use rpath while installing" FORCE)
SET(PKG_CONFIG_PATH                   /usr     CACHE PATH               "default pkg-config path" )

FIND_PROGRAM(PHP_CONFIG "php-config" DOC "php-config as shipped with php")

EXECUTE_PROCESS(COMMAND ${PHP_CONFIG} --prefix             OUTPUT_VARIABLE PHP_PREFIX     OUTPUT_STRIP_TRAILING_WHITESPACE)
EXECUTE_PROCESS(COMMAND ${PHP_CONFIG} --includes           OUTPUT_VARIABLE PHP_INCLUDES   OUTPUT_STRIP_TRAILING_WHITESPACE)
EXECUTE_PROCESS(COMMAND ${PHP_CONFIG} --libs               OUTPUT_VARIABLE PHP_LIBS       OUTPUT_STRIP_TRAILING_WHITESPACE)
EXECUTE_PROCESS(COMMAND ${PHP_CONFIG} --configure-options  OUTPUT_VARIABLE PHP_CONFIGURE  OUTPUT_STRIP_TRAILING_WHITESPACE)
EXECUTE_PROCESS(COMMAND ${PHP_CONFIG} --version            OUTPUT_VARIABLE PHP_VERSION    OUTPUT_STRIP_TRAILING_WHITESPACE)

FIND_LIBRARY(PHP_TRACE_LIBPHP "php7" PATHS ${PHP_PREFIX} PATH_SUFFIXES lib lib64 NO_DEFAULT_PATH DOC "path to libphp7")
FIND_LIBRARY(PHP_TRACE_LIBELF "elf"                                                DOC "path to libelf")
FIND_LIBRARY(PHP_TRACE_LIBDW  "dw"                                                 DOC "path to libdw")

if(${PHP_TRACE_LIBPHP} MATCHES PHP_TRACE_LIBPHP_NOTFOUND OR NOT EXISTS ${PHP_TRACE_LIBPHP}) 
    MESSAGE(FATAL_ERROR "libphp7 not found")
else()
    MESSAGE(STATUS "Found libphp7: ${PHP_TRACE_LIBPHP}")
endif()

if(${PHP_TRACE_LIBELF} MATCHES PHP_TRACE_LIBELF_NOTFOUND OR NOT EXISTS ${PHP_TRACE_LIBELF})
    MESSAGE(FATAL_ERROR "libelf not found")
else()
    MESSAGE(STATUS "Found libelf: ${PHP_TRACE_LIBELF}")
endif()

if(${PHP_TRACE_LIBDW} MATCHES PHP_TRACE_LIBDW_NOTFOUND OR NOT EXISTS ${PHP_TRACE_LIBDW})
    MESSAGE(FATAL_ERROR "libdw not found")
else()
    MESSAGE(STATUS "Found libdw: ${PHP_TRACE_LIBDW}")
endif()

if (${PHP_CONFIGURE} MATCHES "enable-debug")
    SET(CMAKE_BUILD_TYPE Debug CACHE STRING "PHP build type" FORCE)
else()
    SET(CMAKE_BUILD_TYPE Release CACHE STRING "PHP build type" FORCE)  
endif()

ADD_LIBRARY(phptrace SHARED php_trace_loop.c php_trace_api.c php_trace_zval.c php_trace_dwfl.c php_trace_print.c)
ADD_EXECUTABLE (php-trace php_trace_main.c)
ADD_DEPENDENCIES(php-trace phptrace)

INCLUDE_DIRECTORIES(.)

TARGET_LINK_LIBRARIES(phptrace ${PHP_TRACE_LIBPHP} ${PHP_TRACE_LIBELF} ${PHP_TRACE_LIBDW} -ldl ${PHP_LIBS})
TARGET_LINK_LIBRARIES(php-trace phptrace)

INSTALL (TARGETS php-trace
        DESTINATION bin)
INSTALL (TARGETS phptrace
        DESTINATION lib)     
INSTALL (FILES ${PROJECT_SOURCE_DIR}/php_trace.h
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
INSTALL (FILES ${PROJECT_BINARY_DIR}/libphptrace.pc
        DESTINATION ${PKG_CONFIG_PATH}/share/pkgconfig)     

SET_TARGET_PROPERTIES(php-trace PROPERTIES 
    C_STANDARD 99
    COMPILE_FLAGS "-D_GNU_SOURCE -Wall -Werror ${PHP_INCLUDES}"
)

SET_TARGET_PROPERTIES(phptrace PROPERTIES 
    C_STANDARD 99
    COMPILE_FLAGS "-D_GNU_SOURCE -Wall -Werror ${PHP_INCLUDES}"
)

CONFIGURE_FILE("libphptrace.pc.in" "libphptrace.pc" @ONLY)
