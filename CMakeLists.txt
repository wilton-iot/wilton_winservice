
cmake_minimum_required ( VERSION 2.8.12 )

# project
project ( wilton_winservice CXX )

# dependencies
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/external_popt )
staticlib_add_subdirectory ( ${STATICLIB_DEPS}/staticlib_winservice )

set ( ${PROJECT_NAME}_DEPS
        staticlib_winservice
        staticlib_json
        staticlib_ranges
        staticlib_utils
        staticlib_tinydir
        popt )
        
staticlib_pkg_check_modules ( ${PROJECT_NAME}_DEPS_PC REQUIRED ${PROJECT_NAME}_DEPS )

# executable
configure_file ( ${CMAKE_CURRENT_LIST_DIR}/resources/${PROJECT_NAME}.rc
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.rc )

add_executable ( ${PROJECT_NAME}
        ${CMAKE_CURRENT_LIST_DIR}/src/winservice.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.rc )
        
target_include_directories ( ${PROJECT_NAME} BEFORE PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${WILTON_DIR}/core/include
        ${WILTON_DIR}/modules/wilton_http/include
        ${WILTON_DIR}/modules/wilton_signal/include
        ${${PROJECT_NAME}_DEPS_PC_INCLUDE_DIRS} )
        
target_link_libraries ( ${PROJECT_NAME} PRIVATE
        wilton_core
        wilton_http
        wilton_signal
        ${${PROJECT_NAME}_DEPS_PC_LIBRARIES}
        wtsapi32 )
        
set_property ( TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "/manifest:no" )
