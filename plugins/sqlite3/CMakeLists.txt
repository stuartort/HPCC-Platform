################################################################################
#    HPCC SYSTEMS software Copyright (C) 2013 HPCC Systems®.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################

# Component: sqlite3embed

#####################################################
# Description:
# ------------
#    Cmake Input File for sqlite3embed
#####################################################

project(sqlite3embed)

if(SQLITE3EMBED)
    ADD_PLUGIN(sqlite3embed PACKAGES SQLITE3)
    if(MAKE_SQLITE3EMBED)
        set(
            SRCS
            sqlite3.cpp)

        include_directories(
            ./../../system/include
            ./../../rtl/eclrtl
            ./../../rtl/include
            ./../../rtl/nbcd
            ./../../common/deftype
            ./../../system/jlib
            ${SQLITE3_INCLUDE_DIR})

        add_definitions(-D_USRDLL -DSQLITE3_EXPORTS)

        HPCC_ADD_LIBRARY(sqlite3embed SHARED ${SRCS})
        if(${CMAKE_VERSION} VERSION_LESS "2.8.9")
            message(WARNING "Cannot set NO_SONAME. shlibdeps will give warnings when package is installed")
        elseif(NOT APPLE)
            set_target_properties(sqlite3embed PROPERTIES NO_SONAME 1)
        endif()

        install(
            TARGETS sqlite3embed
            DESTINATION plugins)
        target_link_libraries(
            sqlite3embed
            ${SQLITE3_LIBRARIES})
        target_link_libraries(
            sqlite3embed
            eclrtl
            jlib)
    endif()
endif()

if(PLATFORM OR CLIENTTOOLS_ONLY)
    install(
        FILES ${CMAKE_CURRENT_SOURCE_DIR}/sqlite3.ecllib
        DESTINATION plugins
        COMPONENT Runtime)
endif()
