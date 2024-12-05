cmake_minimum_required(VERSION 3.27)
project(dnser C)

set(CMAKE_C_STANDARD 11)


add_executable(dnser main.c)
add_library(logic STATIC logic/cmd.c logic/db.c)
target_link_libraries(logic pq)
target_include_directories(logic PRIVATE /usr/include/postgresql)

if(EXISTS "/.dockerenv")
    target_compile_definitions(logic PRIVATE PATH_TO_DB="db")
else ()
    target_compile_definitions(logic PRIVATE PATH_TO_DB="localhost")
endif ()

target_link_libraries(dnser logic)
