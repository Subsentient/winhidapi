cmake_minimum_required(VERSION 3.1.0)
project("WinHIDAPI")


if (DEBUG)
	add_compile_options(-std=gnu++14 -pedantic -Wall -DDEBUG -O0 -g3 -fcf-protection=full -fstack-protector-all -fstack-clash-protection)
	add_link_options(-fstack-check -fstack-clash-protection -fstack-protector-all)
else()
	add_compile_options(-std=gnu++14 -pedantic -Wall -Ofast)
endif()


set(sourcefiles winhidapi.cpp)

add_library(winhidapi SHARED ${sourcefiles})
set_target_properties(winhidapi PROPERTIES PREFIX "")
set_target_properties(winhidapi PROPERTIES OUTPUT_NAME "hidapi")
target_link_libraries(winhidapi hid setupapi)

