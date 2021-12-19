project (optee_tracer)

set (SRC host/main.c host/tracer_interface.c host/backtrace.c host/server.cpp)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} 
	PRIVATE teec
	PRIVATE pthread
	PRIVATE unwind-ptrace
	PRIVATE unwind-ptrace
	PRIVATE unwind-generic
	PRIVATE boost_system
	PRIVATE crypto
	PRIVATE ssl
	PRIVATE cpprest
)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
