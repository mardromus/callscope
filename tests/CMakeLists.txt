file(GLOB CS_TEST_SRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_executable(callscope_tests ${CS_TEST_SRC})
target_link_libraries(callscope_tests PRIVATE callscope)
target_compile_options(callscope_tests PRIVATE ${CS_WARNINGS})
target_compile_definitions(callscope_tests PRIVATE
  CS_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")

add_test(NAME unit COMMAND callscope_tests)

if(TARGET callscope_cli)
  add_test(NAME e2e COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e.sh $<TARGET_FILE:callscope_cli>)
endif()
