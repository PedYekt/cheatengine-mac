set(TEST_SOURCES
    unit_tests.cpp
)

set(INTEGRATION_TEST_SOURCES
    integration_tests.cpp
)

add_executable(cheatengine_tests ${TEST_SOURCES})
add_executable(cheatengine_integration_tests ${INTEGRATION_TEST_SOURCES})

target_link_libraries(cheatengine_tests PRIVATE cheatengine_core)
target_link_libraries(cheatengine_integration_tests PRIVATE cheatengine_core)

add_test(NAME cheatengine_unit_tests COMMAND cheatengine_tests)
add_test(NAME cheatengine_integration_tests COMMAND cheatengine_integration_tests)
