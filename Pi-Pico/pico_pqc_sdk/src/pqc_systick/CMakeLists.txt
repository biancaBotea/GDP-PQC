if(NOT TARGET pqc_systick_headers)
    add_library(pqc_systick_headers INTERFACE)
    target_include_directories(pqc_systick_headers INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
    target_link_libraries(pqc_systick_headers INTERFACE 
        pico_stdlib 
        hardware_base 
        hardware_structs 
        hardware_exception)
endif()

if(NOT TARGET pqc_systick)
    add_library(pqc_systick INTERFACE)
    target_compile_definitions(pqc_systick INTERFACE LIB_PQC_SYSTICK=1)
    target_sources(pqc_systick INTERFACE ${CMAKE_CURRENT_LIST_DIR}/systick.c)
    target_link_libraries(pqc_systick INTERFACE pqc_systick_headers)
endif()