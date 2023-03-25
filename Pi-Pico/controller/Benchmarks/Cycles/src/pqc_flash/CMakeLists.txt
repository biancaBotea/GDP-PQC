if(NOT TARGET pqc_flash_headers)
    add_library(pqc_flash_headers INTERFACE)
    target_include_directories(pqc_flash_headers INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
    target_link_libraries(pqc_flash_headers INTERFACE 
        pico_stdlib 
        hardware_flash)
endif()

if(NOT TARGET pqc_flash)
    add_library(pqc_flash INTERFACE)
    target_compile_definitions(pqc_flash INTERFACE LIB_PQC_FLASH=1)
    target_sources(pqc_flash INTERFACE ${CMAKE_CURRENT_LIST_DIR}/flash.c)
    target_link_libraries(pqc_flash INTERFACE pqc_flash_headers)
endif()