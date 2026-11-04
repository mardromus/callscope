add_executable(mock_upstream mock_upstream.c)

if(TARGET callscope_trace)
  add_executable(orderservice
    orderservice/orderservice.c
    orderservice/net.c)
  # instrument the app (not the tracer) and export symbols for name lookup
  target_compile_options(orderservice PRIVATE -finstrument-functions -O1 -fno-inline
    -fno-optimize-sibling-calls)
  target_link_options(orderservice PRIVATE -rdynamic)
  target_link_libraries(orderservice PRIVATE callscope_trace)
endif()
