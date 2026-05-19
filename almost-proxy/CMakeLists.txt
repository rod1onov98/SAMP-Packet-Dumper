add_executable (almost-proxy
    "main.cpp"
    "samp_parser.cpp"
    "raknet/BitStream.cpp"
)
 
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET almost-proxy PROPERTY CXX_STANDARD 20)
endif()
 