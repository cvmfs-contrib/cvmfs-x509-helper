set (VJSON_SOURCES
  block_allocator.cpp  block_allocator.h
  json.cpp  json.h
)

add_library(vjson STATIC ${VJSON_SOURCES})
