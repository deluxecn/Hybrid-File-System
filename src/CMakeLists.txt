cmake_minimum_required(VERSION 3.6)
project(src)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    cloud-lib/cloud-example.c
    cloud-lib/cloudapi.c
    cloud-lib/cloudapi.h
    cloudfs/cloudfs.c
    cloudfs/cloudfs.h
    cloudfs/main.c
    dedup-lib/dedup.h
    dedup-lib/msb.c
    dedup-lib/msb.h
    dedup-lib/rabin-example.c
    dedup-lib/rabinpoly.c
    dedup-lib/rabinpoly.h
    include/dedup.h
    include/libs3.h
    s3-client/include/libs3.h
    s3-client/src/s3.c
    snapshot/snapshot-api.h
    snapshot/snapshot-test.c)

add_executable(src ${SOURCE_FILES})