cmake_minimum_required(VERSION 3.19)
project(PcapAnalyze)

set(CMAKE_CXX_STANDARD 14)

add_executable(PcapAnalyze main.cpp PcapHeader.cpp PacketHeader.cpp PacketHeader.h MacHeader.cpp MacHeader.h IPv4Header.cpp IPv4Header.h TCPHeader.cpp TCPHeader.h IPv6Header.cpp IPv6Header.h ArpHeader.cpp ArpHeader.h ICMPHeader.cpp ICMPHeader.h Utilities.cpp Utilities.h UDPHeader.cpp UDPHeader.h Data.cpp Data.h)