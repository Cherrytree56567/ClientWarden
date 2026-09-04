#pragma once

#if defined(ANDROID) || !defined(__cpp_lib_jthread)
  #include <nonstd/jthread.hpp>
  using nonstd::jthread;
  using nonstd::stop_token;
  using nonstd::stop_source;
#else
  #include <thread>
  #include <stop_token>
  using std::jthread;
  using std::stop_token;
  using std::stop_source;
#endif