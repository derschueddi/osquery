require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Caf < AbstractOsqueryFormula
  desc "Implementation of the Actor Model for C++"
  homepage "https://actor-framework.org/"
  url "https://github.com/actor-framework/actor-framework.git",
      :revision => "882ba63d1775d8f8a5c1c514decd610134988d8c"
  head "https://github.com/actor-framework/actor-framework.git"
  version "0.15.7"
  revision 1

  needs :cxx11

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end

  depends_on "openssl"
  depends_on "cmake" => :build

  # Use both provided and default CXX flags
  patch :DATA

  def install
    args = %W[--prefix=#{prefix} --no-examples --no-qt-examples --no-protobuf-examples --no-curl-examples --no-unit-tests --no-opencl --no-benchmarks --no-python --build-static-only]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/CMakeLists.txt b/CMakeLists.txt
index b56c979..7aaf516 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -342,9 +342,9 @@ if(CAF_IOS_DEPLOYMENT_TARGET)
   endif()
 endif()
 # check if the user provided CXXFLAGS, set defaults otherwise
-if(NOT CMAKE_CXX_FLAGS)
-  set(CMAKE_CXX_FLAGS                   "-std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
-endif()
+#if(NOT CMAKE_CXX_FLAGS)
+set(CMAKE_CXX_FLAGS                   "${CMAKE_CXX_FLAGS} -std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
+#endif()
 if(NOT CMAKE_CXX_FLAGS_DEBUG)
   set(CMAKE_CXX_FLAGS_DEBUG             "-O0 -g")
 endif()
diff --git a/libcaf_core/caf/intrusive_ptr.hpp b/libcaf_core/caf/intrusive_ptr.hpp
index 25d8a01..580dca3 100644
--- a/libcaf_core/caf/intrusive_ptr.hpp
+++ b/libcaf_core/caf/intrusive_ptr.hpp
@@ -247,7 +247,7 @@ std::string to_string(const intrusive_ptr<T>& x) {
   // we convert to hex representation, i.e.,
   // one byte takes two characters + null terminator + "0x" prefix
   char buf[sizeof(v) * 2 + 3];
-  sprintf(buf, "%" PRIxPTR, v);
+  sprintf(buf, "%lu", v);
   return buf;
 }
