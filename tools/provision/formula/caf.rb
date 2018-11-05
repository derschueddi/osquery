require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Caf < AbstractOsqueryFormula
  desc "Implementation of the Actor Model for C++"
  homepage "https://actor-framework.org/"
  url "https://github.com/actor-framework/actor-framework.git",
      :revision => "9cb3dde60e82aa68052aa2a093628a600cf6f89c"
  head "https://github.com/actor-framework/actor-framework.git"
  version "0.16.1"
  revision 0

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
    args = %W[--prefix=#{prefix} --no-examples --no-unit-tests --no-opencl --no-benchmarks --no-tools --no-python --build-static-only]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 9402137..d4268c4 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -335,9 +335,9 @@ if(CAF_IOS_DEPLOYMENT_TARGET)
   endif()
 endif()
 # check if the user provided CXXFLAGS, set defaults otherwise
-if(NOT CMAKE_CXX_FLAGS)
-  set(CMAKE_CXX_FLAGS                   "-std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
-endif()
+#if(NOT CMAKE_CXX_FLAGS)
+set(CMAKE_CXX_FLAGS                   "${CMAKE_CXX_FLAGS} -std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
+#endif()
 if (NOT "${CMAKE_CXX_FLAGS}" MATCHES "-std=")
   message(STATUS "Supplied CXXFLAGS do not contain a C++ standard, setting std to c++11")
   set(CMAKE_CXX_FLAGS                   "-std=c++11 ${CMAKE_CXX_FLAGS}")
