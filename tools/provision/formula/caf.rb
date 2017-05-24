require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Caf < AbstractOsqueryFormula
  desc "Implementation of the Actor Model for C++"
  homepage "https://actor-framework.org/"
  url "https://github.com/actor-framework/actor-framework.git",
        :revision => "09d32c7267acd7552b722d918107863592e91d53"
  sha256 "afc4bc928ecd7d017768e5c85b7300196aa5b70ef11d97e11b21a1ae28ce9d3f"
  #head "https://github.com/actor-framework/actor-framework.git",
  #  :branch => "develop"
  version "0.14.5"

  needs :cxx11

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end

  depends_on "cmake" => :build

  # Use both provided and default CXX flags
  patch :DATA

  def install
    args = %W[--prefix=#{prefix} --no-examples --no-unit-tests --no-opencl --no-nexus --no-cash --no-benchmarks --no-riac --build-static-only]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 9a20c5e..6ee9cb2 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -216,18 +216,18 @@ if(CAF_IOS_DEPLOYMENT_TARGET)
   endif()
 endif()
 # check if the user provided CXXFLAGS, set defaults otherwise
-if(CMAKE_CXX_FLAGS)
-  set(CMAKE_CXX_FLAGS_DEBUG          "")
-  set(CMAKE_CXX_FLAGS_MINSIZEREL     "")
-  set(CMAKE_CXX_FLAGS_RELEASE        "")
-  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
-else()
-  set(CMAKE_CXX_FLAGS "-std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
-  set(CMAKE_CXX_FLAGS_DEBUG          "-O0 -g")
-  set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os")
-  set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -DNDEBUG")
-  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
-endif()
+#if(CMAKE_CXX_FLAGS)
+#  set(CMAKE_CXX_FLAGS_DEBUG          "")
+#  set(CMAKE_CXX_FLAGS_MINSIZEREL     "")
+#  set(CMAKE_CXX_FLAGS_RELEASE        "")
+#  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
+#else()
+set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
+set(CMAKE_CXX_FLAGS_DEBUG          "-O0 -g")
+set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os")
+set(CMAKE_CXX_FLAGS_RELEASE        "-O3 -DNDEBUG")
+set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
+#endif()
 # set build default build type to RelWithDebInfo if not set
 if(NOT CMAKE_BUILD_TYPE)
   set(CMAKE_BUILD_TYPE RelWithDebInfo)
--
2.7.4
diff --git a/libcaf_core/caf/actor.hpp b/libcaf_core/caf/actor.hpp
index 0561434..8397d7f 100644
--- a/libcaf_core/caf/actor.hpp
+++ b/libcaf_core/caf/actor.hpp
@@ -170,6 +170,8 @@ private:
 
   actor(abstract_actor*);
 
+public:
+
   abstract_actor_ptr ptr_;
 };
 
-- 
2.7.4
