require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Caf < AbstractOsqueryFormula
  desc "Implementation of the Actor Model for C++"
  homepage "https://actor-framework.org/"
  url "https://github.com/actor-framework/actor-framework.git",
        :revision => "9fb82f556760e1004e27fb4d303499b603a3fc19"
  sha256 "afc4bc928ecd7d017768e5c85b7300196aa5b70ef11d97e11b21a1ae28ce9d3f"
  head "https://github.com/actor-framework/actor-framework.git",
    :branch => "develop"
  version "0.14.5"

  needs :cxx11

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    prepend "CXXFLAGS", "-std=c++11 -stdlib=libstdc++ -static-libstdc++ -Wextra -Wall -pedantic"
    args = %W[--prefix=#{prefix} --no-auto-libc++ --no-examples --no-unit-tests --build-static-only]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end
