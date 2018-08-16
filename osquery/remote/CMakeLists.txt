#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

SET(OSQUERY_REMOTE
  enroll/enroll.cpp
  serializers/json.cpp
  transports/tls.cpp
  http/http_client.cpp
  remote.cpp
  uri.cpp
)

if(NOT SKIP_BRO)
  LIST(APPEND OSQUERY_REMOTE "bro/broker_manager.cpp")
  LIST(APPEND OSQUERY_REMOTE "bro/query_manager.cpp")
  LIST(APPEND OSQUERY_REMOTE "bro/bro_utils.cpp")
endif()

ADD_OSQUERY_LIBRARY(FALSE osquery_remote ${OSQUERY_REMOTE})

ADD_OSQUERY_LIBRARY(FALSE osquery_enrollment_plugins
  enroll/plugins/tls_enroll.cpp
)

file(GLOB OSQUERY_ENROLLMENT_PLUGIN_TESTS "enroll/plugins/tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_ENROLLMENT_PLUGIN_TESTS})

file(GLOB OSQUERY_REMOTE_TESTS "tests/*.cpp")
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_TESTS})

file(GLOB OSQUERY_REMOTE_COMPONENT_TESTS "*/tests/*.cpp")
if(SKIP_BRO)
  file(GLOB BRO_REMOTE_COMPONENT_TESTS "enroll/plugins/tests/bro/*.cpp")
  foreach(bro_remote_component_test IN ${BRO_REMOTE_COMPONENT_TESTS})
    LIST(REMOVE_ITEM OSQUERY_REMOTE_COMPONENT_TESTS bro_remote_component_test)
  endforeach(bro_remote_component_test)
endif()
ADD_OSQUERY_TEST(FALSE ${OSQUERY_REMOTE_COMPONENT_TESTS})
