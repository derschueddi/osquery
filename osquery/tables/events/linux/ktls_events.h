/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/auditeventpublisher.h"

namespace osquery {

// Used to read the crypt info record
struct KtlsCryptInfo final {
  uint16_t version;
  uint16_t cipherType;
  uint64_t iv;
  uint8_t key[16];
  uint32_t salt;
  uint64_t rec_seq;
};

class KtlsEventSubscriber final
    : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

  /// Processes the updates received from the callback
  static Status ProcessEvents(
      std::vector<Row>& emitted_row_list,
      const std::vector<AuditEvent>& event_list) noexcept;

  /// Returns the set of syscalls that this subscriber can handle
  static const std::set<int>& GetSyscallSet() noexcept;
};

} // namespace osquery
