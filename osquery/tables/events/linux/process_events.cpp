/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/events/linux/audit.h"

namespace osquery {

#define AUDIT_SYSCALL_CLONE 56
#define AUDIT_SYSCALL_FORK 57
#define AUDIT_SYSCALL_VFORK 58
#define AUDIT_SYSCALL_EXECVE 59

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

bool ProcessUpdate_CLONE(size_t type, const AuditFields& fields, AuditFields& r) {
  if (type == AUDIT_SYSCALL) {
    r["action"] = "clone";
    r["auid"] = (fields.count("auid")) ? fields.at("auid") : "0";
    r["pid"] = (fields.count("exit")) ? fields.at("exit") : "0";
    r["parent"] = fields.count("pid") ? fields.at("pid") : "0";
    r["uid"] = fields.count("uid") ? fields.at("uid") : "0";
    r["euid"] = fields.count("euid") ? fields.at("euid") : "0";
    r["gid"] = fields.count("gid") ? fields.at("gid") : "0";
    r["egid"] = fields.count("egid") ? fields.at("euid") : "0";
    r["path"] = (fields.count("exe")) ? decodeAuditValue(fields.at("exe")) : "";

    auto qd = SQL::selectAllFrom("file", "path", EQUALS, r.at("path"));
    if (qd.size() == 1) {
      r["ctime"] = qd.front().at("ctime");
      r["atime"] = qd.front().at("atime");
      r["mtime"] = qd.front().at("mtime");
      r["btime"] = "0";
    }

    // This should get overwritten during the EXECVE state.
    r["cmdline"] = (fields.count("comm")) ? fields.at("comm") : "";
    // Do not record a cmdline size. If the final state is reached and no
    // 'argc'
    // has been filled in then the EXECVE state was not used.
    r["cmdline_size"] = "";

    r["overflows"] = "";
    r["env_size"] = "0";
    r["env_count"] = "0";
    r["env"] = "";
  }

  return true;
}

bool ProcessUpdate_FORK(size_t type, const AuditFields& fields, AuditFields& r) {
  if (type == AUDIT_SYSCALL) {
    r["action"] = "fork";
    r["auid"] = (fields.count("auid")) ? fields.at("auid") : "0";
    r["pid"] = (fields.count("exit")) ? fields.at("exit") : "0";
    r["parent"] = fields.count("pid") ? fields.at("pid") : "0";
    r["uid"] = fields.count("uid") ? fields.at("uid") : "0";
    r["euid"] = fields.count("euid") ? fields.at("euid") : "0";
    r["gid"] = fields.count("gid") ? fields.at("gid") : "0";
    r["egid"] = fields.count("egid") ? fields.at("euid") : "0";
    r["path"] = (fields.count("exe")) ? decodeAuditValue(fields.at("exe")) : "";

    auto qd = SQL::selectAllFrom("file", "path", EQUALS, r.at("path"));
    if (qd.size() == 1) {
      r["ctime"] = qd.front().at("ctime");
      r["atime"] = qd.front().at("atime");
      r["mtime"] = qd.front().at("mtime");
      r["btime"] = "0";
    }

    // This should get overwritten during the EXECVE state.
    r["cmdline"] = (fields.count("comm")) ? fields.at("comm") : "";
    // Do not record a cmdline size. If the final state is reached and no
    // 'argc'
    // has been filled in then the EXECVE state was not used.
    r["cmdline_size"] = "";

    r["overflows"] = "";
    r["env_size"] = "0";
    r["env_count"] = "0";
    r["env"] = "";
  } else {
    VLOG(1) << "Unknown syscall record for fork: " << type;
  }

  return true;
}

bool ProcessUpdate_VFORK(size_t type, const AuditFields& fields, AuditFields& r) {
  if (type == AUDIT_SYSCALL) {
    r["action"] = "vfork";
    r["auid"] = (fields.count("auid")) ? fields.at("auid") : "0";
    r["pid"] = (fields.count("exit")) ? fields.at("exit") : "0";
    r["parent"] = fields.count("pid") ? fields.at("pid") : "0";
    r["uid"] = fields.count("uid") ? fields.at("uid") : "0";
    r["euid"] = fields.count("euid") ? fields.at("euid") : "0";
    r["gid"] = fields.count("gid") ? fields.at("gid") : "0";
    r["egid"] = fields.count("egid") ? fields.at("euid") : "0";
    r["path"] = (fields.count("exe")) ? decodeAuditValue(fields.at("exe")) : "";

    auto qd = SQL::selectAllFrom("file", "path", EQUALS, r.at("path"));
    if (qd.size() == 1) {
      r["ctime"] = qd.front().at("ctime");
      r["atime"] = qd.front().at("atime");
      r["mtime"] = qd.front().at("mtime");
      r["btime"] = "0";
    }

    // This should get overwritten during the EXECVE state.
    r["cmdline"] = (fields.count("comm")) ? fields.at("comm") : "";
    // Do not record a cmdline size. If the final state is reached and no
    // 'argc'
    // has been filled in then the EXECVE state was not used.
    r["cmdline_size"] = "";

    r["overflows"] = "";
    r["env_size"] = "0";
    r["env_count"] = "0";
    r["env"] = "";
  } else {
    VLOG(1) << "Unknown syscall record for vfork: " << type;
  }

  return true;
}

bool ProcessUpdate_EXECVE(size_t type, const AuditFields& fields, AuditFields& r) {
  if (type == AUDIT_SYSCALL) {
    r["action"] = "execve";
    r["auid"] = (fields.count("auid")) ? fields.at("auid") : "0";
    r["pid"] = (fields.count("pid")) ? fields.at("pid") : "0";
    r["parent"] = fields.count("ppid") ? fields.at("ppid") : "0";
    r["uid"] = fields.count("uid") ? fields.at("uid") : "0";
    r["euid"] = fields.count("euid") ? fields.at("euid") : "0";
    r["gid"] = fields.count("gid") ? fields.at("gid") : "0";
    r["egid"] = fields.count("egid") ? fields.at("euid") : "0";
    r["path"] = (fields.count("exe")) ? decodeAuditValue(fields.at("exe")) : "";

    auto qd = SQL::selectAllFrom("file", "path", EQUALS, r.at("path"));
    if (qd.size() == 1) {
      r["ctime"] = qd.front().at("ctime");
      r["atime"] = qd.front().at("atime");
      r["mtime"] = qd.front().at("mtime");
      r["btime"] = "0";
    }

    // This should get overwritten during the EXECVE state.
    r["cmdline"] = (fields.count("comm")) ? fields.at("comm") : "";
    // Do not record a cmdline size. If the final state is reached and no
    // 'argc'
    // has been filled in then the EXECVE state was not used.
    r["cmdline_size"] = "";

    r["overflows"] = "";
    r["env_size"] = "0";
    r["env_count"] = "0";
    r["env"] = "";
  }

  if (type == AUDIT_EXECVE) {
    // Reset the temporary storage from the SYSCALL state.
    r["cmdline"] = "";
    for (const auto& arg : fields) {
      if (arg.first == "argc") {
        continue;
      }

      // Amalgamate all the "arg*" fields.
      if (r.at("cmdline").size() > 0) {
        r["cmdline"] += " ";
      }
      r["cmdline"] += decodeAuditValue(arg.second);
    }

    // There may be a better way to calculate actual size from audit.
    // Then an overflow could be calculated/determined based on
    // actual/expected.
    r["cmdline_size"] = std::to_string(r.at("cmdline").size());

    // Uptime is helpful for execution-based events.
    r["uptime"] = std::to_string(tables::getUptime());
  }

  if (type == AUDIT_PATH) {
    r["mode"] = (fields.count("mode")) ? fields.at("mode") : "";
    r["owner_uid"] = fields.count("ouid") ? fields.at("ouid") : "0";
    r["owner_gid"] = fields.count("ogid") ? fields.at("ogid") : "0";
  }

  if (type == AUDIT_CWD) {
    r["cwd"] = fields.count("cwd") ? decodeAuditValue(fields.at("cwd")) : "";
  }
  return true;
}

class ProcessEventSubscriber : public EventSubscriber<AuditEventPublisher> {
 public:
  /// The process event subscriber declares an audit event type subscription.
  Status init() override;

  /// Kernel events matching the event type will fire.
  Status Callback(const ECRef& ec, const SCRef& sc);

 private:
  AuditAssembler asm_clone_;
  AuditAssembler asm_fork_;
  AuditAssembler asm_vfork_;
  AuditAssembler asm_execve_;
};

REGISTER(ProcessEventSubscriber, "event_subscriber", "process_events");

Status ProcessEventSubscriber::init() {
  asm_clone_.start(
          20, {AUDIT_SYSCALL}, &ProcessUpdate_CLONE);

  asm_fork_.start(
          20, {AUDIT_SYSCALL}, &ProcessUpdate_FORK);

  asm_vfork_.start(
          20, {AUDIT_SYSCALL}, &ProcessUpdate_VFORK);

  asm_execve_.start(
          20, {AUDIT_SYSCALL, AUDIT_EXECVE, AUDIT_PATH, AUDIT_CWD}, &ProcessUpdate_EXECVE);

  auto sc = createSubscriptionContext();
  // Monitor for syscalls.
  sc->rules.push_back({AUDIT_SYSCALL_CLONE, ""});
  sc->rules.push_back({AUDIT_SYSCALL_FORK, ""});
  sc->rules.push_back({AUDIT_SYSCALL_VFORK, ""});
  sc->rules.push_back({AUDIT_SYSCALL_EXECVE, ""});


  // Request call backs for all parts of the process execution state.
  // Drop events if they are encountered outside of the expected state.
  sc->types = {AUDIT_SYSCALL, AUDIT_EXECVE, AUDIT_CWD, AUDIT_PATH};
  subscribe(&ProcessEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status ProcessEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  // Check and set the valid state change.
  // If this is an unacceptable change reset the state and clear row data.
  if (ec->fields.count("success") && ec->fields.at("success") == "no") {
    return Status(0, "OK");
  }

  if (ec->type == AUDIT_PATH && ec->fields.count("item") &&
      ec->fields.at("item") != "0") {
    return Status(0, "OK");
  }

  boost::optional<AuditFields> fields;
  if (ec->syscall == AUDIT_SYSCALL_CLONE || asm_clone_.exists(ec->audit_id)) {
    fields = asm_clone_.add(ec->audit_id, ec->type, ec->fields);
  } else if (ec->syscall == AUDIT_SYSCALL_FORK || asm_fork_.exists(ec->audit_id)) {
    fields = asm_fork_.add(ec->audit_id, ec->type, ec->fields);
  } else if (ec->syscall == AUDIT_SYSCALL_VFORK || asm_vfork_.exists(ec->audit_id)) {
    fields = asm_vfork_.add(ec->audit_id, ec->type, ec->fields);
  } else if (ec->syscall == AUDIT_SYSCALL_EXECVE || asm_execve_.exists(ec->audit_id)) {
    fields = asm_execve_.add(ec->audit_id, ec->type, ec->fields);
  } else{
    return Status(1, "Not a process related syscall");
  }

  if (fields.is_initialized()) {
    add(*fields);
  }

  return Status(0, "OK");
}
}
