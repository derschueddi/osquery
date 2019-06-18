/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <asm/unistd_64.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <boost/algorithm/string.hpp>

#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/core/conversions.h"
#include "osquery/events/linux/auditeventpublisher.h"
#include "osquery/tables/events/linux/ktls_events.h"

namespace osquery {

FLAG(bool,
     audit_allow_ktls,
     true,
     "Allow the audit publisher to install socket-related rules");

// Depend on the external getUptime table method.
namespace tables {
extern long getUptime();
}

REGISTER(KtlsEventSubscriber, "event_subscriber", "ktls_events");

Status KtlsEventSubscriber::init() {
  if (!FLAGS_audit_allow_ktls) {
    return Status(1, "Subscriber disabled via configuration");
  }

  auto sc = createSubscriptionContext();
  subscribe(&KtlsEventSubscriber::Callback, sc);

  return Status(0, "OK");
}

Status KtlsEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  std::vector<Row> emitted_row_list;
  auto status = ProcessEvents(emitted_row_list, ec->audit_events);
  if (!status.ok()) {
    return status;
  }

  addBatch(emitted_row_list);
  return Status(0, "Ok");
}

Status KtlsEventSubscriber::ProcessEvents(
    std::vector<Row>& emitted_row_list,
    const std::vector<AuditEvent>& event_list) noexcept {
  emitted_row_list.clear();
  emitted_row_list.reserve(event_list.size());

  // needed to resolve the pointer t a3 cipher record
  unsigned long a3_addr = 0;
  int8_t value = 0;
  uint64_t pid = 0;
  char file[64];
  int fd;

  for (const auto& event : event_list) {
    if (event.type != AuditEvent::Type::Syscall) {
      continue;
    }

    Row row = {};
    const auto& event_data = boost::get<SyscallAuditEventData>(event.data);
    char buff[100];
    KtlsCryptInfo cryptinfo;

    if (event_data.syscall_number == __NR_setsockopt) {
      row["action"] = "setsockopt";
    } else {
      continue;
    }

    const AuditEventRecord* syscall_event_record =
        GetEventRecord(event, AUDIT_SYSCALL);
    if (syscall_event_record == nullptr) {
      VLOG(1) << "Malformed syscall event. The AUDIT_SYSCALL record "
                 "is missing";
      continue;
    }

    /* Expecting 'SOL_TLS' as socket level value (hex-string)*/
    if (syscall_event_record->fields.at("a1") != "11a") {
      continue;
    }

    CopyFieldFromMap(row, syscall_event_record->fields, "auid");
    CopyFieldFromMap(row, syscall_event_record->fields, "pid");
    GetStringFieldFromMap(row["fd"], syscall_event_record->fields, "a0");

    row["path"] = DecodeAuditPathValues(syscall_event_record->fields.at("exe"));
    row["fd"] = syscall_event_record->fields.at("a0");
    row["success"] =
        (syscall_event_record->fields.at("success") == "yes") ? "1" : "0";
    row["uptime"] = std::to_string(tables::getUptime());

    if (syscall_event_record->fields.at("a2") == "1") {
      row["tls_sock_opt"] = "TLS_TX";
    } else if (syscall_event_record->fields.at("a2") == "2") {
      row["tls_sock_opt"] = "TLS_RX";
    } else {
      row["tls_sock_opt"] = "UNKNOWN";
    }

    /* get address pointer of cipher info data */
    a3_addr = std::stoul(syscall_event_record->fields.at("a3"), 0, 16);
    /* get the corresponding pid */
    GetIntegerFieldFromMap(pid, syscall_event_record->fields, "pid", 10, 0);
   
    /* use ptrace and try to read the cipher data from the pids memory */
    sprintf(file, "/proc/%ld/mem", pid);
    fd = open(file, O_RDWR);
    ptrace(PTRACE_ATTACH, pid, 0, 0);
    waitpid(pid, NULL, 0);
    for (unsigned int j = 0; j < 40; j++) {
      pread(fd, &value, sizeof(value), a3_addr+j);
      buff[j] = value & 0xFF;
    }
    ptrace(PTRACE_DETACH, pid, 0, 0);
    close(fd);
    memcpy(&(cryptinfo.version), &(buff[0]), 2);
    memcpy(&(cryptinfo.cipherType), &(buff[2]), 2);
    memcpy(&(cryptinfo.iv), &(buff[4]), 8);
    memcpy(&(cryptinfo.key), &(buff[12]), 16);
    memcpy(&(cryptinfo.salt), &(buff[28]), 4);
    memcpy(&(cryptinfo.rec_seq), &(buff[32]), 8);
    
    snprintf(buff, 100, "0x%04X", cryptinfo.version);
    row["tls_version"] = buff;
    snprintf(buff, 100, "0x%04X", cryptinfo.cipherType);
    row["tls_cipher_type"] = buff;
    snprintf(buff, 100, "0x%016lX", cryptinfo.iv);
    row["tls_iv"] = buff; 
    snprintf(buff, 100, "0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X"
        " 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X",
	cryptinfo.key[0] & 0xFF, cryptinfo.key[1] & 0xFF, cryptinfo.key[2] & 0xFF,
	cryptinfo.key[3] & 0xFF, cryptinfo.key[4] & 0xFF, cryptinfo.key[5] & 0xFF,
	cryptinfo.key[6] & 0xFF, cryptinfo.key[7] & 0xFF, cryptinfo.key[8] & 0xFF,
	cryptinfo.key[9] & 0xFF, cryptinfo.key[10] & 0xFF, cryptinfo.key[11] & 0xFF,
	cryptinfo.key[12] & 0xFF, cryptinfo.key[13] & 0xFF, cryptinfo.key[14] & 0xFF,
	cryptinfo.key[15] & 0xFF);
    row["tls_key"] = buff;
    snprintf(buff, 100, "0x%08X", cryptinfo.salt);
    row["tls_salt"] = buff;
    snprintf(buff, 100, "0x%016lX", cryptinfo.rec_seq);
    row["tls_rec_seq"] = buff;
    
    emitted_row_list.push_back(row);
  }

  return Status(0, "Ok");
}

const std::set<int>& KtlsEventSubscriber::GetSyscallSet() noexcept {
  static const std::set<int> syscall_set = {__NR_setsockopt};
  return syscall_set;
}
} // namespace osquery
