/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <iostream>

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

#include <osquery/distributed.h>
#include <osquery/status.h>
#include <osquery/system.h>

#include "osquery/remote/bro/query_manager.h"

namespace osquery {

/**
 * @brief Request types for query subscriptions
 */
enum BrokerRequestType { EXECUTE = 0, SUBSCRIBE = 1, UNSUBSCRIBE = 2 };

/**
 * @brief Names of the subscription request types
 */
const std::map<BrokerRequestType, std::string> kBrokerRequestTypeNames = {
    {EXECUTE, "EXECUTE"},
    {SUBSCRIBE, "SUBSCRIBE"},
    {UNSUBSCRIBE, "UNSUBSCRIBE"},

};

/**
 * @brief Parse an incoming broker message as subscription request.
 *
 * Incoming broker messages can contain SQL queries to be executed by osquery
 * hosts. There are two kind of queries: Ad-hoc (one-time) or Schedule
 * (repeating). Requests for both kinds can be described as SubscriptionRequest.
 *
 * @param rType the request type (EXECUTE, SUBSCRIBE or UNSUBSCRIBE)
 * @param event the incoming broker message that is parsed
 * @param incoming_topic the broker topic where the message was received on
 * @param sr the SubscriptionRequest to be filled
 * @return
 */
Status createSubscriptionRequest(const BrokerRequestType& rType,
                                 const broker::bro::Event& event,
                                 const std::string& incoming_topic,
                                 SubscriptionRequest& sr);

/**
 * @brief Parse the broker groups from the json configuration
 *
 * Initial groups can be written to the configuration to indicate which groups
 * (i.e. broker topics) the osquery host should join
 *
 * @param json_groups the part of the json configuration that holds the groups
 * @param groups the parsed groups
 * @return
 */
Status parseBrokerGroups(const std::string& json_groups,
                         std::vector<std::string>& groups);

/**
 * @brief Serialize a vector of DistributedQueryRequest objects into a JSON string
 *
 * @param rs the vector of DistributedQueryRequests to serialize
 * @param json the output JSON string
 *
 * @return Status indicating the success or failure of the operation
 */
Status serializeDistributedQueryRequestsJSON(const std::vector<DistributedQueryRequest>& rs,
                                            std::string& json);
/**
 * @brief Parses a serialized DistributedQueryResult
 *
 * @param json the serialized json string of the DistributedQueryResult
 * @param rs the output vector with QueryData and StatusCode per requestID
 * @return Status indicating the success or failure of the operation
 */
Status parseDistributedQueryResultsJSON(const std::string& json,
                                 std::vector<std::pair<std::string, std::pair<QueryData,int>>>& rs);
} // namespace osquery
