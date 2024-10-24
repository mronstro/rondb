/*
 * Copyright (C) 2024, 2024 Hopsworks AB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "ping_ctrl.hpp"
#include "json_parser.hpp"
#include "encoding.hpp"
#include "buffer_manager.hpp"
#include "api_key.hpp"
#include "config_structs.hpp"
#include "constants.hpp"

#include <cstring>
#include <drogon/HttpTypes.h>
#include <memory>
#include <simdjson.h>
#include <EventLogger.hpp>

extern EventLogger *g_eventLogger;

#if (defined(VM_TRACE) || defined(ERROR_INSERT))
//#define DEBUG_PING_CTRL 1
#endif

#ifdef DEBUG_PING_CTRL
#define DEB_PING_CTRL(...) do { g_eventLogger->info(__VA_ARGS__); } while (0)
#else
#define DEB_PING_CTRL(...) do { } while (0)
#endif

void PingCtrl::ping(const drogon::HttpRequestPtr &req,
                    std::function<void(
                      const drogon::HttpResponsePtr &)> &&callback) {
  auto resp = drogon::HttpResponse::newHttpResponse();

  // Store it to the first string buffer
  size_t length = req->getBody().length();
#ifdef DEBUG_PING_CTRL
  const char *json_str = req->getBody().data();
  DEB_PING_CTRL("\n\n JSON REQUEST: with len: %u\n %s \n",
                (Uint32)length, json_str);
#endif
  if (unlikely(length > 0)) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setBody("Ping Request should be empty");
    resp->setStatusCode(drogon::HttpStatusCode::k400BadRequest);
    callback(resp);
    return;
  }
  // Authenticate
  if (globalConfigs.security.apiKey.useHopsworksAPIKeys &&
      globalConfigs.rest.pingRequiresAPIKey) {
    auto api_key = req->getHeader(API_KEY_NAME_LOWER_CASE);
    auto status = authenticate_empty(api_key);
    if (unlikely(static_cast<drogon::HttpStatusCode>(status.http_code) !=
          drogon::HttpStatusCode::k200OK)) {
      resp->setBody(std::string(status.message));
      resp->setStatusCode((drogon::HttpStatusCode)status.http_code);
      callback(resp);
      return;
    }
  }
  resp->setStatusCode(drogon::HttpStatusCode::k200OK);
  callback(resp);
}
