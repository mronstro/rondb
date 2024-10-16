/*
 * Copyright (c) 2024, 2024, Hopsworks and/or its affiliates.
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

/*
 * These class definitions for configuration are wrapped in macros so they can
 * be used for several things:
 * 1) Define the class
 * 2) Define the default constructor
 * 3) Define a function for validating an instance
 * 4) Define a JSON parser for the class
 * 5) Define a JSON printer for the class
 *
 * Macros used:
 * CLASS(Name, Contents) for class definition
 * CM(Datatype, Variablename, JSONKeyname, init expression) for data member
 *     included in parsing and printing
 * PROBLEM(condition, message) for validation
 * CLASSDEFS(Contents) for all other class definition content
 * VECTOR(Datatype) to indicate that a vector of this datatype will be used
 *
 * These macros should be defined before and undefined after including this file.
 *
 * In order to be able to define all classes without having to first declare
 * them, the class definitions are in depth-first, deepest-first order.
 * I.e., something like:
 *   define_class_including_dependencies(class) {
 *     for ( element : variables_in(class) ) {
 *       if ( not_declared(datatype(element)) ) {
 *         define_class_including_dependencies(datatype(element));
 *       }
 *     }
 *     define_one_class(class);
 *   }
 *   define_class_including_dependencies(AllConfigs);
 */
#include <ndb_types.h>

CLASS
(
 Internal,
 CM(Uint32, reqBufferSize,       ReqBufferSize,       1024 * 1024)
 CM(Uint32, respBufferSize,      RespBufferSize,      5 * 1024 * 1024)
 CM(Uint32, preAllocatedBuffers, PreAllocatedBuffers, 32)
 CM(Uint32, batchMaxSize,        BatchMaxSize,        256)
 CM(Uint32, operationIdMaxSize,  OperationIDMaxSize,  256)
 //todo warn (preallocatedbuffers == 0, "preAllocatedBuffers should be > 0")
 PROBLEM(reqBufferSize < 256, "ReqBufferSize should be >= 256")
 PROBLEM(respBufferSize < 256, "RespBufferSize should be >= 256")
)

CLASS
(
 REST,
 CM(bool,        enable,     Enable,     true)
 CM(std::string, serverIP,   ServerIP,   "0.0.0.0")
 CM(Uint16,    serverPort, ServerPort, 5406)
 CM(unsigned,    numThreads, NumThreads, 16)
 CM(bool,        healthRequiresAPIKey, HealthRequiresAPIKey, false)
 CM(bool,        pingRequiresAPIKey, PingRequiresAPIKey, false)
 PROBLEM(!enable, "REST must be enabled")
 PROBLEM(serverIP.empty(), "REST server IP cannot be empty")
 PROBLEM(serverPort == 0, "REST server port cannot be zero")
 PROBLEM(numThreads == 0, "Number of threads cannot be zero")
 PROBLEM(numThreads > 991, "Number of threads too high")
)

CLASS(GRPC,
  CM(bool,        enable,     Enable,     false)
  CM(std::string, serverIP,   ServerIP,   "0.0.0.0")
  CM(Uint16,    serverPort, ServerPort, 4406)
  PROBLEM(enable, "gRPC not supported")
)

CLASS(Mgmd,
  CM(std::string, IP,   IP,   "localhost")
  CM(Uint16,    port, Port, 1186)
  PROBLEM(IP.empty(), "the Management server IP cannot be empty")
  PROBLEM(port == 0, "the Management server port cannot be zero")
)

VECTOR(Mgmd)

VECTOR(Uint32)

CLASS
(RonDB,
 CM(std::vector<Mgmd>, Mgmds,                         Mgmds,                     {Mgmd()})
 CM(Uint32, connectionPoolSize, ConnectionPoolSize, 1)
 CM(std::vector<Uint32>, nodeIDs, NodeIDs, {0})
 CM(Uint32, connectionRetries, ConnectionRetries, 5)
 CM(Uint32, connectionRetryDelayInSec, ConnectionRetryDelayInSec, 5)
 CM(Uint32, opRetryOnTransientErrorsCount, OpRetryOnTransientErrorsCount, 3)
 CM(Uint32, opRetryInitialDelayInMS, OpRetryInitialDelayInMS, 500)
 CM(Uint32, opRetryJitterInMS, OpRetryJitterInMS, 100)
 PROBLEM(Mgmds.empty(), "at least one Management server has to be defined")
 PROBLEM(Mgmds.size() > 1,
 "we do not support specifying more than one Management server yet")
 PROBLEM(connectionPoolSize > 8,
 "wrong connection pool size. Currently only at most 8 RonDB connections"
 " are supported")
 PROBLEM(nodeIDs.size() != connectionPoolSize && nodeIDs.size() != 0,
 "wrong number of NodeIDs. The number of node ids must match the connection"
 " pool size or be 0 (in which case the node ids are selected by RonDB")
 CLASSDEFS
 (
  bool present_in_config_file = false;
  std::string generate_Mgmd_connect_string();
 )
)

CLASS
(TestParameters,
 CM(std::string, clientCertFile, ClientCertFile, "")
 CM(std::string, clientKeyFile,  ClientKeyFile,  "")
)

CLASS
(TLS,
 CM(bool, enableTLS, EnableTLS, false)
 CM(bool, requireAndVerifyClientCert, RequireAndVerifyClientCert, false)
 CM(std::string, certificateFile, CertificateFile, "")
 CM(std::string, privateKeyFile, PrivateKeyFile, "")
 CM(std::string, rootCACertFile, RootCACertFile, "")
 CM(TestParameters, testParameters, TestParameters, TestParameters())
 PROBLEM(enableTLS && (certificateFile.empty() ||
         privateKeyFile.empty()),
         "cannot enable TLS if `CertificateFile` or `PrivateKeyFile` is"
         " not set")
 PROBLEM(!enableTLS && requireAndVerifyClientCert,
         "cannot require client certificates if TLS is not enabled")
)

CLASS
(APIKey,
 CM(bool, useHopsworksAPIKeys, UseHopsworksAPIKeys, true)
 CM(Uint32, cacheRefreshIntervalMS, CacheRefreshIntervalMS, 10000)
 CM(Uint32, cacheUnusedEntriesEvictionMS, CacheUnusedEntriesEvictionMS, 60000)
 CM(Uint32, cacheRefreshIntervalJitterMS, CacheRefreshIntervalJitterMS, 1000)
 PROBLEM(cacheRefreshIntervalMS <= 0,
   "cache refresh interval must be greater than 0")
 PROBLEM(cacheUnusedEntriesEvictionMS <= 0,
   "cache unused entries eviction must be greater than 0")
 PROBLEM(cacheRefreshIntervalMS > cacheUnusedEntriesEvictionMS,
   "cache refresh interval cannot be greater than cache unused"
   " entries eviction")
 PROBLEM(cacheRefreshIntervalJitterMS >= cacheRefreshIntervalMS,
   "cache refresh interval must be smaller than cache refresh interval jitter")
)

CLASS
(Security,
 CM(TLS,    tls,    TLS,    TLS())
 CM(APIKey, apiKey, APIKey, APIKey())
)

CLASS
(LogConfig,
 CM(std::string, level,      Level,      "warn")
 CM(std::string, filePath,   FilePath,   "")
 CM(int,         maxSizeMb,  MaxSizeMb,  100)
 CM(int,         maxBackups, MaxBackups, 10)
 CM(int,         maxAge,     MaxAge,     30)
 // TODO implement validation
)

CLASS
(MySQLServer,
 CM(std::string,  IP,   IP,  "localhost")
 CM(Uint16,     port, Port, 13001)
 PROBLEM(IP.empty(), "the MySQL server IP cannot be empty")
 PROBLEM(port == 0, "the MySQL server port cannot be empty")
)

VECTOR(MySQLServer)

CLASS
(MySQL,
 CM(std::vector<MySQLServer>, servers,  Servers,  {MySQLServer()})
 CM(std::string,              user,     User,     "root")
 CM(std::string,              password, Password, "")
 CLASSDEFS
 (
  bool present_in_config_file = false;
  std::string generate_mysqld_connect_string();
 )
 PROBLEM(servers.empty(), "at least one MySQL server has to be defined")
 PROBLEM(servers.size() > 1,
 "we do not support specifying more than one MySQL server yet")
 PROBLEM(user.empty(), "the MySQL user cannot be empty")
)

CLASS
(Testing,
 CM(MySQL, mySQL,                MySQL,                MySQL())
 CM(MySQL, mySQLMetadataCluster, MySQLMetadataCluster, MySQL())
)

CLASS
(AllConfigs,
 CM(Internal,    internal,             Internal,             Internal())
 CM(std::string, pidfile,              PIDFile,              "")
 CM(REST,        rest,                 REST,                 REST())
 CM(GRPC,        grpc,                 GRPC,                 GRPC())
 CM(RonDB,       ronDB,                RonDB,                RonDB())
 CM(RonDB,       ronDBMetadataCluster, RonDBMetadataCluster, RonDB())
 CM(Security,    security,             Security,             Security())
 CM(LogConfig,   log,                  Log,                  LogConfig())
 CM(Testing,     testing,              Testing,              Testing())
 CLASSDEFS
 (
  static AllConfigs get_all();
  static RS_Status set_all(AllConfigs);
  static RS_Status set_from_file(const std::string &);
  static RS_Status init(std::string configFile);
 )
)
