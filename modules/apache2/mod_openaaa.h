/*
 * $Id: mod_tls_aaa.h Daniel Kubec <niel@rtfm.cz> $
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MOD_AUTH_TLS_H__
#define __MOD_AUTH_TLS_H__

/* require mod_ssl / mod_auth_basic / libaaa */

#include <stdlib.h>
#include <unistd.h>
#include <ap_config.h>
#include <httpd.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_log.h>
#include <http_main.h>
#include <http_request.h>
#include <http_protocol.h>
#include <http_request.h>
#include <util_filter.h>
#include <util_script.h>

#define MODULE_PREFIX "authnz_ssl"
#define MODULE_VERSION "OpenAAA/1.0.0" 
#define MODULE_ENTRY authnz_ssl_module

extern module AP_MODULE_DECLARE_DATA MODULE_ENTRY;

#endif/*__MOD_AUTH_TLS_H__*/
