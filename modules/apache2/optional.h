/*
 * $Id: optional.h                              Daniel Kubec <niel@rtfm.cz> $
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

#ifndef __MOD_TLS_AAA_OPTIONAL_H__
#define __MOD_TLS_AAA_OPTIONAL_H__

/*
 * The ssl_var_lookup() optional function retrieves SSL environment
 * variables. 
 */

APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup, 
                       (apr_pool_t *, server_rec *, 
                        conn_rec *, request_rec *, char *));

/*
 * An optional function which returns non-zero if the given connection
 * is using SSL/TLS. 
 */

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

/*
 * The ssl_export_keying_material exports a value derived from the master
 * secret, as specified in RFC 5705. It writes |olen| bytes to |out| given
 * a label and optional context. (Since a zero length context is allowed,
 * the |use_ctx| flag controls whether a context is included.)
 *
 * It returns OK on success and DECLINED otherwise.
 */

APR_DECLARE_OPTIONAL_FN(int, ssl_export_keying_material,
                       (conn_rec *c,
                        unsigned char *out, size_t olen,
                        const char *label, size_t llen,
                        const unsigned char *p, size_t plen,
                        int use_ctx));

/**The ssl_renegotiate() function sets flags to initiate renegotiation.
 * The renegotiation may happen at the next I/O operation provided that
 * client/server are ready for renegotiation.
 *
 * It returns OK on success and DECLINED otherwise.
 */

APR_DECLARE_OPTIONAL_FN(int, ssl_renegotiation, (conn_rec *));

/*
 * The npn_advertise_protos callback allows another modules to add
 * entries to the list of protocol names advertised by the server
 * during the Next Protocol Negotiation (NPN) portion of the SSL
 * handshake.  The callback is given the connection and an APR array;
 * it should push one or more char*'s pointing to NUL-terminated
 * strings (such as "http/1.1" or "spdy/2") onto the array and return
 * OK.  To prevent further processing of (other modules') callbacks,
 * return DONE. 
 */

typedef int (*ssl_npn_advertise_protos)(conn_rec *connection,
             apr_array_header_t *protos);

/*
 * The npn_proto_negotiated callback allows other modules to discover
 * the name of the protocol that was chosen during the Next Protocol
 * Negotiation (NPN) portion of the SSL handshake.  Note that this may
 * be the empty string (in which case modules should probably assume
 * HTTP), or it may be a protocol that was never even advertised by
 * the server.  The callback is given the connection, a
 * non-NUL-terminated string containing the protocol name, and the
 * length of the string; it should do something appropriate
 * (i.e. insert or remove filters) and return OK.  To prevent further
 * processing of (other modules') callbacks, return DONE.
 */

typedef int (*ssl_npn_proto_negotiated)(conn_rec *connection,
            const char *proto_name, apr_size_t proto_name_len);

/*
 * An optional function which can be used to register a pair of
 * callbacks for NPN handling.  This optional function should be
 * invoked from a pre_connection hook which runs *after* mod_ssl.c's
 * pre_connection hook.  The function returns OK if the callbacks are
 * register, or DECLINED otherwise (for example if mod_ssl does not
 * support NPN).  
 */

APR_DECLARE_OPTIONAL_FN(int, modssl_register_npn, (conn_rec *conn,
                        ssl_npn_advertise_protos advertisefn,
                        ssl_npn_proto_negotiated negotiatedfn));

#endif/*__MOD_TLS_AAA_OPTIONAL_H__*/
