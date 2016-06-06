/*
 * (AAA) Autentication, Authorisation and Accounting) Library
 *
 * The MIT License (MIT)         Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
 *                                                                              
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"),to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell    
 * copies of the Software, and to permit persons to whom the Software is        
 * furnished to do so, subject to the following conditions:                     
 *                                                                              
 * The above copyright notice and this permission notice shall be included in   
 * all copies or substantial portions of the Software.                          
 *                                                                              
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR   
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,     
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER       
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN    
 * THE SOFTWARE.
 *
 */

#ifndef __AAA_LIB_PUBLIC_H__
#define __AAA_LIB_PUBLIC_H__

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

/* API version, they compare as integers */
#define API_VERSION PACKAGE_VERSION

#define AAA_ENDPOINT_CLIENT       1
#define AAA_ENDPOINT_SERVER       2

/* A private structures containing the aaa context */
struct aaa;

enum aaa_endpoint {
	ENDPOINT_CLIENT = 1,
	ENDPOINT_SERVER = 2
};

/* public api functions */

/*
 * NAME
 *
 * aaa_new()
 *
 * DESCRIPTION
 *
 * Creates a new aaa context. Before using it, it is necessary to initialize
 * it by calling aaa_open().
 *
 * RETURN
 *
 * A pointer to the new context or NULL is returned.
 */

struct aaa *
aaa_new(enum aaa_endpoint type);

/*
 * NAME
 *
 * aaa_new()
 *
 * DESCRIPTION
 *
 * Creates a new aaa context. Before using it, it is necessary to initialize
 * it by calling aaa_open().
 *
 * RETURN
 *
 * A pointer to the new context or NULL is returned.
 */

void
aaa_free(struct aaa *);

/*
 * NAME
 *
 * aaa_bind()
 *
 * DESCRIPTION
 *
 * aaa_bind() finds a session identified by @id. 
 * The meaning of @id depends on the selected @mode.
 *
 * It can also be used to switch from one session to another after the context 
 * is reset.
 *
 * Binding does not fetch the automatic attributes to the context.
 * Use aaa_select() to fetch other subtrees as needed.
 *
 * NOTE
 *
 * The authentication rules used in binding can vary between implementations 
 *
 * RETURN
 *
 * Upon successful completion, 0 is returned.  Otherwise, a negative
 * error code is returned.
 */

int
aaa_bind(struct aaa *, int type, const char *value);

/*
 * NAME
 *
 * aaa_set()
 *
 * DESCRIPTION
 *
 * Sets the single-valued attribute identified by @key to @val. If @val
 * is NULL, the attribute is removed.
 *
 * Changing of the o.id attribute is possible, but covered by special
 * rules. It must be performed on a context which is bound
 * and the context must be destroyed afterwards.
 *
 * RETURN
 *
 * Upon successful completion, 0 is returned.  Otherwise, a negative
 * error code is returned.
 */

int 
aaa_attr_set(struct aaa *, const char *attr, char *value);

/*
 * NAME
 *
 * aaa_get()
 *
 * DESCRIPTION
 *
 * Gets the current value of a single-valued attribute identified by @key.
 *
 * RETURN
 *
 * Upon successful completion, the value of the attribute is returned.  
 * Otherwise, NULL is returned and you can call aaa_last_error() to determine 
 * the cause of the error.
 */

const char *
aaa_attr_get(struct aaa *, const char *attr);

/*
 * NAME
 *
 * aaa_object_set()
 *
 * DESCRIPTION
 *
 * Sets the binary object
 *                                                                              
 * RETURN
 *
 * Upon successful completion, 0 is returned.  Otherwise, a negative            
 * error code is returned.                                                      
 */

int
aaa_attr_del_value(struct aaa *, const char *key, const char *val);

/*
 * NAME
 *
 * aaa_has_value()
 *
 * DESCRIPTION
 *
 * This function checks if @val is present in the set of values of the given
 * multi-valued attribute.
 *
 * RETURN
 *
 * When the value is present, a value of 1 is returned. If it is not present,
 * the function returns 0. If any error occurs, a negative error code is returned.
 */

int
aaa_attr_has_value(struct aaa *, const char *key, const char *val);

/*
 * NAME
 *
 * aaa_find_first()
 *
 * DESCRIPTION
 *
 * Finds the first attribute in the subtree of attributes whose names start w
 * ith @path.
 * Further attributes in the subtree can be retrieved by calling 
 * aaa_find_next().
 *
 * The attributes are enumerated in no particular order, but the library 
 * guarantees that every attribute will be listed exactly once. When the 
 * enumeration is in progress, no attributes should be added nor removed.
 *
 * The @recurse parameter controls whether to enumerate only the immediate 
 * descendants (if set to 0), or the whole subtree (if set to 1).
 *
 * RETURN
 *
 * Upon successful completion, the name of the attribute is returned and if 
 * @val is non-NULL,
 * *@val is set to the value of the attribute (in case of multi-valued 
 * attributes, it is an arbitrary chosen value from the set). Otherwise, NULL 
 * is returned and you can call aaa_last_error() to determine the cause of the
 * error.
 */

const char *
aaa_attr_find_first(struct aaa *, const char *path, unsigned recurse);

/*
 * NAME
 *
 * aaa_find_next()
 *
 * DESCRIPTION
 *
 * It finds the next attribute in the specified subtree, as initialized by a call
 * to aaa_find_first().
 *
 * RETURN
 *
 * Upon successful completion, the name of the attribute is returned and 
 * if @val is non-NULL, *@val is set to the value of the attribute (in case of 
 * multi-valued attributes, it is an arbitrary chosen value from the set). 
 * Otherwise, NULL is returned and you can call aaa_last_error() to 
 * determine the cause of the error.
 */

const char *
aaa_attr_find_next(struct aaa *);

/*
 * NAME
 *
 * aaa_select()
 *
 * DESCRIPTION
 *
 * This function fetches the up-to-date values of all attributes in given subtrees
 * from the primary storage (depending on the subtree). 
 *
 * The subtrees are specified by their names separated by ':'.
 *
 * RETURN
 *
 * Upon successful completion, 0 is returned.  Otherwise, a negative
 * error code is returned.
 */

int 
aaa_select(struct aaa *, const char *path);

int
aaa_touch(struct aaa *);

/*
 * NAME
 *
 * aaa_commit()
 *
 * DESCRIPTION
 *
 * Commits all attribute changes to persistent storage.
 *
 * RETURN
 *
 * Upon successful completion, 0 is returned.  Otherwise, a negative
 * error code is returned.
 */

int
aaa_commit(struct aaa *);

enum aaa_opt_e {                                                                
	AAA_OPT_USERDATA  = 1,                                                  
	AAA_OPT_CUSTOMLOG = 2                                                   
};

typedef void (*aaa_custom_log_t)(struct aaa*, unsigned level, const char *msg);

#endif/*__AAA_LIB_H__*/
