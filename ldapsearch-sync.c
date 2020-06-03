/*
 *  LDAP Examples
 *  Copyright (C) 2011 David M. Syzdek <david@syzdek.net>.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of David M. Syzdek nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL DAVID M. SYZDEK BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */
/**
 *  @file ldapsearch-sync.c an example of an LDAP synchronous search using an LDAP API.
 */
/*
 *  Simple Build:
 *     gcc -W -Wall -O2 -c ldapsearch-sync.c
 *     gcc -W -Wall -O2 -lldap -llber -o ldapsearch-sync ldapsearch-sync.o
 *
 *  GNU Libtool Build:
 *     libtool --mode=compile gcc -W -Wall -g -O2 -c ldapsearch-sync.c
 *     libtool --mode=link    gcc -W -Wall -g -O2 -lldap -llber -o ldapsearch-sync ldapsearch-sync.lo
 *
 *  GNU Libtool Install:
 *     libtool --mode=install install -c ldapsearch-sync /usr/local/bin/ldapsearch-sync
 *
 *  GNU Libtool Clean:
 *     libtool --mode=clean rm -f ldapsearch-sync.lo ldapsearch-sync
 */


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef PMARK
#pragma mark - Headers
#endif

#include <stdio.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef PMARK
#pragma mark - Definitions & Macros
#endif

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapsearch-sync"
#endif

#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT "syzdek@bindlebinaries.com"
#endif

#ifndef PACKAGE_NAME
#define PACKAGE_NAME "LDAP Examples"
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef PMARK
#pragma mark - Datatypes
#endif

/// @brief stores data for interactive SASL authentication
typedef struct ldapexample_auth LDAPAuth;
struct ldapexample_auth
{
   const char     * dn;        ///< DN to use for simple bind
   const char     * saslmech;  ///< SASL mechanism to use for authentication
   const char     * authuser;  ///< user to authenticate
   const char     * user;      ///< pre-authenticated user
   const char     * realm;     ///< SASL realm used for authentication
   BerValue         cred;      ///< the credentials of "user" (i.e. password)
};


/// @brief stores data for interactive SASL authentication
typedef struct ldapexample_config LDAPConfig;
struct ldapexample_config
{
   int              verbose;
   char             ldap_url[1024];
   const char     * ldap_ca;
   int              ldap_tls;
   int              ldap_version;
   int              search_limit;
   struct timeval   search_timeout;
   struct timeval   tcp_timeout;
   LDAPURLDesc    * ludp;
   LDAPAuth         auth;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef PMARK
#pragma mark - Prototypes
#endif

// retrieves information during interactive SASL auth attempt
int ldapexample_sasl_interact(LDAP * ld, unsigned flags, void * defaults,
   void * sin);

// displays usage information
void ldapexample_usage(void);

// print verbose message
void ldapexample_verbose(LDAPConfig * cnfp, const char * fmt, ...);
   
// main execution loop
int main(int argc, char * argv[]);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef PMARK
#pragma mark - Functions
#endif

/// @brief retrieves information during interactive SASL auth attempt
/// @param ld         current LDAP descriptor
/// @param flags      type of SASL auth
/// @param defaults   pointer to populated TestAuthData
/// @param sin        requested information
int ldapexample_sasl_interact(LDAP * ld, unsigned flags, void * defaults,
   void * sin)
{
   LDAPAuth        * ldap_inst;
   sasl_interact_t * interact;

   if (!(ld))
      return(LDAP_PARAM_ERROR);

   if (!(defaults))
      return(LDAP_PARAM_ERROR);

   if (!(sin))
      return(LDAP_PARAM_ERROR);

   switch(flags)
   {
      case LDAP_SASL_AUTOMATIC:
      case LDAP_SASL_INTERACTIVE:
      case LDAP_SASL_QUIET:
      default:
      break;
   };

   ldap_inst = defaults;

   for(interact = sin; (interact->id != SASL_CB_LIST_END); interact++)
   {
      interact->result = NULL;
      interact->len    = 0;
      switch(interact->id)
      {
         case SASL_CB_GETREALM:
            //fprintf(stderr, "SASL Data: SASL_CB_GETREALM (%s)\n", ldap_inst->realm ? ldap_inst->realm : "");
            interact->result = ldap_inst->realm ? ldap_inst->realm : "";
            interact->len    = (unsigned)strlen( interact->result );
            break;
         case SASL_CB_AUTHNAME:
            //fprintf(stderr, "SASL Data: SASL_CB_AUTHNAME (%s)\n", ldap_inst->authuser ? ldap_inst->authuser : "");
            interact->result = ldap_inst->authuser ? ldap_inst->authuser : "";
            interact->len    = (unsigned)strlen( interact->result );
            break;
         case SASL_CB_PASS:
            //fprintf(stderr, "SASL Data: SASL_CB_PASS (%s)\n", ldap_inst->cred.bv_val ? ldap_inst->cred.bv_val : "");
            interact->result = ldap_inst->cred.bv_val ? ldap_inst->cred.bv_val : "";
            interact->len    = (unsigned)ldap_inst->cred.bv_len;
            break;
         case SASL_CB_USER:
            //fprintf(stderr, "SASL Data: SASL_CB_USER (%s)\n", ldap_inst->user ? ldap_inst->user : "");
            interact->result = ldap_inst->user ? ldap_inst->user : "";
            interact->len    = (unsigned)strlen( interact->result );
            break;
         case SASL_CB_NOECHOPROMPT:
            //fprintf(stderr, "SASL Data: SASL_CB_NOECHOPROMPT\n");
            break;
         case SASL_CB_ECHOPROMPT:
            //fprintf(stderr, "SASL Data: SASL_CB_ECHOPROMPT\n");
            break;
         default:
            //fprintf(stderr, "SASL Data: unknown option: %lu\n", interact->id);
            break;
      };
   };

   return(LDAP_SUCCESS);
}


/// @brief displays usage information
void ldapexample_usage(void)
{
   printf(("Usage: %s [OPTIONS]\n"
         "  -2                        use protocol version 2\n"
         "  -3                        use protocol version 3\n"
         "  -C file                   file containing CA certificates\n"
         "  -D dn                     bind DN\n"
         "  -H url                    LDAP URL\n"
         "  -h, --help                print this help and exit\n"
         "  -l limit                  search limit\n"
         "  -T timeout                TCP timeout\n"
         "  -t timeout                search timeout\n"
         "  -U user                   SASL bind user\n"
         "  -w password               bind password\n"
         "  -Y mech                   SASL bind mechanism\n"
         "  -Z                        Start TLS request (-ZZ verify hostname matches)\n"
         "\n"
         "LDAP URL: ldap://hostport/dn[?attrs[?scope[?filter[?exts]]]]\n"
         "\n"
         "   example: ldap://ldap.example.net/dc=example,dc=net?cn,sn?sub?(cn=*)\n"
         "\n"
         "Report bugs to <%s>.\n"
      ), PROGRAM_NAME, PACKAGE_BUGREPORT);
   return;
}


/// @brief print verbose message
/// @param verbose    verbose level
/// @param fmt        printf format
/// @param ...        printf format arguments
void ldapexample_verbose(LDAPConfig * cnfp, const char * fmt, ...)
{
   va_list args;

   if (cnfp->verbose < 1)
      return;

   va_start(args, fmt);
   vfprintf (stderr, fmt, args );
   va_end(args);

   return;
}


/// @brief main loop
/// @param argc       number of arguments passed to program
/// @param argv       array of arguments passed to program
int main(int argc, char * argv[])
{
   // local variables
   LDAPConfig       config;
   void           * ptr;
   LDAP           * ld;
   int              err;
   char           * errmsg;
   int              opt;
   BerValue       * servercredp;
   BerValue       * authzid;
   LDAPMessage    * res;
   LDAPMessage    * entry;
   LDAPMessage    * new_entry;
   char           * dn;
   const char     * attribute;
   BerElement     * ber;
   BerValue      ** vals;
   int              pos;

   // local variables for parsing cli arguments
   int                  c;
   int                  opt_index;
   static char          short_opt[] = "23C:D:H:hl:T:t:U:vw:Y:Z";
   static struct option long_opt[] =
   {
      {"help",          no_argument, 0, 'h'},
      {"silent",        no_argument, 0, 'q'},
      {"quiet",         no_argument, 0, 'q'},
      {"verbose",       no_argument, 0, 'v'},
      {NULL,            0,           0, 0  }
   };

   // reset config data
   memset(&config, 0, sizeof(LDAPConfig));
   strncpy(config.ldap_url, "ldap://localhost/", 1024);
   config.ldap_version   = LDAP_VERSION3;

   // processes command line arguments
   while((c = getopt_long(argc, argv, short_opt, long_opt, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
            break;
         case '2':
            config.ldap_version = LDAP_VERSION2;
            break;
         case '3':
            config.ldap_version = LDAP_VERSION3;
            break;
         case 'D':
            config.auth.dn       = optarg;
            break;
         case 'C':
            config.ldap_ca = optarg;
            break;
         case 'H':
            if ((ldap_url_parse(optarg, &config.ludp)))
            {
               fprintf(stderr, "ldap_url_parse(): invalid LDAP URL\n");
               return(1);
            };
            snprintf(config.ldap_url, 1024, "%s://%s:%i",
               config.ludp->lud_scheme, config.ludp->lud_host,
               config.ludp->lud_port);
            break;
         case 'h':
            ldapexample_usage();
            return(0);
         case 'l':
            config.search_limit = (int) strtol(optarg, NULL, 0);
            break;
         case 'T':
            config.search_timeout.tv_sec = (int) strtol(optarg, NULL, 0);
            config.tcp_timeout.tv_sec = (int) strtol(optarg, NULL, 0);
            break;
         case 't':
            config.search_timeout.tv_sec = (int) strtol(optarg, NULL, 0);
            break;
         case 'U':
            config.auth.authuser = optarg;
            break;
         case 'v':
            config.verbose++;
            break;
         case 'w':
            config.auth.cred.bv_val = optarg;
            config.auth.cred.bv_len = strlen(config.auth.cred.bv_val);
            break;
         case 'Y':
            config.auth.saslmech = optarg;
            break;
         case 'Z':
            config.ldap_tls++;
            break;
         case '?':
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
         default:
            fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            return(1);
      };
   };

   // checks for unknown options
   if (optind != argc)
   {
      fprintf(stderr, "%s: too many arguments\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   // initialize LDAP handle
   ldapexample_verbose(&config, "ldap_initialize()\n");
   if ((err = ldap_initialize(&ld, config.ldap_url)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_initialize(): %s\n", ldap_err2string(err));
      return(1);
   };

   // set LDAP protocol version
   ldapexample_verbose(&config, "ldap_set_option(LDAP_OPT_PROTOCOL_VERSION)\n");
   err = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &config.ldap_version);
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };

   // set network timout
   if ((config.tcp_timeout.tv_sec))
   {
      ldapexample_verbose(&config, "ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT)\n");
      err = ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &config.tcp_timeout);
      if (err != LDAP_SUCCESS)
      {
         fprintf(stderr, "ldap_set_option(SIZELIMIT): %s\n", ldap_err2string(err));
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
   };

   // set LDAP search size limit
   ldapexample_verbose(&config, "ldap_set_option(LDAP_OPT_SIZELIMIT)\n");
   err = ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &config.search_limit);
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_set_option(SIZELIMIT): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };

   // set LDAP instance to require SSL cert
   opt = LDAP_OPT_X_TLS_NEVER;
   if (config.ldap_tls > 1)
      opt = LDAP_OPT_X_TLS_DEMAND;
   ldapexample_verbose(&config, "ldap_set_option(TLS_REQUIRE_CERT)\n");
   err = ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt);
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_set_option(TLS_REQUIRE_CERT): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };

   // set SSL/TLS CA cert file
   if ((config.ldap_ca))
   {
      ldapexample_verbose(&config, "ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE)\n");
      err = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, (void *)config.ldap_ca);
      if (err != LDAP_SUCCESS)
      {
         fprintf(stderr, "ldap_set_option(TLS_CACERTFILE): %s\n", ldap_err2string(err));
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
   };

   // starts SSL connection
   if ((config.ldap_tls))
   {
      ldapexample_verbose(&config, "ldap_start_tls_s()\n");
      err = ldap_start_tls_s(ld, NULL, NULL);
      switch(err)
      {
         case LDAP_SUCCESS:
         break;

         case LDAP_CONNECT_ERROR:
         ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&errmsg);
         fprintf(stderr, "ldap_start_tls_s(): %s\n", errmsg);
         ldap_memfree(errmsg);
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);

         default:
         fprintf(stderr, "ldap_start_tls_s(): %s\n", ldap_err2string(err));
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
   };

   // binds to system
   if (!(config.auth.saslmech))
   {
      ldapexample_verbose(&config, "ldap_sasl_bind_s()\n");
      err = ldap_sasl_bind_s
      (
         ld,                // LDAP           * ld
         config.auth.dn,    // const char     * dn
         LDAP_SASL_SIMPLE,  // const char     * mechanism
         &config.auth.cred, // struct berval  * cred
         NULL,              // LDAPControl    * sctrls[]
         NULL,              // LDAPControl    * cctrls[]
         &servercredp       // struct berval ** servercredp
      );
      if (err != LDAP_SUCCESS)
      {
         fprintf(stderr, "ldap_sasl_bind_s(): %s\n", ldap_err2string(err));
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
   };
   if ((config.auth.saslmech))
   {
      ldapexample_verbose(&config, "ldap_sasl_interactive_bind_s()\n");
      err = ldap_sasl_interactive_bind_s
      (
         ld,                         // LDAP                    * ld
         NULL,                       // const char              * dn
         config.auth.saslmech,       // const char              * mechs
         NULL,                       // LDAPControl             * sctrls[]
         NULL,                       // LDAPControl             * cctrls[]
         LDAP_SASL_QUIET,            // unsigned                  flags
         ldapexample_sasl_interact,  // LDAP_SASL_INTERACT_PROC * interact
         &config.auth                // void                    * defaults
      );
      if (err != LDAP_SUCCESS)
      {
         fprintf(stderr, "ldap_sasl_interactive_bind_s(): %s\n", ldap_err2string(err));
         ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&errmsg);
         fprintf(stderr, "ldap_sasl_interactive_bind_s(): %s\n", errmsg);
         ldap_memfree(errmsg);
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
   };

   // perform LDAP whoami query
   ldapexample_verbose(&config, "ldap_whoami_s()\n");
   err = ldap_whoami_s(ld, &authzid, NULL, NULL);
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_whoami_s(): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };
   printf("# whoami: %s\n", authzid->bv_val);
   ldap_memfree(authzid);

   // sets pointer to timeout if timeout is set
   ptr = NULL;
   if ((config.search_timeout.tv_sec))
      ptr = &config.search_timeout;

   // perform search
   LDAPControl *ctls[2];
   LDAPControl ctl1;
   ctl1.ldctl_oid = "1.2.840.113556.1.4.801";
   char buf[100];
   sprintf(buf, "%c%c%c%c%c", 48, 3, 2, 1, 7);
   ctl1.ldctl_value.bv_len=strlen(buf);
   ctl1.ldctl_value.bv_val=buf;
   ctls[0] = &ctl1;
   ctls[1] = NULL;
   ldapexample_verbose(&config, "ldap_search_ext_s()\n");
   err = ldap_search_ext_s(
      ld,                         // LDAP            * ld
      config.ludp->lud_dn,        // char            * base
      config.ludp->lud_scope,     // int               scope
      config.ludp->lud_filter,    // char            * filter
      config.ludp->lud_attrs,     // char            * attrs[]
      0,                          // int               attrsonly
      ctls,                       // LDAPControl    ** serverctrls
      NULL,                       // LDAPControl    ** clientctrls
      ptr,                        // struct timeval  * timeout
      config.search_limit,        // int               sizelimit
      &res                        // LDAPMessage    ** res
   );
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_search_ext_s(): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };

   // verify an entry was found
   ldapexample_verbose(&config, "ldap_count_entries()\n");
   if (!(ldap_count_entries(ld, res)))
   {
      printf("0 entries found.\n");
      ldap_msgfree(res);
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(0);
   };
   printf("# %i entries found.\n", ldap_count_entries(ld, res));

   // loops through entries, attributes, and values
   entry = ldap_first_entry(ld, res);
   while((entry))
   {
      dn = ldap_get_dn(ld, entry);
      fprintf(stderr, "dn: %s\n", dn);
      ldap_memfree(dn);

      attribute = ldap_first_attribute(ld, entry, &ber);
      while((attribute))
      {
         vals = ldap_get_values_len(ld, entry, attribute);
         for(pos = 0; pos < ldap_count_values_len(vals); pos++)
            printf("%s: %s\n", attribute, vals[pos]->bv_val);
         ldap_value_free_len(vals);
         attribute = ldap_next_attribute(ld, entry, ber);
      };
      ber_free(ber, 0);

      printf("\n");

      new_entry = ldap_next_entry(ld, entry);
      ldap_memfree(entry);
      entry = new_entry;
   };

   // unbind from LDAP server
   ldapexample_verbose(&config, "ldap_unbind_ext_s()\n");
   ldap_unbind_ext_s(ld, NULL, NULL);

   // frees resources
   ldapexample_verbose(&config, "ldap_free_urldesc()\n");
   ldap_free_urldesc(config.ludp);

   return(0);
}

/* end of source */
