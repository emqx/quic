/*--------------------------------------------------------------------
Copyright (c) 2023 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-------------------------------------------------------------------*/
#include "quicer_tls.h"

/*
** Build QUIC_CREDENTIAL_CONFIG from options, certfile, keyfile and password
*/
BOOLEAN
parse_cert_options(ErlNifEnv *env,
                   ERL_NIF_TERM options,
                   QUIC_CREDENTIAL_CONFIG *CredConfig)
{
  char *password = NULL;
  char *certfile = NULL;
  char *keyfile = NULL;
  ERL_NIF_TERM tmp_term;

  if (!CredConfig)
    {
      return FALSE;
    }

  if (!(certfile
        = str_from_map(env, ATOM_CERTFILE, &options, NULL, PATH_MAX + 1)))
    {
      return FALSE;
    }
  if (!(keyfile
        = str_from_map(env, ATOM_KEYFILE, &options, NULL, PATH_MAX + 1)))
    {
      return FALSE;
    }

  // Get password for Server CertFile
  if (enif_get_map_value(env, options, ATOM_PASSWORD, &tmp_term))
    {
      if (!(password = str_from_map(env, ATOM_PASSWORD, &options, NULL, 256)))
        {
          return FALSE;
        }

      QUIC_CERTIFICATE_FILE_PROTECTED *CertFile
          = (QUIC_CERTIFICATE_FILE_PROTECTED *)CXPLAT_ALLOC_NONPAGED(
              sizeof(QUIC_CERTIFICATE_FILE_PROTECTED),
              QUICER_CERTIFICATE_FILE);

      if (!CertFile)
        {
          return FALSE;
        }
      CertFile->CertificateFile = certfile;
      CertFile->PrivateKeyFile = keyfile;
      CertFile->PrivateKeyPassword = password;
      CredConfig->CertificateFileProtected = CertFile;
      CredConfig->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
    }
  else
    {
      QUIC_CERTIFICATE_FILE *CertFile
          = (QUIC_CERTIFICATE_FILE *)CXPLAT_ALLOC_NONPAGED(
              sizeof(QUIC_CERTIFICATE_FILE), QUICER_CERTIFICATE_FILE);
      if (!CertFile)
        {
          return FALSE;
        }
      CertFile->CertificateFile = certfile;
      CertFile->PrivateKeyFile = keyfile;
      CredConfig->CertificateFile = CertFile;
      CredConfig->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    }

  return TRUE;
}

/*
 * Parse verify option for listener (server)
 *  verify : boolean() | undefined
 */
BOOLEAN
parse_verify_options(ErlNifEnv *env,
                     ERL_NIF_TERM options,
                     QUIC_CREDENTIAL_CONFIG *CredConfig,
                     BOOLEAN is_server)
{

  BOOLEAN verify = load_verify(env, &options, FALSE);

  if (!verify)
    {
      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }
  else
    {
      // Verify peer is enabled
      if (is_server)
        {
          CredConfig->Flags
              |= QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
        }
      else
        {
          ERL_NIF_TERM tmp;
          if (enif_get_map_value(env, options, ATOM_CACERTFILE, &tmp))
            {
              // cacertfile is set, use it for self validation.
              CredConfig->Flags
                  |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
              CredConfig->Flags
                  |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
            }
          CredConfig->Flags
              |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
        }
    }
  return TRUE;
}

/*
** Parse optional cacertfile option
*/
BOOLEAN
parse_cacertfile_option(ErlNifEnv *env,
                        ERL_NIF_TERM options,
                        char **cacertfile)
{
  ERL_NIF_TERM ecacertfile;
  char *tmp = NULL;

  if (!enif_is_map(env, options))
    {
      return FALSE;
    }

  if (enif_get_map_value(env, options, ATOM_CACERTFILE, &ecacertfile))
    {
      tmp = str_from_map(env, ATOM_CACERTFILE, &options, NULL, PATH_MAX + 1);
      if (!tmp)
        {
          return FALSE;
        }
    }
  *cacertfile = tmp;
  return TRUE;
}

BOOLEAN
build_trustedstore(const char *cacertfile, X509_STORE **trusted_store)
{
  X509_STORE *store = NULL;
  X509_LOOKUP *lookup = NULL;

  if (cacertfile == NULL)
    {
      return FALSE;
    }

  store = X509_STORE_new();
  if (store == NULL)
    {
      return FALSE;
    }

  lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  if (lookup == NULL)
    {
      X509_STORE_free(store);
      return FALSE;
    }

  if (!X509_LOOKUP_load_file(lookup, cacertfile, X509_FILETYPE_PEM))
    {
      X509_STORE_free(store);
      return FALSE;
    }

  *trusted_store = store;
  return TRUE;
}

/*
 * Free certfile/certfileprotected of QUIC_CREDENTIAL_CONFIG
 *
 */
void
free_certificate(QUIC_CREDENTIAL_CONFIG *cc)
{
  if (!cc)
    {
      return;
    }

  if (QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE == cc->Type)
    {
      free((char *)cc->CertificateFile->CertificateFile);
      free((char *)cc->CertificateFile->PrivateKeyFile);
      CxPlatFree(cc->CertificateFile, QUICER_CERTIFICATE_FILE);
    }
  else if (QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED == cc->Type)
    {
      free((char *)cc->CertificateFileProtected->CertificateFile);
      free((char *)cc->CertificateFileProtected->PrivateKeyFile);
      free((char *)cc->CertificateFileProtected->PrivateKeyPassword);
      CxPlatFree(cc->CertificateFileProtected,
                 QUICER_CERTIFICATE_FILE_PROTECTED);
    }
}

/*
 * Parse 'sslkeylogfile' option and set QUIC_PARAM_CONN_TLS_SECRETS conn
 * options for sslkeylogfile dump.
 *
 * alloc and update:
 * c_ctx->TlsSecrets = TlsSecrets;
 * c_ctx->ssl_keylogfile = keylogfile;
 *
 * usually they are not inuse (NULL), so we use heap memory.
 * Caller should ensure they are freed after use.
 *
 */
void
parse_sslkeylogfile_option(ErlNifEnv *env,
                           ERL_NIF_TERM eoptions,
                           QuicerConnCTX *c_ctx)
{
  QUIC_STATUS Status;

  char *keylogfile = str_from_map(
      env, ATOM_SSL_KEYLOGFILE_NAME, &eoptions, NULL, PATH_MAX + 1);

  if (!keylogfile)
    {
      return;
    }

  // Allocate the TLS secrets
  QUIC_TLS_SECRETS *TlsSecrets
      = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_TLS_SECRETS), QUICER_TLS_SECRETS);

  if (!TlsSecrets)
    {
      return;
    }

  CxPlatZeroMemory(TlsSecrets, sizeof(QUIC_TLS_SECRETS));

  // Set conn opt QUIC_PARAM_CONN_TLS_SECRETS
  if (QUIC_FAILED(Status = MsQuic->SetParam(c_ctx->Connection,
                                            QUIC_PARAM_CONN_TLS_SECRETS,
                                            sizeof(QUIC_TLS_SECRETS),
                                            TlsSecrets)))
    {
      //unlikely
      CXPLAT_FREE(keylogfile, QUICER_TRACE);
      keylogfile = NULL;
      CXPLAT_FREE(TlsSecrets, QUICER_TLS_SECRETS);
      TlsSecrets = NULL;
      fprintf(stderr,
              "failed to enable secret logging: %s",
              QuicStatusToString(Status));
    }

  // @TODO: check if old ssl_keylogfile/TlsSecrets is set, free it?
  c_ctx->TlsSecrets = TlsSecrets;
  c_ctx->ssl_keylogfile = keylogfile;
}
