/*
 * Copyright © 2012-2015 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ntlm_mglueP.h"
#include "ntlm_encrypt.h"
#include "ntlm_util.h"
#include <krb5.h>
#include "gssapiP_ntlm.h"
#include "gssapi/gssapi_krb5.h"
#include "gssapi_alloc.h"
#include <lber.h>
#include <csrp/srp.h>
#include <ctype.h>

static OM_uint32
__ntlm_ber_flatten_output_token(
    OM_uint32 *minor_status,
    BerElement *ber,
    int ber_len,
    gss_buffer_t asn1_oid,
    gss_buffer_t output_token)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    OM_uint32 output_token_len = 0;
    gss_buffer_desc output_token_mem = {0};
    unsigned char *ptr = NULL;
    int berror = 0;
    struct berval *flatten = NULL;

    berror = ber_flatten(ber, &flatten);
    if (berror == -1)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

    output_token_len = (OM_uint32) (asn1_oid->length + ber_len);
    output_token_mem.value = gssalloc_malloc(output_token_len);
    if (!output_token_mem.value)
    {
        minor = ENOMEM;
        major = GSS_S_FAILURE;
        goto error;
    }
    memset(output_token_mem.value, 0, output_token_len);

    output_token_mem.length = output_token_len;
    ptr = output_token_mem.value;

    memcpy(ptr, asn1_oid->value, asn1_oid->length);
    ptr += asn1_oid->length;

    memcpy(ptr, flatten->bv_val, flatten->bv_len);
    ptr += ber_len;

    /* output_token now owns the memory in output_token_mem */
    *output_token = output_token_mem;
    memset(&output_token_mem, 0, sizeof(output_token_mem));

error:
    if (major)
    {
        *minor_status = minor;
        if (output_token_mem.value)
        {
            gssalloc_free(output_token_mem.value);
        }
    }
    if (flatten)
    {
        ber_bvfree(flatten);
    }
    return major;
}

/*
 * Carol → Steve: I and A = g**a
 */
static
OM_uint32
_ntlm_gss_make_auth_init_output_token(
    OM_uint32 *minor_status,
    gss_OID ntlm_mech_oid,
    gss_name_t auth_name,
    gss_buffer_t auth_password,
    ntlm_gss_ctx_id_t ntlm_context_handle,
    gss_buffer_t output_token)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    gss_buffer_desc asn1_ntlm_oid = {0};
    gss_buffer_desc export_name_buf = {0};
    gss_buffer_t export_name = NULL;
    gss_OID export_OID = NULL;
    BerElement *ber = NULL;
    int ber_len = 0;
    int berror = 0;
    char *export_name_str = NULL;
    char *password = NULL;
    struct SRPUser *usr = NULL;
    const char *ntlm_auth_user = NULL;
    const unsigned char *ntlm_bytes_A = NULL;
    int ntlm_bytes_A_len = 0;
    int i = 0;
    SRP_NGType ng_type = SRP_NG_2048;

    ber = ber_alloc_t(LBER_USE_DER);
    if (!ber)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

    major = ntlm_asn1_encode_mech_oid_token(
                &minor,
                ntlm_mech_oid,
                &asn1_ntlm_oid);
    if (major)
    {
        goto error;
    }

    major = gss_display_name(&minor, auth_name, &export_name_buf, &export_OID);
    if (major)
    {
        goto error;
    }
    export_name = &export_name_buf;

    export_name_str = calloc(export_name_buf.length+1, sizeof(char));
    if (!export_name_str)
    {
        minor = ENOMEM;
        major = GSS_S_FAILURE;
        goto error;
    }

    /* This is a '\0' terminated string */
    memcpy(export_name_str, export_name_buf.value, export_name_buf.length);

    /*
     * Lower case UPN name to match NTLM secret generated by vmdir.
     * This is sematically wrong for vmdir to do this, but the UPN
     * case must match for the NTLM values to match.
     */
    for (i=0; i<export_name_buf.length; i++)
    {
        export_name_str[i] = (char) tolower((int) export_name_str[i]);
    }

    /* The caller constructs this as a '\0' terminated string */
    password = auth_password->value;
    usr = srp_user_new(SRP_SHA1, ng_type,
                         export_name_str,
                         (const unsigned char *)password,
                         (int) strlen(password), NULL, NULL);
    if (!usr)
    {
        ntlm_debug_printf("srp_user_new: failed!\n");
        major = GSS_S_FAILURE;
        return(EXIT_FAILURE);
    }
    ntlm_context_handle->upn_name = export_name_str;

    /* User -> Host: (username, bytes_A) */
    srp_user_start_authentication(usr,
                                  &ntlm_auth_user,
                                  &ntlm_bytes_A,
                                  &ntlm_bytes_A_len);
    if (!ntlm_auth_user || !ntlm_bytes_A || ntlm_bytes_A_len == 0)
    {
        ntlm_debug_printf("srp_user_start_authentication: failed!\n");
        major = GSS_S_FAILURE;
        return(EXIT_FAILURE);
    }

ntlm_print_hex(ntlm_bytes_A, ntlm_bytes_A_len, "_ntlm_gss_make_auth_init_output_token(init_sec_context): bytes_A");
    /*
     * ASN.1 encode the following data:
     * |- GSS_NTLM_OID -|-State TAG-|-State Data 1-|-...-|-State Data N-|
     * |- GSS_NTLM_OID -|-NTLM_INIT(1)-|-UPN(octet string)-|-NTLM-bytes_A-|
     * Note: Use octet string for upn_string; o is octet string, i is length
     *       describing string length to ASN.1 encoder.
     */
    berror = ber_printf(ber, "t{oo}",
                  (int) NTLM_AUTH_INIT,
                  ntlm_auth_user,
                  export_name_buf.length,
                  ntlm_bytes_A,
                  ntlm_bytes_A_len);

    if (berror == -1)
    {
        major = GSS_S_FAILURE;
        goto error;
    }
    ber_len = berror;


    major = __ntlm_ber_flatten_output_token(
                &minor,
                ber,
                ber_len,
                &asn1_ntlm_oid,
                output_token);
    if (major)
    {
        goto error;
    }

    /* Save the srp_user_new() context in the ntlm_gss_ctx... handle */
    ntlm_context_handle->ntlm_usr = usr;

error:
    if (major)
    {
        *minor_status = minor;
    }
    if (export_name)
    {
        gss_release_buffer(&minor, export_name);
    }
    if (asn1_ntlm_oid.value)
    {
        gss_release_buffer(&minor, &asn1_ntlm_oid);
    }
    ber_free(ber, 1);
    return major;
}

static
OM_uint32
_ntlm_auth_salt_resp(
    OM_uint32 *minor_status,
    gss_OID ntlm_mech_oid,
    ntlm_gss_ctx_id_t ntlm_context_handle,
    int state,
    gss_buffer_t input_token,
    gss_buffer_t output_token)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    ber_tag_t ber_state = 0;
    struct berval ber_in_tok = {0};
    BerElement *ber_resp = NULL;
    ber_tag_t berror = 0;
    struct berval *ber_mda = NULL;
    struct berval *ber_salt = NULL;
    struct berval *ber_B = NULL;
    const unsigned char *ntlm_bytes_M = NULL;
    int ntlm_bytes_M_len = 0;
    int ntlm_session_key_len = 0;
    gss_buffer_desc asn1_ntlm_oid = {0};
    BerElement *ber = NULL;
    int ber_len = 0;
    const unsigned char *ntlm_session_key = NULL;

    ber_in_tok.bv_len = input_token->length;
    ber_in_tok.bv_val = input_token->value;
    ber_resp = ber_init(&ber_in_tok);
    berror = ber_scanf(ber_resp, "t{OOO}",
                 &ber_state, &ber_mda, &ber_salt, &ber_B);
    if (berror == LBER_ERROR)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

#if 1
ntlm_print_hex(ber_salt->bv_val, (int) ber_salt->bv_len, "_ntlm_auth_salt_resp(init_sec_context): salt");
ntlm_print_hex(ber_B->bv_val, (int) ber_B->bv_len, "_ntlm_auth_salt_resp(init_sec_context): bytes_B");
#endif

    /* Consistency check, this must match state */
    if ((int) ber_state != state)
    {
        major = GSS_S_FAILURE;
        goto error;
    }
    srp_user_process_challenge(ntlm_context_handle->ntlm_usr,
                               ber_salt->bv_val, (int) ber_salt->bv_len,
                               ber_B->bv_val, (int) ber_B->bv_len,
                               &ntlm_bytes_M, &ntlm_bytes_M_len);

    ntlm_session_key = srp_user_get_session_key(
                          ntlm_context_handle->ntlm_usr,
                          &ntlm_session_key_len);
    if (ntlm_session_key && ntlm_session_key_len > 0)
    {
        ntlm_context_handle->ntlm_session_key =
            calloc(ntlm_session_key_len, sizeof(unsigned char));
        if (!ntlm_context_handle->ntlm_session_key)
        {
            minor = ENOMEM;
            major = GSS_S_FAILURE;
            goto error;
        }
        memcpy(ntlm_context_handle->ntlm_session_key,
               ntlm_session_key,
               ntlm_session_key_len);
        ntlm_context_handle->ntlm_session_key_len = ntlm_session_key_len;
#if 1
/* TBD: Adam debuging only */
        ntlm_print_hex(ntlm_context_handle->ntlm_session_key,
                      ntlm_context_handle->ntlm_session_key_len,
                      "_ntlm_auth_salt_resp(init_sec_ctx) got session key");
#endif
    }


    ber = ber_alloc_t(LBER_USE_DER);
    if (!ber)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

    major = ntlm_asn1_encode_mech_oid_token(
                &minor,
                ntlm_mech_oid,
                &asn1_ntlm_oid);
    if (major)
    {
        goto error;
    }

    /* ASN.1 encode the following data:
     * |- GSS_NTLM_OID -|-State TAG-|-State Data 1-|-...-|-State Data N-|
     * |- GSS_NTLM_OID -|-NTLM_AUTH_CLIENT_VALIDATE(1)-|-NTLM-bytes_A-|
     * Note: Use octet string for upn_string; o is octet string, i is length
     *       describing string length to ASN.1 encoder.
     */

#if 1 /* TBD: debug */
ntlm_print_hex(ntlm_bytes_M, ntlm_bytes_M_len,
              "_ntlm_auth_salt_resp(init_sec_ctx) sending bytes_M");
#endif

    berror = ber_printf(ber, "t{o}",
                  (int) NTLM_AUTH_CLIENT_VALIDATE,
                  ntlm_bytes_M,
                  ntlm_bytes_M_len);

    if (berror == -1)
    {
        major = GSS_S_FAILURE;
        return(EXIT_FAILURE);
    }
    ber_len = berror;

    major = __ntlm_ber_flatten_output_token(
                &minor,
                ber,
                ber_len,
                &asn1_ntlm_oid,
                output_token);
    if (major)
    {
        goto error;
    }

error:
    if (major)
    {
        *minor_status = minor;
    }

    if (ber_mda)
    {
        ber_bvfree(ber_mda);
    }
    if (ber_salt)
    {
        ber_bvfree(ber_salt);
    }
    if (ber_B)
    {
        ber_bvfree(ber_B);
    }
    if (asn1_ntlm_oid.value)
    {
        gss_release_buffer(&minor, &asn1_ntlm_oid);
    }
    ber_free(ber_resp, 1);
    ber_free(ber, 1);

    return major;
}


static
OM_uint32
_ntlm_auth_server_validate(
    OM_uint32 *minor_status,
    gss_OID ntlm_mech_oid,
    ntlm_gss_ctx_id_t ntlm_context_handle,
    int state,
    gss_buffer_t input_token,
    gss_buffer_t output_token)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    int berror = 0;
    ber_tag_t ber_state = 0;
    BerElement *ber = NULL;
    struct berval *ber_ntlm_bytes_HAMK = NULL;
    struct berval ber_ctx = {0};

    ber_ctx.bv_val = (void *) input_token->value;
    ber_ctx.bv_len = input_token->length;
    ber = ber_init(&ber_ctx);
    if (!ber)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

    ntlm_debug_printf("_ntlm_auth_server_validate(): "
                     "state=NTLM_AUTH_CLIENT_VALIDATE\n");

    /*
     * ASN.1 decode the "HAMK" server mutual auth token
     */
    berror = ber_scanf(ber, "t{O}", &ber_state, &ber_ntlm_bytes_HAMK);
    if (berror == -1)
    {
        major = GSS_S_FAILURE;
        minor = EINVAL; /* TBD: Adam, return a real error code here */
        goto error;
    }

    /*
     * This is mostly impossible, as state IS the "t" field.
     * More a double check for proper decoding.
     */
    if ((int) ber_state != state || ber_ntlm_bytes_HAMK->bv_len == 0)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

    ntlm_print_hex(
        ber_ntlm_bytes_HAMK->bv_val,
        (int) ber_ntlm_bytes_HAMK->bv_len,
        "_ntlm_auth_server_validate(accept_sec_ctx) received ber_ntlm_bytes_HAMK");

    srp_user_verify_session(
        ntlm_context_handle->ntlm_usr,
        ber_ntlm_bytes_HAMK->bv_val);
    if (!srp_user_is_authenticated(ntlm_context_handle->ntlm_usr))
    {
        major = GSS_S_FAILURE;
        goto error;
    }


error:

    /* Free a bunch of stuff ... */
    if (ber_ntlm_bytes_HAMK)
    {
        ber_bvfree(ber_ntlm_bytes_HAMK);
    }


    ber_free(ber, 1);
    if (major)
    {
        if (minor)
        {
            *minor_status = minor;
        }
    }

    return major;
}


/*
 * Message format for generated output token (state dependent)
 * |- ASN.1 NTLM OID -|- state -|- data -|- ... -|
 *
 *
 * NTLM_AUTH_INIT: | ASN.1 NTLM OID | NTLM_AUTH_INIT (byte) | UPN (type GSS_KRB5_NT_PRINCIPAL_NAME) |
 *
 */
OM_uint32
ntlm_gss_init_sec_context(
    OM_uint32 *minor_status,
    gss_cred_id_t claimant_cred_handle,
    gss_ctx_id_t *context_handle,
    gss_name_t target_name,
    gss_OID mech_type,
    OM_uint32 req_flags,
    OM_uint32 time_req,
    gss_channel_bindings_t input_chan_bindings,
    gss_buffer_t input_token,
    gss_OID *actual_mech,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec)
{
    /*
     * send_token is used to indicate in later steps
     * what type of token, if any should be sent or processed.
     * NO_TOKEN_SEND = no token should be sent
     * INIT_TOKEN_SEND = initial token will be sent
     * CONT_TOKEN_SEND = continuing tokens to be sent
     * CHECK_MIC = no token to be sent, but have a MIC to check.
     */
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    unsigned char *ptr = NULL;
    OM_uint32 state = 0;
    ntlm_gss_cred_id_t ntlm_cred = NULL;
    ntlm_gss_ctx_id_t ntlm_context_handle = NULL;
    gss_buffer_desc output_token_mem = {0};
    krb5_error_code krb5_err = 0;
    gss_OID ntlm_mech_oid = {0};
    int iv_len = 0;

    dsyslog("Entering init_sec_context\n");

    if (!claimant_cred_handle || !context_handle)
    {
        major = GSS_S_FAILURE;
        goto error;
    }

    ntlm_cred = (ntlm_gss_cred_id_t) claimant_cred_handle;
    ntlm_mech_oid = ntlm_cred->ntlm_mech_oid;

    /* First call to init_sec_context; allocate new context */
    if (*context_handle == GSS_C_NO_CONTEXT)
    {
        state = NTLM_AUTH_INIT;
        ntlm_debug_printf("ntlm_gss_init_sec_context: state=NTLM_AUTH_INIT\n");
        ntlm_context_handle =
            (ntlm_gss_ctx_id_t) xmalloc(sizeof(ntlm_gss_ctx_id_rec));
        if (!ntlm_context_handle)
        {
            minor = ENOMEM;
            major = GSS_S_FAILURE;
            goto error;
        }
        memset(ntlm_context_handle, 0, sizeof(ntlm_gss_ctx_id_rec));

        major = ntlm_gss_duplicate_oid(&minor,
                                      ntlm_mech_oid,
                                      &ntlm_context_handle->mech);
        if (major)
        {
            goto error;
        }
        ntlm_context_handle->magic_num = NTLM_MAGIC_ID;
        ntlm_context_handle->state     = state;
        ntlm_context_handle->cred      = ntlm_cred;

        /* Needed for Kerberos AES256-SHA1 keyblock generation */
        krb5_err = krb5_init_context(&ntlm_context_handle->krb5_ctx);
        if (krb5_err)
        {
            major = GSS_S_FAILURE;
            minor = krb5_err;
            goto error;
        }

        major = _ntlm_gss_make_auth_init_output_token(
                    &minor,
                    ntlm_mech_oid,
                    ntlm_cred->name,
                    ntlm_cred->password,
                    ntlm_context_handle,
                    &output_token_mem);
        if (major)
        {
            goto error;
        }
        ntlm_context_handle->state = NTLM_AUTH_SALT_RESP;
        *context_handle = (gss_ctx_id_t) ntlm_context_handle;
        ntlm_context_handle = NULL;
        major = GSS_S_CONTINUE_NEEDED;
    }
    else
    {
        ntlm_context_handle = (ntlm_gss_ctx_id_t) *context_handle;
        if (!input_token)
        {
            major = GSS_S_FAILURE;
            goto error;
        }
        ptr = input_token->value;

        /* Verify state machine is consistent with expected state */
        state = NTLM_AUTH_STATE_VALUE(ptr[0]);
        if (state != ntlm_context_handle->state)
        {
            major = GSS_S_FAILURE;
            goto error;
        }

        ntlm_context_handle->state = state;
        switch (ntlm_context_handle->state)
        {
          case NTLM_AUTH_SALT_RESP:
            ntlm_debug_printf("ntlm_gss_init_sec_context: "
                             "state=NTLM_AUTH_SALT_RESP\n");
            major = _ntlm_auth_salt_resp(
                         &minor,
                         ntlm_mech_oid,
                         ntlm_context_handle,
                         ntlm_context_handle->state,
                         input_token,
                         &output_token_mem);
            if (major)
            {
                goto error;
            }

            ntlm_context_handle->state = NTLM_AUTH_SERVER_VALIDATE;
            major = GSS_S_CONTINUE_NEEDED;
            break;

          case NTLM_AUTH_SERVER_VALIDATE:
            ntlm_debug_printf("ntlm_gss_init_sec_context: "
                             "state=NTLM_AUTH_SERVER_VALIDATE\n");
            major = _ntlm_auth_server_validate(
                         &minor,
                         ntlm_mech_oid,
                         ntlm_context_handle,
                         ntlm_context_handle->state,
                         input_token,
                         &output_token_mem);
            if (major)
            {
                ntlm_debug_printf("ntlm_gss_init_sec_context: "
                                 "state=NTLM_AUTH_FAILED!!!\n");
                ntlm_context_handle->state = NTLM_AUTH_FAILED;
                major = GSS_S_FAILURE;
            }
            else
            {
                ntlm_debug_printf("ntlm_gss_init_sec_context: "
                                 "state=NTLM_AUTH_COMPLETE!!!\n");
                ntlm_context_handle->state = NTLM_AUTH_COMPLETE;
                memset(&output_token_mem, 0, sizeof(output_token_mem));
                major = GSS_S_COMPLETE;
            }
            break;

          case NTLM_AUTH_COMPLETE:
            major = GSS_S_COMPLETE;
          break;

          case NTLM_AUTH_FAILED:
            ntlm_debug_printf("ntlm_gss_init_sec_context: "
                             "state=NTLM_AUTH_FAILED!!!\n");
            major = GSS_S_FAILURE;
          break;

          default:
            ntlm_debug_printf("ntlm_gss_init_sec_context: "
                             "state=UNKNOWN!!!\n");
            major = GSS_S_FAILURE;
            break;
        }
    }

    *output_token = output_token_mem;

    if (major == GSS_S_COMPLETE)
    {
        krb5_err = ntlm_make_enc_keyblock(ntlm_context_handle);
        if (krb5_err)
        {
            major = GSS_S_FAILURE;
            minor = krb5_err;
            goto error;
        }
        if (actual_mech)
        {
            *actual_mech = ntlm_mech_oid;
        }
        AES_set_encrypt_key(
            ntlm_context_handle->keyblock->contents,
            ntlm_context_handle->keyblock->length * 8,
            &ntlm_context_handle->aes_encrypt_key);
        AES_set_decrypt_key(
            ntlm_context_handle->keyblock->contents,
            ntlm_context_handle->keyblock->length * 8,
            &ntlm_context_handle->aes_decrypt_key);

        iv_len = (AES_BLOCK_SIZE < ntlm_context_handle->ntlm_session_key_len) ?
                     AES_BLOCK_SIZE : ntlm_context_handle->ntlm_session_key_len;
        memset(ntlm_context_handle->aes_encrypt_iv, 0, iv_len);
        memcpy(ntlm_context_handle->aes_encrypt_iv,
               ntlm_context_handle->ntlm_session_key,
               iv_len);

        memset(ntlm_context_handle->aes_decrypt_iv, 0, iv_len);
        memcpy(ntlm_context_handle->aes_decrypt_iv,
               ntlm_context_handle->ntlm_session_key,
               iv_len);


    }
    else if (major == GSS_S_CONTINUE_NEEDED && actual_mech)
    {
        *actual_mech = ntlm_mech_oid;
    }

error:

    /* Free a bunch of stuff ... */
    if (major)
    {
        if (minor)
        {
            *minor_status = minor;
        }
    }

    return major;
} /* init_sec_context */
