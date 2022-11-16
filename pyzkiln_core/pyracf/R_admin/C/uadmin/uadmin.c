//
// R_Admin Profile extract methods
//
// Support for extracting profiles for one of the following kinds of resources:
// - encrypted password envelope, password phrase envelope
// - user, next user
// - group, next group
// - user and group connections
// - general resource, next general resource
//
// All of these functions return profiles of similar structure and form.
//
// Note that we're assigning distinct meaning to the terms "ARG" and "PARM" 
// here.  The RACF interface requires a "parm_list" argument, which is distinct
// from the arguments that are passed in on the call.
//
// Also note that live parsing editors don't generally understand the __ptr32
// qualifier on pointer declarations.  They will flag errors in the code that 
// the xl/C compiler on z/OS process correctly.
//
// Author: Joe Bostian
// Copyright Contributors to the Ambitus Project.
// SPDX-License-Identifier: Apache-2.0 
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>

#include "irrpcomp.h"
#include "r_admin.h"
#include "uadmin.h"
#include "transcode.h"
#include "log.h"
#include "dump.h"

// Constants for calling the R_admin interface.
const unsigned int ALET = 0x00000000;  // primary address space
const unsigned int ACEE = 0x00000000;
const unsigned char OUTBUF_SUBPOOL = 127;


// Local prototypes
static UADMIN_UNDERBAR_ARG_AREA_T * __ptr32 alloc_31bit_area(UADMIN_CTL_T *);
RC build_31bit_args(UADMIN_CTL_T *, R_ADMIN_CTL_T *);
UADMIN_CTL_T *uadmin_init(LOGGER_T *);
UADMIN_CTL_T *uadmin_term(UADMIN_CTL_T *);
// Glue code to call R_admin (IRRSEQ00).
int callRadmin(UADMIN_CALL_ARGS_LIST_T * __ptr32);


// -----------------------------------------------------------------------
// Mainline code
// -----------------------------------------------------------------------
KV_CTL_T *uadmin_run(R_ADMIN_CTL_T *pRACtl, LOGGER_T *pLog)
   {
    UADMIN_CTL_T *pUADMINCtl = uadmin_init(pLog);
    KV_CTL_T   *pKVCtl_res = NULL;

    if (pUADMINCtl != NULL)
       {
        RC rc = build_31bit_args(pUADMINCtl, pRACtl);

        if (rc == SUCCESS)
           {
            UADMIN_UNDERBAR_ARG_AREA_T * __ptr32 p31 = pUADMINCtl->pP31Area;

            log_debug(pRACtl->pLog, "31-bit args are built, call RACF ...");
            rc = callRadmin((UADMIN_CALL_ARGS_LIST_T * __ptr32)&(p31->arg_list));

            if ((!rc) &&
                (!p31->args.SAF_rc) &&
                (!p31->args.RACF_rc) && (!p31->args.RACF_rsn))
               {
                log_debug(pUADMINCtl->pLog, "Woo Hoo, got requested profile");
                log_debug(pUADMINCtl->pLog, "Build KV list for results");
                // dump_mem((BYTE *)p31->args.pOutbuf, sizeof(R_ADMIN_UADMIN_PARMS_T)+32,
                //          CCSID_EBCDIC, pRACtl->pLog);
                pKVCtl_res = uadmin_results_to_kv(pUADMINCtl, (R_ADMIN_UADMIN_PARMS_T *)p31->args.pOutbuf);
                log_set_name(pUADMINCtl->pLog, "uadmin");
               }

            else
               {
                log_debug(pUADMINCtl->pLog, "Error, R_admin request failed.");
                log_debug(pUADMINCtl->pLog, "   rc: %08d", rc);
                log_debug(pUADMINCtl->pLog, "   SAF_rc: %08d", p31->args.SAF_rc);
                log_debug(pUADMINCtl->pLog, "   RACF_rc: %08d, RACF_rsn: %08d",
                          p31->args.RACF_rc, p31->args.RACF_rsn);
                if (!rc)
                   rc = FAILURE;
               }

           }

       }

    // Clean up
    uadmin_term(pUADMINCtl);
    return pKVCtl_res;
   }                                   // uadmin_run

// -----------------------------------------------------------------------
// Subroutines
// -----------------------------------------------------------------------
UADMIN_CTL_T *uadmin_init(LOGGER_T *pLog)
   {
    UADMIN_CTL_T *pUADMINCtl = calloc(1, sizeof(UADMIN_CTL_T));

    if (pUADMINCtl != NULL)
       {
        pUADMINCtl->pLog = pLog;
        log_set_name(pUADMINCtl->pLog, "uadmin");

        // Allocate an area in 31-bit addressable memory for calling IRRSEQ00.
        // We will want to calculate the size of the 31 bit area later, but 
        // for now let's just allocate enough space to get everything working.
        pUADMINCtl->lP31Area = 4096;
        pUADMINCtl->pP31Area = alloc_31bit_area(pUADMINCtl);

        if (pUADMINCtl->pP31Area == NULL)
           pUADMINCtl = uadmin_term(pUADMINCtl);
       }

    return pUADMINCtl;
   }                                   // uadmin_init

UADMIN_CTL_T *uadmin_term(UADMIN_CTL_T *pUADMINCtl)
   {
    // TODO: A stub needs to be written to invoke FREEMAIN or STORAGE(RELEASE) for
    // outbuf, since it is not heap-managed storage.
    if (pUADMINCtl->pP31Area)
       free(pUADMINCtl->pP31Area); 
    return NULL;
   }                                   // uadmin_term

// Allocate an area in 31-bit addressable memory for the args to call IRRSEQ00.
static UADMIN_UNDERBAR_ARG_AREA_T * __ptr32 alloc_31bit_area(UADMIN_CTL_T *pUADMINCtl)
   {
    UADMIN_UNDERBAR_ARG_AREA_T * __ptr32 p31;

    log_debug(pUADMINCtl->pLog, "Allocate 31-bit arg area");
    p31 = __malloc31(pUADMINCtl->lP31Area);
   
    if (p31 != NULL)
       memset(p31, 0, pUADMINCtl->lP31Area);

    else
       {
        int e = errno;
        log_error(pUADMINCtl->pLog, "Cannot allocate 31-bit argument area");
        log_error(pUADMINCtl->pLog, "   errno: %08d\n", e);
        log_error(pUADMINCtl->pLog, "   %s\n", strerror(e));
       }

    return p31;
   }                                   // alloc_31bit_area

// Build the args in the 31-bit addressable area for alling IRRSEQ00.
RC build_31bit_args(UADMIN_CTL_T *pUADMINCtl, R_ADMIN_CTL_T *pRACtl)
   {
    UADMIN_UNDERBAR_ARG_AREA_T * __ptr32 p31 = pUADMINCtl->pP31Area;
    KV_CTL_T *pKVCtl_req = ra_get_kvctl(pRACtl, KV_REQ);
    RC        rc = SUCCESS;
    char      EBC_eyecatcher[4];

    log_debug(pUADMINCtl->pLog, "Build args in 31-bit area");

    if (pKVCtl_req != NULL)
       {
        KV_T     *pKV = kv_get_list(pKVCtl_req);
        KVV_T *pKVVal;

        // Set the input arg values to pass to R_admin.
        p31->args.ALET_SAF_rc    = ALET;
        p31->args.ALET_RACF_rc   = ALET;
        p31->args.ALET_RACF_rsn  = ALET;
        p31->args.func_code      = pRACtl->iFunc_type;
        p31->args.ACEE           = ACEE;
        p31->args.outbuf_subpool = OUTBUF_SUBPOOL;

        // Dump key value structure
        kv_print(pKVCtl_req);

        // Build segments
        uadmin_kv_to_segments(
            (R_ADMIN_UADMIN_PARMS_T *) &(p31->args.uadmin_parms), 
            (KV_CTL_T *)pKVCtl_req, 
            (LOGGER_T *)pUADMINCtl->pLog
         );

        // Now build a 31-bit argument list so that we can make the transition from
        // 64-bit XPLINK to 31-bit OSLINK.
        p31->arg_list.pWork_area = (char * __ptr32)&p31->args.RACF_work_area;
        p31->arg_list.pALET_SAF_rc = &(p31->args.ALET_SAF_rc);
        p31->arg_list.pSAF_rc = &(p31->args.SAF_rc);
        p31->arg_list.pALET_RACF_rc = &(p31->args.ALET_RACF_rc);
        p31->arg_list.pRACF_rc = &(p31->args.RACF_rc);
        p31->arg_list.pALET_RACF_rsn = &(p31->args.ALET_RACF_rsn);
        p31->arg_list.pRACF_rsn = &(p31->args.RACF_rsn);

        p31->arg_list.pFunc_code = &(p31->args.func_code);
        p31->arg_list.pUADMIN_parms = &(p31->args.uadmin_parms);
        p31->arg_list.pACEE = &(p31->args.ACEE);
        p31->arg_list.pOutbuf_subpool = &(p31->args.outbuf_subpool);
        p31->arg_list.ppOutbuf = &(p31->args.pOutbuf);

        // Turn on the high order bit of the last argument - marks the end of the
        // argument list.
        *((unsigned int *__ptr32)&p31->arg_list.ppOutbuf) |= 0x80000000;

        uadmin_dump_args_parms(pUADMINCtl, pUADMINCtl->pLog);
       }

    else
       {
        log_error(pUADMINCtl->pLog, "No input request to process.");
        return WARNING;
       }

    return rc;
   }