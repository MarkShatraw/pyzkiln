#ifndef __UADMIN_H__
#define __UADMIN_H__
//
// Data shared between routines that make up the profile extact functions
// of the R_admin service call.
//
// Note that live parsing editors don't generally understand the __ptr32
// qualifier on pointer declarations.  They will flag errors in the code that 
// the xl/C compiler on z/OS process correctly.
//
// Author: Joe Bostian
// Copyright Contributors to the Ambitus Project.
// SPDX-License-Identifier: Apache-2.0
//
#include <iconv.h>

#include "irrpcomp.h"
#include "r_admin.h"
#include "keyval.h"
#include "common_types.h"

// Scaffolding for VSCode - it doesn't understand __ptr32.  Remove this before
// building the code lest ye waken a dragon.
// #define __ptr32

// Constants
#define L_RACF_WORK_AREA 1024

#pragma pack(1) // Make sure there is no padding in between fields in UADMIN_SDESC and UADMIN_FDESC.
// UADMIN Segment descriptor
typedef struct UADMIN_SDESC {
   char     name[8];                 // segment name, upper case, blank padded
   FLAG     flag;                    // EBCDIC byte 'Y' or 'N'
   USHORT   nFields;                 // number of fields
                                     // start of next segment descriptor
   } UADMIN_SDESC_T;

// UADMIN Field descriptor
typedef struct UADMIN_FDESC {
   char             name[8];     // field name, upper case, blank padded
   FLAG             flag;        // EBCDIC byte 'Y' or 'N'
   USHORT           l_data;      // size of data
                                 // variable length data
                                 // then start of next field descriptor
   } UADMIN_FDESC_T;
#pragma pack(pop) // Restore structure packing.

// We have to marshall our arguments into a 31-bit area that the RACF 
// interface can use.  Not only do the arguments have to live in this
// 31-bit area "under the bar", the argument list has to be there as
// well.
typedef struct UADMIN_CALL_ARGS {
   char RACF_work_area[L_RACF_WORK_AREA];

   int  ALET_SAF_rc;                   // return and reason codes
   RC   SAF_rc;
   int  ALET_RACF_rc;
   RC   RACF_rc;
   int  ALET_RACF_rsn;
   RSN  RACF_rsn;

   BYTE func_code;                     // user administration function to perform

   R_ADMIN_UADMIN_PARMS_T uadmin_parms;     // user administration parm area

   UINT ACEE;                          // output area for the service
   BYTE outbuf_subpool;

   char * __ptr32 pOutbuf;             // R_admin returns data here
   } UADMIN_CALL_ARGS_T;

// Normal OS linkage conventions require a list of pointers for the 
// argument list. This is what will be passed to RACF assembler service.
typedef struct UADMIN_CALL_ARGS_LIST {
   char * __ptr32 pWork_area;

   int *  __ptr32 pALET_SAF_rc;
   RC *   __ptr32 pSAF_rc;
   int *  __ptr32 pALET_RACF_rc;
   RC *   __ptr32 pRACF_rc;
   int *  __ptr32 pALET_RACF_rsn;
   RSN *  __ptr32 pRACF_rsn;

   BYTE * __ptr32 pFunc_code;

   R_ADMIN_UADMIN_PARMS_T * __ptr32 pUADMIN_parms;

   UINT * __ptr32 pACEE;
   BYTE * __ptr32 pOutbuf_subpool;
   char * __ptr32 * __ptr32 ppOutbuf;
   } UADMIN_CALL_ARGS_LIST_T;

// Base segment
typedef struct BASE_SEGMENT {
   KV_T * name;
   KV_T * password;
   KV_T * owner;
   KV_T * special;
} BASE_SEGMENT_T;

// OMVS segment
typedef struct OMVS_SEGMENT {
   KV_T * uid;
   KV_T * home;
   KV_T * program;
} OMVS_SEGMENT_T;

const FLAG YES_FLAG = 0xe8; // 'Y' in EBCDIC
const FLAG NO_FLAG = 0xd5;  // 'N' in EBCDIC

// A convenience method to group the allocation of all the required
// storage areas.
typedef struct UADMIN_UNDERBAR_ARG_AREA {
   UADMIN_CALL_ARGS_T args;
   UADMIN_CALL_ARGS_LIST_T arg_list;
   } UADMIN_UNDERBAR_ARG_AREA_T;

// The main user administration anchor block.
typedef struct UADMIN_CTL {
  UADMIN_UNDERBAR_ARG_AREA_T *pP31Area;
  int       lP31Area;
  LOGGER_T *pLog;
  } UADMIN_CTL_T;

// Main user administration method.
KV_CTL_T *uadmin_run(R_ADMIN_CTL_T *, LOGGER_T *);

// User administration to key-value list.
RC uadmin_kv_to_segments(R_ADMIN_UADMIN_PARMS_T *, KV_CTL_T *, LOGGER_T *);
KV_CTL_T *uadmin_results_to_kv(UADMIN_CTL_T *, R_ADMIN_UADMIN_PARMS_T *);

// User administration dump methods.
void uadmin_raw_dump(R_ADMIN_UADMIN_PARMS_T *);
void uadmin_print(R_ADMIN_UADMIN_PARMS_T *, LOGGER_T *);
void uadmin_dump(R_ADMIN_UADMIN_PARMS_T *, LOGGER_T *);
void uadmin_dump_args_parms(UADMIN_CTL_T *, LOGGER_T *);

#endif