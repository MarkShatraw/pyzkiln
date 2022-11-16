//
// User administration output methods
//
// These are primarily debug routines for dumping out both the
// args and parms for calling RACF, and the output RACF returns.
//
// Author: Joe Bostian
// Copyright Contributors to the Ambitus Project.
// SPDX-License-Identifier: Apache-2.0 
//
#include <stdio.h>
#include <string.h>

#include "r_admin.h"
#include "uadmin.h"
#include "irrpcomp.h"
#include "transcode.h"

const iconv_t CD_NO_TRANSCODE  = (iconv_t)0x00000000;

// Local prototypes
void uadmin_print_segments(BYTE *, int, BYTE *, LOGGER_T *);
void* uadmin_print_fields(BYTE *, int, BYTE *, LOGGER_T *);
void uadmin_dump_segments(R_ADMIN_SDESC_T *, int, LOGGER_T *);
void uadmin_dump_fields(R_ADMIN_FDESC_T *, int, LOGGER_T *);
void uadmin_dump_args_parms(UADMIN_CTL_T *, LOGGER_T *);


//
// Formatted print of user administration function control blocks.
// This includes the returned parameters control block and all 
// associated segments and fields.  Note that this outputs a
// human-readable for of the output.  See the dump routines below
// for raw output of the ouptut from R_admin.
//
void uadmin_print(R_ADMIN_UADMIN_PARMS_T *pParms, LOGGER_T *pLog)
   {                                   // uadmin_print_output
    char userid[8];                    // vars for null-terminating strings
    BYTE *finger;                      // current memory location

    // clear userid buffer and copy userid as ASCII to it.
    memset(userid, 0, sizeof(userid));
    tc_e2a(pParms->userid, &(userid[0]), sizeof(pParms->userid), pLog);

    printf("User administration parms (%08x)\n", pParms);
    printf("   l_userid: %d\n",pParms->l_userid);
    printf("   userid: %s\n",userid);
    printf("   reserved: %d\n",pParms->rsv_1);
    printf("   off_seg_1: %d\n",pParms->off_seg_1);
    printf("   n_segs: %d\n",pParms->n_segs);

    // Set pointer to where the segments start
    // The segments start at the end of R_ADMIN_UADMIN_PARMS_T.
    finger = (BYTE *)pParms + sizeof(R_ADMIN_UADMIN_PARMS_T);

    uadmin_print_segments(finger, pParms->n_segs, (BYTE *)pParms, pLog);
   }                                   // uadmin_print_output

void uadmin_print_segments(BYTE *finger, int nSegments, BYTE *pParms, LOGGER_T *pLog)
   {                                   // uadmin_print_segments
    int i_seg = 1;
    char seg_name[9];                  // var for null-terminating strings
    UADMIN_SDESC_T *p_seg;             // pointer to field descriptor.

    // keep looping until there are no segments left.
    while(i_seg <= nSegments)
      {
       // Cast finger to a (UADMIN_SDESC_T)
       p_seg = (UADMIN_SDESC_T *)finger;

       // clear seg_name buffer and copy name as ASCII to it.
       memset(seg_name, 0, sizeof(seg_name));
       tc_e2a(p_seg->name, &(seg_name[0]), sizeof(p_seg->name), pLog);

       printf("Segment %d (UADMIN_SDESC_T)\n", i_seg);
       printf("   name:             %s\n",seg_name);
       printf("   flag:             %02x\n",p_seg->flag);
       printf("   num fields:       %d\n",p_seg->nFields);

       // For UADMIN, all of the fields associated with a segment follow follow it.
       // Set finger pointer to start of first field descriptor.
       finger += sizeof(UADMIN_SDESC_T);
       // Return value should be a pointer to the start of the next segment.
       finger = uadmin_print_fields(finger, p_seg->nFields, pParms, pLog);
       if (finger == NULL)
          log_error(pLog, "Something went wrong while creating segments.");
          return;
       i_seg++;
      }

   }                                   // uadmin_print_segments

void* uadmin_print_fields(BYTE* finger, int nFields, BYTE *pParms, LOGGER_T *pLog)
   {                                   // uadmin_print_fields
    int i_fld = 1;
    char fld_name[9];                  // var for null-terminating strings
    char * field_data;                 // pointer to field data in 31 bit area.
    char * field_data_tmp;             // pointer for temporary buffer used for displaying field data.
    UADMIN_FDESC_T * p_fld;            // pointer to field descriptor.        

    while(i_fld <= nFields)
      {
       // Cast finger to a (UADMIN_FDESC_T)
       p_fld = (UADMIN_FDESC_T *)finger;
       // Display field name
       // clear fld_name buffer and copy name as ASCII to it.
       memset(fld_name, 0, sizeof(fld_name));
       tc_e2a(p_fld->name, &(fld_name[0]), sizeof(p_fld->name), pLog);
       printf("Field %d (UADMIN_FDESC_T)\n", i_fld);
       printf("   name:  %s\n",fld_name);

       // Display flag
       printf("   flag: (%2x)",p_fld->flag);
       if (p_fld->flag == YES_FLAG) {
          printf("    YES");
       }
       else if (p_fld->flag == NO_FLAG) {
          printf("    NO");
       }
       else {
          printf("    ??");
       }
       printf("\n");
       printf("   l_data: %d\n", p_fld->l_data);
       if (p_fld->l_data != 0) {
          // Field data located at the end of the field descriptor.
          field_data = (char *)finger + sizeof(UADMIN_FDESC_T);
          // Create temporary buffer that is the size of field data plus one to make it null terminated.
          field_data_tmp = calloc(p_fld->l_data + 1, sizeof(char));
          if (field_data_tmp == NULL) 
             return NULL;
          // copy field_data to field_data_tmp as ASCII.
          tc_e2a(field_data, field_data_tmp, p_fld->l_data, pLog);
          printf("  data: %s\n", field_data_tmp);
          free(field_data_tmp);
       }
       else {
          printf("  data: N/A (boolean field only)\n");
       }
       // Set pointer to the beginning of the next field/segment descriptor.
       finger += sizeof(UADMIN_FDESC_T) + p_fld->l_data;
       i_fld++;
      }
   }                                   // uadmin_print_fields


// Raw dump of the profile extract function control blocks.
// This includes the returned parameters control block and all 
// associated segments and fields.  Note that this outputs a
// complete unformatted view of the output from R_admin.
void uadmin_dump(R_ADMIN_UADMIN_PARMS_T *pParms, LOGGER_T *pLog)
   {                                   // uadmin_dump_output
    BYTE *finger;                      // current memory location

    log_debug(pLog, "User administration parms (%08x)", pParms);
    log_debug(pLog, "  +0 l_userid:   %d",pParms->l_userid);
    log_debug(pLog, "  +1 userid:   %s",pParms->userid);
    log_debug(pLog, "  +9 reserved");
    log_debug(pLog, "  +10 off_seg_1:   %d",pParms->off_seg_1);
    log_debug(pLog, "  +12 n_segs:   %d",pParms->n_segs);

    dump_mem(pParms, 80, CCSID_EBCDIC, pLog);

    // Print all of the segments and associated fields.
    finger = (BYTE *)pParms + sizeof(R_ADMIN_UADMIN_PARMS_T);
    uadmin_dump_segments((R_ADMIN_SDESC_T	*)finger, pParms->n_segs, pLog);
   }                                   // uadmin_dump_output

void uadmin_dump_segments(R_ADMIN_SDESC_T *p_sdesc, int nSegments, LOGGER_T *pLog)
   {                                   // uadmin_dump_segments
    int i_seg = 1;
    char seg_name[9];                  // var for null-terminating strings
    R_ADMIN_SDESC_T *p_seg = p_sdesc;

    while(i_seg <= nSegments)
      {
       BYTE *finger = (BYTE *)p_seg + p_seg->off_fdesc_1;

       memset(seg_name, 0, sizeof(seg_name));
       strncpy(seg_name, p_seg->name, sizeof(p_seg->name));

       printf("Segment %d (R_ADMIN_SDESC_T)\n", i_seg);
       printf("   +0 name:        %s\n",seg_name);
       printf("   +8 flags:       %08x\n",p_seg->flags);
       printf("   +C nFields:    %d\n",p_seg->nFields);
       printf("  +10 reserved\n");
       printf("  +14 off_fdesc_1: %d\n",p_seg->off_fdesc_1);
       printf("  +18 reserved\n");

       // If this is the last segment, then fields follow immediately, 
       // otherwise, they are at the offset in this segment descriptor.
       if (i_seg <= nSegments)
          finger = (BYTE *)p_seg + sizeof(R_ADMIN_SDESC_T);
       else
          finger = (BYTE *)p_seg + p_seg->off_fdesc_1;
       uadmin_dump_fields((R_ADMIN_FDESC_T *)finger, p_seg->nFields, pLog);

       i_seg++;
       p_seg++;
      }

   }                                   // uadmin_dump_segments

void uadmin_dump_fields(R_ADMIN_FDESC_T *p_fdesc, int nFields, LOGGER_T *pLog)
   {                                   // uadmin_dump_fields
    int i_fld = 1;
    char fld_name[9];                  // var for null-terminating strings
    R_ADMIN_FDESC_T *p_fld = p_fdesc;

    while(i_fld <= nFields)
      {
       memset(fld_name, 0, sizeof(fld_name));
       strncpy(fld_name, p_fld->name, sizeof(p_fld->name));

       printf("Field %d (R_ADMIN_FDESC_T)\n", i_fld);
       printf("   +0 name:          %s\n",fld_name);
       printf("   +8 type:          %04x\n",p_fld->type);
       printf("   +A reserved\n");                        
       printf("   +C flags:         %08x\n",p_fld->flags);

       if (!(p_fld->type & t_repeat_field_hdr))
         printf("  +10 l_fld_data: %d\n",p_fld->len_rpt.l_fld_data);
       else
         printf("  +10 n_repeat_grps: %d\n",p_fld->len_rpt.n_repeat_grps);

       printf("  +14 reserved\n");

       if (!(p_fld->type & t_repeat_field_hdr))
         printf("  +18 off_fld_data:   %d\n",p_fld->off_rpt.off_fld_data);
       else
         printf("  +18 n_repeat_elems: %d\n",p_fld->off_rpt.n_repeat_elems);

       printf("  +1C reserved\n");

       i_fld++;
       p_fld++;
      }

   }                                   // uadmin_dump_fields

void uadmin_dump_args_parms(UADMIN_CTL_T *pUADMINCtl, LOGGER_T *pLog)
   {
    UADMIN_UNDERBAR_ARG_AREA_T * __ptr32 p31 = pUADMINCtl->pP31Area;

    log_debug(pLog, "---------------------------------------------");
    log_debug(pLog, "Args (%08x), p31: %08x:", &(p31->args), p31);
    log_debug(pLog, "  RACF_work_area p: %08x,  l: %d", &(p31->args.RACF_work_area), L_RACF_WORK_AREA);
    log_debug(pLog, "  SAF_rc,   ALET: %08x,  p: %08x", &(p31->args.ALET_SAF_rc), &(p31->args.SAF_rc));
    log_debug(pLog, "  RACF_rc,  ALET: %08x,  p: %08x", &(p31->args.ALET_RACF_rc), &(p31->args.RACF_rc));
    log_debug(pLog, "  RACF_rsn, ALET: %08x,  p: %08x", &(p31->args.ALET_RACF_rsn), &(p31->args.RACF_rsn));
    log_debug(pLog, "  func_code: %d,  p: %08x\n", p31->args.func_code, &(p31->args.func_code));

    uadmin_dump(&(p31->args.uadmin_parms), pLog);
   
    // log_debug(pLog, "  prof_name (%08x): %s", &(p31->args.prof_name.name), p31->args.prof_name.name);
    log_debug(pLog, "  ACEE (%08x): %08x", &(p31->args.ACEE), p31->args.ACEE);
    log_debug(pLog, "  outbuf_subpool (%08x): %d", &(p31->args.outbuf_subpool), p31->args.outbuf_subpool);
    log_debug(pLog, "  pOutbuf (%08x): %08x\n", &(p31->args.pOutbuf), p31->args.pOutbuf);

    log_debug(pLog, "Arg list (%08x):", &(pUADMINCtl->pP31Area->arg_list));
    log_debug(pLog, "  pWork_area:     %08x", p31->arg_list.pWork_area);
    log_debug(pLog, "  pALET_SAF_rc:   %08x,  pSAF_rc:   %08x", p31->arg_list.pALET_SAF_rc, p31->arg_list.pSAF_rc);
    log_debug(pLog, "  pALET_RACF_rc:  %08x,  pRACF_rc:  %08x", p31->arg_list.pALET_RACF_rc, p31->arg_list.pRACF_rc);
    log_debug(pLog, "  pALET_RACF_rsn: %08x,  pRACF_rsn: %08x", p31->arg_list.pALET_RACF_rsn, p31->arg_list.pRACF_rsn);
    log_debug(pLog, "  pFunc_code:  %08x", p31->arg_list.pFunc_code);
    log_debug(pLog, "  pUADMIN_parms: %08x", p31->arg_list.pUADMIN_parms);
    log_debug(pLog, "  pACEE:       %08x", p31->arg_list.pACEE);
    log_debug(pLog, "  pOutbuf_subpool:  %08x", p31->arg_list.pOutbuf_subpool);
    log_debug(pLog, "  ppOutbuf:  %08x", p31->arg_list.ppOutbuf);
    log_debug(pLog, "---------------------------------------------");
    return;
   }