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

// Local prototypes
void uadmin_print_segments(R_ADMIN_SDESC_T *, int, BYTE *, LOGGER_T *);
void uadmin_print_fields(R_ADMIN_FDESC_T *, int, BYTE *, LOGGER_T *);
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

    memset(userid, 0, sizeof(userid));
    strncpy(userid, pParms->userid, sizeof(pParms->userid));

    printf("User administration parms (%08x)\n", pParms);
    printf("   l_userid: %d\n",pParms->l_userid);
    printf("   userid: %s\n",userid);
    printf("   reserved: %d\n",pParms->rsv_1);
    printf("   off_seg_1: %d\n",pParms->off_seg_1);
    printf("   n_segs: %d\n",pParms->n_segs);

    // Set pointer to where the segments start
    // The segments start at the end of R_ADMIN_UADMIN_PARMS_T.
    finger = (BYTE *)pParms + sizeof(R_ADMIN_UADMIN_PARMS_T);

    uadmin_print_segments((R_ADMIN_SDESC_T *)finger, pParms->n_segs, (BYTE *)pParms, pLog);
   }                                   // uadmin_print_output

void uadmin_print_segments(R_ADMIN_SDESC_T *p_sdesc, int nSegments, BYTE *pParms, LOGGER_T *pLog)
   {                                   // uadmin_print_segments
    int i_seg = 1;
    char seg_name[9];                  // var for null-terminating strings
    R_ADMIN_SDESC_T *p_seg = p_sdesc;

    // keep looping until there are no segments left.
    while(i_seg <= nSegments)
      {
       BYTE *finger = (BYTE *)p_seg + p_seg->off_fdesc_1;

       memset(seg_name, 0, sizeof(seg_name));
       strncpy(seg_name, p_seg->name, sizeof(p_seg->name));

       printf("Segment %d\n", i_seg);
       printf("   name:             %s\n",seg_name);
       printf("   flags:            %08x\n",p_seg->flags);
       printf("   num fields:       %d\n",p_seg->nFields);
       printf("   off field desc 1: %d\n",p_seg->off_fdesc_1);

       // If this is the last segment, then fields follow immediately, 
       // otherwise, they are at the offset in this segment descriptor.
       if (i_seg <= nSegments)
          finger = (BYTE *)p_seg + sizeof(R_ADMIN_SDESC_T);
       else
          finger = (BYTE *)p_seg + p_seg->off_fdesc_1;
       uadmin_print_fields((R_ADMIN_FDESC_T *)finger, p_seg->nFields, pParms, pLog);

       i_seg++;
       p_seg++;
      }

   }                                   // uadmin_print_segments

void uadmin_print_fields(R_ADMIN_FDESC_T *p_fdesc, int nFields, BYTE *pParms, LOGGER_T *pLog)
   {                                   // uadmin_print_fields
    int i_fld = 1;
    char fld_name[9];                  // var for null-terminating strings
    R_ADMIN_FDESC_T *p_fld = p_fdesc;

    while(i_fld <= nFields)
      {
        printf("TODO");
        // TODO
        /*
       memset(fld_name, 0, sizeof(fld_name));
       strncpy(fld_name, p_fld->name, sizeof(p_fld->name));

       printf("Field %d (R_ADMIN_FDESC_T)\n", i_fld);
       printf("   name:  %s\n",fld_name);

       printf("   type: (%04x)  ",p_fld->type);
       if (p_fld->type & t_boolean_field)
         printf("  boolean");
       else
         printf("  character");
       if (p_fld->type & t_mbr_repeat_group)
         printf(", repeat group member ");
       if (p_fld->type & t_repeat_field_hdr)
         printf(", repeat field header ");
       printf("\n");

       printf("   flags: (%08x)",p_fld->flags);
       if (p_fld->flags & f_output_only)
          printf("    output only");
       printf("\n");

       if (p_fld->type & t_boolean_field)
         {                              // boolean field type
          if (p_fld->flags & f_boolean_field)
            printf("     TRUE\n");
          else
            printf("     FALSE\n");
         }                             // boolean field type

       else
         {                             // character field

          if (!(p_fld->type & t_repeat_field_hdr))
            {                          // single value field
             char content[1025];       // null-terminated string
             int l_content = sizeof(content);

             // Null-terminate, and clip the size of the content if necessary.
             memset(content, 0, sizeof(content));
             if (p_fld->len_rpt.l_fld_data < sizeof(content))
               l_content = p_fld->len_rpt.l_fld_data;
             strncpy(content, ((char *)pParms)+p_fld->off_rpt.off_fld_data, l_content);
             printf("   content: %s\n", content);
            }                          // single value field

          else
            {                          // repeating field
             printf("   num repeat grps:  %d\n",p_fld->len_rpt.n_repeat_grps);
             printf("   num repeat elems: %d\n",p_fld->off_rpt.n_repeat_elems);
            }                          // repeating field

         }                             // character field
        */

       i_fld++;
       p_fld++;
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
    UNDERBAR_ARG_AREA_T * __ptr32 p31 = pUADMINCtl->pP31Area;

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