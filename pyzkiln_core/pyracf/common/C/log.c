//
// logger.c - logger in C that mirrors the function of the standard Python
//            logger.  Please try to keep the output generated by this logger
//            aligned with the logger we have set up in the main RACF Python class.
//
// Author: Joe Bostian
// Copyright Contributors to the Ambitus Project.
// SPDX-License-Identifier: Apache-2.0 
//
#define _ISOC99_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "log.h"
#include "common_types.h"


//
// Init and term.
//
LOGGER_T *logger_init(FLAG fDebug, char *pLog_name)
   {
    LOGGER_T *pLog = (LOGGER_T *)calloc(sizeof(LOGGER_T), 1);

    if (pLog)
       {
        log_set_debug(pLog, fDebug);
        log_set_name(pLog, pLog_name);

        // Set up an array of mnemonics for each of the logging types.
        BYTE *p = calloc((N_LOG_TYPES*L_LOG_TYPE), 1);

        if (p != NULL)
           {
            pLog->log_types[LOG_NONE] = (char *)p;

            strcpy(pLog->log_types[LOG_NONE], "NONE");
            pLog->log_types[LOG_DEBUG] = pLog->log_types[LOG_NONE] + L_LOG_TYPE;

            strcpy(pLog->log_types[LOG_DEBUG], "DEBUG");
            pLog->log_types[LOG_INFO] = pLog->log_types[LOG_DEBUG] + L_LOG_TYPE;

            strcpy(pLog->log_types[LOG_INFO], "INFO");
            pLog->log_types[LOG_WARNING] = pLog->log_types[LOG_INFO] + L_LOG_TYPE;

            strcpy(pLog->log_types[LOG_WARNING], "WARNING");
            pLog->log_types[LOG_ERROR] = pLog->log_types[LOG_WARNING] + L_LOG_TYPE;

            strcpy(pLog->log_types[LOG_ERROR], "ERROR");
            pLog->log_types[LOG_CRITICAL] = pLog->log_types[LOG_ERROR] + L_LOG_TYPE;

            strcpy(pLog->log_types[LOG_CRITICAL], "CRITICAL");
           }

       }

    else
        fprintf(stderr, "Error - C logging init failure (pLog).\n");
    return pLog;
   }                                   // logger_init

void logger_term(LOGGER_T *pLog)
   {
    free(pLog->log_types);
    free(pLog);
    return;
   }                                   // logger_term

void log_log(LOGGER_T *pLog, BYTE log_type, char *fmt_buf)
   {
    char time_buf[16];
    time_t utc_time = time(NULL);
    struct tm *pLocal_time = localtime(&utc_time);

    // Get the timestamp and printable log type for this message.
    strftime(time_buf, sizeof(time_buf)-1, "%H:%M:%S", pLocal_time);
    printf("%s [%s] - %s: %s\n", time_buf, pLog->log_name, pLog->log_types[log_type], fmt_buf);

    return;
   }                                   // log_log

void log_debug(LOGGER_T *pLog, const char *fmt_str, ...)
   {

    if (pLog->fDebug == ON)
       {
        va_list arg_lst;
        va_start(arg_lst, fmt_str);
        char prt_buf[vsnprintf(NULL, 0, fmt_str, arg_lst)+1];
        va_end(arg_lst);

        va_start(arg_lst, fmt_str);
        vsnprintf(prt_buf, sizeof(prt_buf), fmt_str, arg_lst);
        va_end(arg_lst);

        // Wrap the text in logging details and output.
        log_log(pLog, LOG_DEBUG, prt_buf);
       }

    return;
   }                                   // log_debug

void log_info(LOGGER_T *pLog, const char *fmt_str, ...)
   {
    va_list arg_lst;
    va_start(arg_lst, fmt_str);
    char prt_buf[vsnprintf(NULL, 0, fmt_str, arg_lst)+1];
    va_end(arg_lst);

    va_start(arg_lst, fmt_str);
    vsnprintf(prt_buf, sizeof(prt_buf), fmt_str, arg_lst);
    va_end(arg_lst);

    // Wrap the text in logging details and output.
    log_log(pLog, LOG_INFO, prt_buf);
    return;
   }

void log_warning(LOGGER_T *pLog, const char *fmt_str, ...)
   {
    va_list arg_lst;
    va_start(arg_lst, fmt_str);
    char prt_buf[vsnprintf(NULL, 0, fmt_str, arg_lst)+1];
    va_end(arg_lst);

    va_start(arg_lst, fmt_str);
    vsnprintf(prt_buf, sizeof(prt_buf), fmt_str, arg_lst);
    va_end(arg_lst);

    // Wrap the text in logging details and output.
    log_log(pLog, LOG_WARNING, prt_buf);
    return;
   }

void log_error(LOGGER_T *pLog, const char *fmt_str, ...)
   {
    va_list arg_lst;
    va_start(arg_lst, fmt_str);
    char prt_buf[vsnprintf(NULL, 0, fmt_str, arg_lst)+1];
    va_end(arg_lst);

    va_start(arg_lst, fmt_str);
    vsnprintf(prt_buf, sizeof(prt_buf), fmt_str, arg_lst);
    va_end(arg_lst);

    // Wrap the text in logging details and output.
    log_log(pLog, LOG_ERROR, prt_buf);
    return;
   }

void log_critical(LOGGER_T *pLog, const char *fmt_str, ...)
   {
    va_list arg_lst;
    va_start(arg_lst, fmt_str);
    char prt_buf[vsnprintf(NULL, 0, fmt_str, arg_lst)+1];
    va_end(arg_lst);

    va_start(arg_lst, fmt_str);
    vsnprintf(prt_buf, sizeof(prt_buf), fmt_str, arg_lst);
    va_end(arg_lst);

    // Wrap the text in logging details and output.
    log_log(pLog, LOG_INFO, prt_buf);
    return;
   }


//
// Getters and setters
//
void log_set_debug(LOGGER_T *pLog, FLAG fDebug)
   {
    if (pLog != NULL)
       pLog->fDebug = fDebug;
   }                                   // set_debug

void log_set_name(LOGGER_T *pLog, char *pLog_name)
   {

    if (pLog != NULL)
       {
        int lLog_name = (strlen(pLog_name) > (L_LOG_NAME-1)) ? L_LOG_NAME : strlen(pLog_name);
        memset(pLog->log_name, 0, L_LOG_NAME);
        strncpy(pLog->log_name, pLog_name, lLog_name);
       }

   }                                   // set_log_name