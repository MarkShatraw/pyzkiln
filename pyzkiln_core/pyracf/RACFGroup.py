"""
  RACFGroup.py - Python representation of a RACF Group

  Author: Mark Shatraw
  Copyright Contributors to the Ambitus Project.
  SPDX-License-Identifier: Apache-2.0
"""
import os
import tempfile
import logging
import ctypes
import json

import r_admin

SUCCESS = 0x00000000
WARNING = 0x00000004
FAILURE = 0x00000008

# RACF callable services
CK_ACCESS = 0x01
CK_FILE_OWNER = 0x02
CK_IPC_ACCESS = 0x03
CK_OWNER_TWO_FILES = 0x04
CK_PRIV = 0x05
CK_PROCESS_OWNER = 0x06
CLEAR_SETID = 0x07
DELETEUSP = 0x08
GETGMAP = 0x09
GET_UID_GID_SUPGRPS = 0x10
GETUMAP = 0x11
INITACEE = 0x12
INITUSP = 0x13
MAKEFSP = 0x14
MAKEISP = 0x15
MAKE_ROOT_FSP = 0x16
QUERY_FILE_SECURITY_OPTIONS = 0x17
R_ADMIN = 0x18
R_AUDIT = 0x19
R_AUDITX = 0x20
R_CACHESERV = 0x21
R_CHAUDIT = 0x22
R_CHMOD = 0x23
R_CHOWN = 0x24
R_DATALIB = 0x25
R_DCEAUTH = 0x26
R_DCEINFO = 0x27
R_DCEKEY = 0x28
R_DCERUID = 0x29
R_EXEC = 0x30
R_FORK = 0x31
R_GENSEC = 0x32
R_GETGROUPS = 0x33
R_GETGROUPSBYNAME = 0x34
R_GETINFO = 0x35
R_IPC_CTL = 0x36
R_KERBINFO = 0x37
R_PGMSIGNVER = 0X38
R_PKISERV = 0x39
R_PROXYSERV = 0x40
R_PTRACE = 0x41
R_SETEGID = 0x42
R_SETEUID = 0x43
R_SETFACL = 0x44
R_SETFSECL = 0x45
R_SETGID = 0x46
R_SETUID = 0x47
R_TICKETSERV = 0x48
R_UMASK = 0x49
R_USERMAP = 0x50
R_WRITEPRIV = 0x51


# A RACF Group, represented in Python
class RACFGroup:
    def __init__(self, name, racf=None):
        if name is None:
            print('Error - Group must be specified with a name')
            raise Exception
        self.verify_name(self, name)
        self.name = name
        if racf is None:
            self.racf = Racf()
        else:
            self.racf = racf
        self.users = []
        return

    def verify_name(self, name):
        pass

    def add_user(self, user):
        users.append(user)
        user.add_to_group(self)
        return

    def remove_user(self, user):
        users.remove(user)
        user.add_to_group(self)
        return
