"""
  RACFUser.py - Python representation of RACF user

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
from py_racf import Racf

class RACFUser:
    def __init__(self, userid=None, traits=None, racf=None, password=None, build_user_from_extract=0):
        if racf is not None:
            self.racf = Racf()
        else:
            self.racf = racf
        self.racf.init_svc(py_racf.R_ADMIN)
        self.groups = []
        if build_user_from_extract=1 and userid is None:
            print('Error - must specify userid to be extracted')
            raise Exception
        elif build_user_from_extract=1 and userid is not None:
            if password is not None:
                self.verify_password(password)
                self.password = password
            self.verify_userid(self, userid)
            self.userid = userid
            self.build_extracted_user(self, userid, racf)
            return

        if traits is None and userid is None:
            print('Error - must specify userid or include traits with userid')
            raise Exception
        if userid is None and traits is not None and 'userid' not in traits:
            print('Error - must specify key "userid" in traits')
            raise Exception
        if traits is not None:
            self.verify_traits(traits, password)
        if userid is not None:
            self.verify_userid(self, userid)
            self.userid = userid
        return

    def verify_userid(self, userid):
        if len(userid) < 1 or len(userid) > 8:
            print('Error - userid length must be 1 to 8 characters')
            raise Exception
        if re.fullmatch(r'[a-zA-Z0-9$@#]{1,8}',userid) is None:
            print('Error - userid does not adhere to syntax rules')
            raise Exception
        return
    
    def verify_password(self, password):
        pass 

    def verify_traits(self, traits, password):
        self.verify_userid(traits['userid'])
        self.userid = traits['userid']
        self.verify_password(password)
        self.password = password
        return

    def add_user(self):
        self.racf.init_func(ADMIN_ADD_USER)
        if self.traits is not None:
            self.traits = {}
            traits['userid'] = self.userid
        self.racf.svc.func.set_user_traits(traits, password)
        rv = self.racf.svc.func.run()
        return

    def build_extracted_user(self, userid, racf):
        self.racf.init_func(ADMIN_XTR_USER)
        self.racf.svc.func.set_prof_name(userid)
        traits_to_extract = self.racf.svc.func.run()
        self.set_extracted_variables(self, traits_to_extract)
        return

    def set_extracted_variables(self, traits):
        self.userid = traits['profile']
        self.name = traits['base']['name']
        return

    def add_to_group(self, group):
        self.groups.append(group)
        return

    def remove_from_group(self, group):
        self.groups.remove(group)
        return
        

