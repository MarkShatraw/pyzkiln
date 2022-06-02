"""
  uadmin.py - Python interface to the RACF R_admin user administration functions

  Author: Joe Bostian
  Copyright Contributors to the Ambitus Project.
  SPDX-License-Identifier: Apache-2.0
"""
import json
import re

import py_racf
import r_admin


# Input to the profile extract functions of R_admin.  All the extract functions
# share this set of call parameters.  These map into the input/output parameter
# list of IRRSEQ00.  
class Uadmin:
    def __init__(self, racf=None, radmin=None, func_type=None):
        print('Uadmin constructor')
        print('inside UADMIN')
        if racf is not None:
            self.racf = racf
        else:
            print('Error - missing ancestor object')
            raise Exception
        if radmin is not None:
            self.radmin = radmin
        else:
            print('Error - missing ancestor object')
            raise Exception
        self.set_function(func_type)
        self.racf.log.debug('Uadmin init')
        if self.func_type is not None:
            self.racf.log.debug('    func_type: (0x%02x)' % self.func_type)
        return

    def set_function(self, func_type):
        if func_type == None:
            return None
        elif func_type == r_admin.ADMIN_ADD_USER:
            self.func_type = r_admin.ADMIN_ADD_USER
            self.fgrp = r_admin.ADMIN_GRP_UADMIN
        return
        

    def set_user_traits(self, traits, password):
        self.parms = traits
        if 'userid' not in traits:
            print('Error - must provide "userid" as dictionary key')
            raise Exception
        self.name = traits['name']
        self.verify_username(traits['userid'])
        self.userid = traits['userid']
        self.verify_password(password)
        self.password = password
        print(self.name)
        print(self.userid)
        print(self.password)
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
    
    def run(self):
        self.racf.log.debug('Uadmin run')
        self.racf.log.debug('    Call data file: %s' %
                            (self.racf.request_df.get_name()))
        self.racf.log.debug('    Return data file: %s' %
                            (self.racf.results_df.get_name()))

        # Collect any parms from the parent function (R_admin) that the user
        # may have set, and assemble them into the input parameter json file
        # that gets passed to the C code.
        call_parms = self.radmin.bld_request()
        call_parms = call_parms + '            "func":\n'
        call_parms = call_parms + json.dumps(self.traits, indent=16) + '\n'
        call_parms = call_parms + '        }\n'
        call_parms = call_parms + '    }\n'
        call_parms = call_parms + '}\n'
        self.racf.log.debug('    parms built, write to %s' %
                            (self.racf.request_df.get_name()))
# Write the parms to the request data file.  We're using this like a
        # pipe, but are using a regular file instead to avoid inherent
        # limitations on the length of data being passed.  Requests to RACF
        # aren't generally that long, but results from RACF can be very verbose.
        self.racf.request_df.open('w')
        self.racf.request_df.write(call_parms)
        self.racf.request_df.close()

        # Call the C interface to the profile extract function of the R_admin
        # service.  Pass in the name of the request and results files.
        self.racf.libracf.r_admin.restype = C.c_int
        self.racf.libracf.r_admin.argtypes = [C.c_char_p, C.c_char_p, C.c_int]
        request_fn = C.c_char_p(bytes(self.racf.request_df.get_name(),
                                'ISO8859-1'))
        results_fn = C.c_char_p(bytes(self.racf.results_df.get_name(),
                                'ISO8859-1'))
        f_debug = C.c_int(self.racf.get_debug())
        rc = self.racf.libracf.r_admin(request_fn, results_fn, f_debug)

        # Read and parse the results to return to the caller.
        return self.racf.get_results()

