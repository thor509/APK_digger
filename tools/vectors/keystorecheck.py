#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class KeystoreCheck(VulnerabilityVector):

       def __init__(self,context):

            self.context = context




       def analyze(self):

            self.KeyStore_null_PWD_check()
            self.Find_all_keystore()

            self.bksCheck()


       def KeyStore_null_PWD_check(self):

            list_no_pwd_probably_ssl_pinning_keystore = []
            list_no_pwd_keystore = []
            list_protected_keystore = []

            path_KeyStore = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/security/KeyStore;", "load",
                                                                                        "(Ljava/io/InputStream; [C)V")
            path_KeyStore = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_KeyStore)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_KeyStore):
                if i.getResult()[2] == 0:  #null = 0 = Not using password
                    if (i.is_class_container(1)):
                        clz_invoked = i.getResult()[1]
                        if clz_invoked.get_class_name() == "Ljava/io/ByteArrayInputStream;":
                            list_no_pwd_probably_ssl_pinning_keystore.append(i.getPath())
                        else:
                            list_no_pwd_keystore.append(i.getPath())
                    else:
                        if i.getResult()[1] == 0:  #null = 0
                            list_no_pwd_probably_ssl_pinning_keystore.append(i.getPath())
                        else:
                            list_no_pwd_keystore.append(i.getPath())
                else:
                    list_protected_keystore.append(i.getPath())

            if (not list_no_pwd_keystore) and (not list_protected_keystore) and (not list_no_pwd_probably_ssl_pinning_keystore):

                self.context.writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_INFO, "KeyStore Protection Checking",
                                   "Ignore checking KeyStore protected by password or not because you're not using KeyStore.",
                                   ["KeyStore", "Hacker"])

            else:
                if list_no_pwd_probably_ssl_pinning_keystore:

                    self.context.writer.startWriter("HACKER_KEYSTORE_SSL_PINNING", LEVEL_CRITICAL, "KeyStore Protection Checking",
                                       "The Keystores below seem using \"byte array\" or \"hard-coded cert info\" to do SSL pinning (Total: " + str(
                                           len(list_no_pwd_probably_ssl_pinning_keystore)) + "). Please manually check:",
                                       ["KeyStore", "Hacker"])

                    for keystore in list_no_pwd_probably_ssl_pinning_keystore:
                        self.context.writer.show_Path(self.context.d, keystore)

                if list_no_pwd_keystore:

                    self.context.writer.startWriter("HACKER_KEYSTORE_NO_PWD", LEVEL_CRITICAL, "KeyStore Protection Checking",
                                       "The Keystores below seem \"NOT\" protected by password (Total: " + str(
                                           len(list_no_pwd_keystore)) + "). Please manually check:", ["KeyStore", "Hacker"])

                    for keystore in list_no_pwd_keystore:
                        self.context.writer.show_Path(self.context.d, keystore)

                if list_protected_keystore:

                    self.context.startWriter("HACKER_KEYSTORE_SSL_PINNING2", LEVEL_NOTICE, "KeyStore Protection Information",
                                       "The Keystores below are \"protected\" by password and seem using SSL-pinning (Total: " + str(
                                           len(
                                               list_protected_keystore)) + "). You can use \"Portecle\" tool to manage the certificates in the KeyStore:",
                                       ["KeyStore", "Hacker"])

                    for keystore in list_protected_keystore:
                        self.context.writer.show_Path(self.context.d, keystore)


       def Find_all_keystore(self):


                #Find all keystore

                list_keystore_file_name = []
                list_possible_keystore_file_name = []

                for name, _, _ in self.context.a.get_files_information():
                    """
                        1.Name includes cert (search under /res/raw)
                        2.ends with .bks (search all)
                    """
                    if name.endswith(".bks") or name.endswith(".jks"):
                        if (name.startswith("res/")) and (
                                not name.startswith("res/raw/")):  #If any files found on "/res" dir, only get from "/res/raw"
                            continue
                        list_keystore_file_name.append(name)
                    elif ("keystore" in name) or ("cert" in name):
                        if (name.startswith("res/")) and (
                                not name.startswith("res/raw/")):  #If any files found on "/res" dir, only get from "/res/raw
                            continue
                        list_possible_keystore_file_name.append(name)

                if list_keystore_file_name or list_possible_keystore_file_name:
                    if list_keystore_file_name:
                        self.context.writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_NOTICE, "KeyStore File Location",
                                           "BKS Keystore file:", ["KeyStore", "Hacker"])
                        for i in list_keystore_file_name:
                            self.context.writer.write(i)

                    if list_possible_keystore_file_name:
                        self.context.writer.startWriter("HACKER_KEYSTORE_LOCATION2", LEVEL_NOTICE, "Possible KeyStore File Location",
                                           "BKS possible keystore file:", ["KeyStore", "Hacker"])
                        for i in list_possible_keystore_file_name:
                            self.context.writer.write(i)
                else:
                    self.context.writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_INFO, "KeyStore File Location",
                                       "Did not find any possible BKS keystores or certificate keystore file (Notice: It does not mean this app does not use keysotre):",
                                       ["KeyStore", "Hacker"])


       def bksCheck(self):


            #BKS KeyStore checking:

            """
                Example:
                const-string v11, "BKS"
                invoke-static {v11}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
            """

            list_Non_BKS_keystore = []
            path_BKS_KeyStore = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/security/KeyStore;",
                                                                                            "getInstance",
                                                                                            "(Ljava/lang/String;)Ljava/security/KeyStore;")
            path_BKS_KeyStore = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_BKS_KeyStore)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_BKS_KeyStore):
                if i.getResult()[0] is None:
                    continue
                if (i.is_string(i.getResult()[0])) and ((i.getResult()[0]).upper() != "BKS"):
                    list_Non_BKS_keystore.append(i.getPath())

            if list_Non_BKS_keystore:
                self.context.writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_CRITICAL, "KeyStore Type Checking",
                                   "Android only accept 'BKS' type KeyStore. Please confirm you are using 'BKS' type KeyStore:",
                                   ["KeyStore"])
                for keystore in list_Non_BKS_keystore:
                    self.context.writer.show_Path(self.context.d, keystore)
            else:
                self.context.writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_INFO, "KeyStore Type Checking", "KeyStore 'BKS' type check OK",
                                   ["KeyStore"])



