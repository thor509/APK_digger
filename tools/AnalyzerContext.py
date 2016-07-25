#coding:utf8


import imp,base64

import os

from zipfile import BadZipfile
from . import *









class AnalyzerContext(object):

      def __init__(self,writer, args):

            self.args = args

            self.efficientStringSearchEngine = EfficientStringSearchEngine()
            self.filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_REGEXP_TYPE_EXCLUDE_CLASSES)

            self.isUsingSQLCipher = False
            self.isMasterKeyVulnerability = False

            self.writer = writer

            if args.line_max_output_characters is None:
                if platform.system().lower() == "windows":
                    args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - LINE_MAX_OUTPUT_INDENT
                else:
                    args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - LINE_MAX_OUTPUT_INDENT


            if not os.path.isdir(args.report_output_dir):
                os.mkdir(args.report_output_dir)




            self.writer.writeInf_ForceNoPrint("analyze_mode", args.analyze_mode)
            self.writer.writeInf_ForceNoPrint("analyze_engine_build", args.analyze_engine_build)
            self.writer.writeInf_ForceNoPrint("analyze_tag", args.analyze_tag)

            ##added by heen, apk file and dex file processed independently
            if (args.apk_file.endswith(".apk")):
                self.__processApk(args)

            # dex or odex , in some situation odex got from oat2dex is actually dex
            elif (args.apk_file.endswith("dex")):
                self.__processDex(args)
            else:
                raise ExpectedException("unknown_file_type", "Only Support APK or Dex File with correct file suffix!")



      def __processApk(self,args):
          APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file
          apk_Path = APK_FILE_NAME_STRING  # + ".apk"



          if (".." in args.apk_file):
              raise ExpectedException("apk_file_name_slash_twodots_error",
                                      "APK file name should not contain slash(/) or two dots(..) (File: " + apk_Path + ").")

          if not os.path.isfile(apk_Path):
              raise ExpectedException("apk_file_not_exist", "APK file not exist (File: " + apk_Path + ").")

          if args.store_analysis_result_in_db:
              try:
                  imp.find_module('pymongo')
                  found_pymongo_lib = True
              except ImportError:
                  found_pymongo_lib = False

              if not found_pymongo_lib:
                  pass

          apk_filepath_absolute = os.path.abspath(apk_Path)

          #writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
          self.writer.writeInf_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

          apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024)
          self.writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

          self.writer.update_analyze_status("loading_apk")

          self.writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())

          self.a = apk.APK(apk_Path)

          self.writer.update_analyze_status("starting_apk")

          package_name = self.a.get_package()



          if isNullOrEmptyString(package_name, True):
              raise ExpectedException("package_name_empty", "Package name is empty (File: " + apk_Path + ").")

          self.writer.writeInf("platform", "Android", "Platform")
          self.writer.writeInf("package_name", str(package_name), "Package Name")

          # Check: http://developer.android.com/guide/topics/manifest/manifest-element.html
          if not isNullOrEmptyString(self.a.get_androidversion_name()):
              try:
                  self.writer.writeInf("package_version_name", str(self.a.get_androidversion_name()), "Package Version Name")
              except:
                  self.writer.writeInf("package_version_name", self.a.get_androidversion_name().encode('ascii', 'ignore'),
                                       "Package Version Name")

          if not isNullOrEmptyString(self.a.get_androidversion_code()):
              # The version number shown to users. This attribute can be set as a raw string or as a reference to a string resource.
              # The string has no other purpose than to be displayed to users.
              try:
                  self.writer.writeInf("package_version_code", int(self.a.get_androidversion_code()), "Package Version Code")
              except ValueError:
                  self.writer.writeInf("package_version_code", self.a.get_androidversion_code(), "Package Version Code")

          if len(self.a.get_dex()) == 0:
              raise ExpectedException("classes_dex_not_in_apk",
                                      "Broken APK file. \"classes.dex\" file not found (File: " + apk_Path + ").")

          try:
              str_min_sdk_version = self.a.get_min_sdk_version()
              if (str_min_sdk_version is None) or (str_min_sdk_version == ""):
                  raise ValueError
              else:
                  self.int_min_sdk = int(str_min_sdk_version)
                  self.writer.writeInf("minSdk", self.int_min_sdk, "Min Sdk")
          except ValueError:
              # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
              # If "minSdk" is not set, the default value is "1"
              self.writer.writeInf("minSdk", 1, "Min Sdk")
              self.int_min_sdk = 1

          try:
              str_target_sdk_version = self.a.get_target_sdk_version()
              if (str_target_sdk_version is None) or (str_target_sdk_version == ""):
                  raise ValueError
              else:
                  self.int_target_sdk = int(str_target_sdk_version)
                  self.writer.writeInf("targetSdk", self.int_target_sdk, "Target Sdk")
          except ValueError:
              # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
              # If not set, the default value equals that given to minSdkVersion.
              self.int_target_sdk = self.int_min_sdk

          md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
          self.writer.writeInf("file_md5", md5, "MD5   ")
          self.writer.writeInf("file_sha1", sha1, "SHA1  ")
          self.writer.writeInf("file_sha256", sha256, "SHA256")
          self.writer.writeInf("file_sha512", sha512, "SHA512")

          self.writer.update_analyze_status("starting_dvm")

          self.d = dvm.DalvikVMFormat(self.a.get_dex())

          self.writer.update_analyze_status("starting_analyze")

          self.vmx = analysis.VMAnalysis(self.d)

          self.writer.update_analyze_status("starting_androbugs")


          self.all_permissions = self.a.get_permissions()

          self.allstrings = self.d.get_strings()
          self.allurls_strip_duplicated = []

          # ------------------------------------------------------------------------
          #[Important: String Efficient Searching Engine]
          # >>>>STRING_SEARCH<<<<
          #addSearchItem params: (1)match_id  (2)regex or string(url or string you want to find), (3)is using regex for parameter 2
          self.efficientStringSearchEngine.addSearchItem("$__possibly_check_root__", re.compile("/system/bin"),
                                                         True)  # "root" checking
          self.efficientStringSearchEngine.addSearchItem("$__possibly_check_su__", "su", False)  # "root" checking2
          self.efficientStringSearchEngine.addSearchItem("$__sqlite_encryption__", re.compile("PRAGMA\s*key\s*=", re.I),
                                                         True)  #SQLite encryption checking


          self.list_base64_success_decoded_string_to_original_mapping = {}
          self.list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=",
                                                       "Liouciou"]  #exclusion list

          for line in self.allstrings:
              if (isBase64(line)) and (len(line) >= 3):
                  try:
                      decoded_string = base64.b64decode(line)
                      if isSuccessBase64DecodedString(decoded_string):
                          if len(decoded_string) > 3:
                              if (decoded_string not in self.list_base64_success_decoded_string_to_original_mapping) and (
                                          line not in self.list_base64_excluded_original_string):
                                  self.list_base64_success_decoded_string_to_original_mapping[decoded_string] = line
                                  # >>>>STRING_SEARCH<<<<
                                  self.efficientStringSearchEngine.addSearchItem(line, line, False)
                  except Exception,e:
                      #print e
                      pass


          self.efficientStringSearchEngine.search(self.d, self.allstrings)

          self.PermissionName_to_ProtectionLevel = self.a.get_PermissionName_to_ProtectionLevel_mapping()

      def __processDex(self,args):

          DEX_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file  # in this branch, apk_file is dexfile
          dex_Path = DEX_FILE_NAME_STRING  # + ".apk"



          if (".." in args.apk_file):
              raise ExpectedException("dex_file_name_slash_twodots_error",
                                      "Dex file name should not contain slash(/) or two dots(..) (File: " + dex_Path + ").")

          if not os.path.isfile(dex_Path):
              raise ExpectedException("dex_file_not_exist", "Dex file not exist (File: " + dex_Path + ").")

          if args.store_analysis_result_in_db:
              try:
                  imp.find_module('pymongo')
                  found_pymongo_lib = True
              except ImportError:
                  found_pymongo_lib = False

              if not found_pymongo_lib:
                  pass

          dex_filepath_absolute = os.path.abspath(dex_Path)

          #writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
          self.writer.writeInf_ForceNoPrint("apk_filepath_absolute", dex_filepath_absolute)

          dex_file_size = float(os.path.getsize(dex_filepath_absolute)) / (1024 * 1024)
          self.writer.writeInf_ForceNoPrint("dex_file_size", dex_file_size)
          self.writer.update_analyze_status("loading_dex")
          self.writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())
          self.a = None
          self.writer.update_analyze_status("starting_dex")

          self.writer.writeInf("platform", "Android", "Platform")

          # fake package_name for dex file
          self.writer.writeInf("package_name", os.path.basename(DEX_FILE_NAME_STRING),  "Package Name")

          md5, sha1, sha256, sha512 = get_hashes_by_filename(DEX_FILE_NAME_STRING)
          self.writer.writeInf("file_md5", md5, "MD5   ")
          self.writer.writeInf("file_sha1", sha1, "SHA1  ")
          self.writer.writeInf("file_sha256", sha256, "SHA256")
          self.writer.writeInf("file_sha512", sha512, "SHA512")

          self.writer.update_analyze_status("starting_dvm")

          self.d = dvm.DalvikVMFormat(open(args.apk_file,"rb" ).read()) ##read dex file

          self.writer.update_analyze_status("starting_analyze")

          self.vmx = analysis.VMAnalysis(self.d)

          self.writer.update_analyze_status("starting_androbugs")


          self.allstrings = self.d.get_strings()
          self.allurls_strip_duplicated = []

          # ------------------------------------------------------------------------
          #[Important: String Efficient Searching Engine]
          # >>>>STRING_SEARCH<<<<
          #addSearchItem params: (1)match_id  (2)regex or string(url or string you want to find), (3)is using regex for parameter 2
          self.efficientStringSearchEngine.addSearchItem("$__possibly_check_root__", re.compile("/system/bin"),
                                                         True)  # "root" checking
          self.efficientStringSearchEngine.addSearchItem("$__possibly_check_su__", "su", False)  # "root" checking2
          self.efficientStringSearchEngine.addSearchItem("$__sqlite_encryption__", re.compile("PRAGMA\s*key\s*=", re.I),
                                                         True)  #SQLite encryption checking


          self.list_base64_success_decoded_string_to_original_mapping = {}
          self.list_base64_excluded_original_string = ["endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=",
                                                       "Liouciou"]  #exclusion list

          for line in self.allstrings:
              if (isBase64(line)) and (len(line) >= 3):
                  try:
                      decoded_string = base64.b64decode(line)
                      if isSuccessBase64DecodedString(decoded_string):
                          if len(decoded_string) > 3:
                              if (decoded_string not in self.list_base64_success_decoded_string_to_original_mapping) and (
                                          line not in self.list_base64_excluded_original_string):
                                  self.list_base64_success_decoded_string_to_original_mapping[decoded_string] = line
                                  # >>>>STRING_SEARCH<<<<
                                  self.efficientStringSearchEngine.addSearchItem(line, line, False)
                  except Exception,e:
                      #print e
                      pass


          self.efficientStringSearchEngine.search(self.d, self.allstrings)






