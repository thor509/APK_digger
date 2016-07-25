#coding:utf8



#from tools import *
from .. import *
from VulnerabilityVector import VulnerabilityVector



class AppinfoCheck(VulnerabilityVector):


       def __init__(self,context):

            self.context = context




       def analyze(self):

        # only for apk analysis #added by heen
           if self.context.a is not None:
               self.debugcheck()
               self.checkGCM()
               self.adb_backup_check()
               self.networkCheck()
        # for apk and dex analysis
           self.signCheck()
           self.install_from_Google_Play_check()


       def networkCheck(self):

            #Find network methods:

            # pkg_xxx is a 'PathP' object
            pkg_URLConnection = self.context.vmx.get_tainted_packages().search_packages("Ljava/net/URLConnection;")
            pkg_HttpURLConnection = self.context.vmx.get_tainted_packages().search_packages("Ljava/net/HttpURLConnection;")
            pkg_HttpsURLConnection = self.context.vmx.get_tainted_packages().search_packages("Ljavax/net/ssl/HttpsURLConnection;")
            pkg_DefaultHttpClient = self.context.vmx.get_tainted_packages().search_packages(
                "Lorg/apache/http/impl/client/DefaultHttpClient;")
            pkg_HttpClient = self.context.vmx.get_tainted_packages().search_packages("Lorg/apache/http/client/HttpClient;")

            pkg_URLConnection = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_URLConnection)
            pkg_HttpURLConnection = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_HttpURLConnection)
            pkg_HttpsURLConnection = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_HttpsURLConnection)
            pkg_DefaultHttpClient = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_DefaultHttpClient)
            pkg_HttpClient = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_HttpClient)

            # size_pkg_URLConnection = len(pkg_URLConnection)
            # size_pkg_HttpURLConnection = len(pkg_HttpURLConnection)
            # size_pkg_HttpsURLConnection = len(pkg_HttpsURLConnection)
            # size_pkg_DefaultHttpClient = len(pkg_DefaultHttpClient)
            # size_pkg_HttpClient = len(pkg_HttpClient)

            # Provide 2 options for users:
            # 1.Show the network-related class or not
            # 2.Exclude 'Lcom/google/' package or 'Lcom/facebook/' package  or not
            # **Should Make the output path sorted by class name

            if pkg_URLConnection or pkg_HttpURLConnection or pkg_HttpsURLConnection or pkg_DefaultHttpClient or pkg_HttpClient:

                if "android.permission.INTERNET" in self.context.all_permissions:
                    self.context.writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_INFO, "Accessing the Internet Checking",
                                       "This app is using the Internet via HTTP protocol.")

                else:
                    self.context.writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_CRITICAL, "Accessing the Internet Checking",
                                       "This app has some internet accessing codes but does not have 'android.permission.INTERNET' use-permission in AndroidManifest.")

                    # if pkg_URLConnection:
                    # 	print("        =>URLConnection:")
                    # 	analysis.show_Paths(d, pkg_URLConnection)
                    # 	print
                    # if pkg_HttpURLConnection:
                    # 	print("        =>HttpURLConnection:")
                    # 	analysis.show_Paths(d, pkg_HttpURLConnection)
                    # 	print
                    # if pkg_HttpsURLConnection:
                    # 	print("        =>HttpsURLConnection:")
                    # 	analysis.show_Paths(d, pkg_HttpsURLConnection)
                    # 	print
                    # if pkg_DefaultHttpClient:
                    # 	print("        =>DefaultHttpClient:")
                    # 	analysis.show_Paths(d, pkg_DefaultHttpClient)
                    # 	print
                    # if pkg_HttpClient:
                    # 	print("        =>HttpClient:")
                    # 	analysis.show_Paths(d, pkg_HttpClient)
                    # 	print

            else:
                self.context.writer.startWriter("USE_PERMISSION_INTERNET", LEVEL_INFO, "Accessing the Internet Checking",
                                   "No HTTP-related connection codes found.")



       def checkGCM(self):

            isSuggestGCM = False   #Google Cloud Messaging
            if self.context.int_min_sdk is not None:
                if self.context.int_min_sdk < 8:  #Android 2.2=SDK 8
                    isSuggestGCM = True

            if isSuggestGCM:

                output_string = """Your supporting minSdk is """ + str(self.context.int_min_sdk) + """
        You are now allowing minSdk to less than 8. Please check: http://developer.android.com/about/dashboards/index.html
        Google Cloud Messaging (Push Message) service only allows Android SDK >= 8 (Android 2.2). Pleae check: http://developer.android.com/google/gcm/gcm.html
        You may have the change to use GCM in the future, so please set minSdk to at least 9."""
                self.context.writer.startWriter("MANIFEST_GCM", LEVEL_NOTICE, "Google Cloud Messaging Suggestion", output_string)

            else:

                self.context.writer.startWriter("MANIFEST_GCM", LEVEL_INFO, "Google Cloud Messaging Suggestion", "Nothing to suggest.")


       def debugcheck(self):

            if self.context.a is not None:
                is_debug_open = self.context.a.is_debuggable()  #Check 'android:debuggable'
            else:    #when dex analysis, omit debugcheck  #added by heen
                return

            if is_debug_open:
                self.context.writer.startWriter("DEBUGGABLE", LEVEL_CRITICAL, "Android Debug Mode Checking",
                                   "DEBUG mode is ON(android:debuggable=\"true\") in AndroidManifest.xml. This is very dangerous. The attackers will be able to sniffer the debug messages by Logcat. Please disable the DEBUG mode if it is a released application.",
                                   ["Debug"])

            else:
                self.context.writer.startWriter("DEBUGGABLE", LEVEL_INFO, "Android Debug Mode Checking",
                                   "DEBUG mode is OFF(android:debuggable=\"false\") in AndroidManifest.xml.", ["Debug"])



            # Checking whether the app is checking debuggable:

            """
                Java code checking debuggable:
                    boolean isDebuggable = (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
                    if (isDebuggable) { }

                Smali code checking debuggable:
                    invoke-virtual {p0}, Lcom/example/androiddebuggable/MainActivity;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
                    move-result-object v1
                    iget v1, v1, Landroid/content/pm/ApplicationInfo;->flags:I
                    and-int/lit8 v1, v1, 0x2
                    if-eqz v1, :cond_0

                Checking Pattern:
                    1. Find tainted calling field: Landroid/content/pm/ApplicationInfo;->flags:I
                    2. Get the next instruction of the calling field: Landroid/content/pm/ApplicationInfo;->flags:I
                    3. Check whether the next instruction is 0xDD(and-int/lit8) and make sure the register numbers are all matched
                        iget [[v1]], v1, [[[Landroid/content/pm/ApplicationInfo;->flags:I]]]
                        and-int/lit8 v1, [[v1]], [0x2]

            """
            list_detected_FLAG_DEBUGGABLE_path = []
            field_ApplicationInfo_flags_debuggable = self.context.vmx.get_tainted_field("Landroid/content/pm/ApplicationInfo;", "flags", "I")

            if field_ApplicationInfo_flags_debuggable:
                for path, stack in field_ApplicationInfo_flags_debuggable.get_paths_and_stacks(self.context.d,
                                                                                               self.context.filteringEngine.get_filtering_regexp()):
                    last_one_ins = stack.gets()[-1]
                    last_two_ins = stack.gets()[-2]

                    if (last_one_ins is not None) and (last_two_ins is not None):
                        try:
                            if (last_one_ins[0] == 0xDD) and (last_two_ins[1][0][1] == last_one_ins[1][1][1]) and (
                                        last_one_ins[1][2][1] == 2):  #and-int/lit8 vx,vy,lit8
                                list_detected_FLAG_DEBUGGABLE_path.append(path)
                            """
                                Example 1:
                                    last_two_ins => [82, [(0, 1), (0, 1), (258, 16, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
                                    last_one_ins => [221, [(0, 1), (0, 1), (1, 2)]]

                                Example 2:
                                    last_two_ins => [82, [(0, 2), (0, 0), (258, 896, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
                                    last_one_ins => [221, [(0, 2), (0, 2), (1, 2)]]

                                Java code:
                                    stack.show()
                                    print(last_one_ins)
                                    print(last_two_ins)
                            """
                        except:
                            pass

            if list_detected_FLAG_DEBUGGABLE_path:
                self.context.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE, "Codes for Checking Android Debug Mode",
                                   "Found codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml:",
                                   ["Debug", "Hacker"])

                for path in list_detected_FLAG_DEBUGGABLE_path:
                    self.context.writer.show_single_PathVariable(self.context.d, path)
            else:
                self.context.writer.startWriter("HACKER_DEBUGGABLE_CHECK", LEVEL_INFO, "Codes for Checking Android Debug Mode",
                                   "Did not detect codes for checking \"ApplicationInfo.FLAG_DEBUGGABLE\" in AndroidManifest.xml.",
                                   ["Debug", "Hacker"])



       def signCheck(self):


            """
                Example:

                    move-result-object v0
                    iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

                    PackageManager pkgManager = context.getPackageManager();
                    pkgManager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures[0].toByteArray();
            """

            list_PackageInfo_signatures = []
            path_PackageInfo_signatures = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/content/pm/PackageManager;", "getPackageInfo",
                "(Ljava/lang/String; I)Landroid/content/pm/PackageInfo;")
            path_PackageInfo_signatures = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_PackageInfo_signatures)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_PackageInfo_signatures):
                if i.getResult()[2] is None:
                    continue
                if i.getResult()[2] == 64:
                    list_PackageInfo_signatures.append(i.getPath())

            if list_PackageInfo_signatures:
                self.context.writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_NOTICE, "Getting Signature Code Checking",
                                   "This app has code checking the package signature in the code. It might be used to check for whether the app is hacked by the attackers.",
                                   ["Signature", "Hacker"])
                for signature in list_PackageInfo_signatures:
                    self.context.writer.show_Path(self.context.d, signature)
            else:
                self.context.writer.startWriter("HACKER_SIGNATURE_CHECK", LEVEL_INFO, "Getting Signature Code Checking",
                                   "Did not detect this app is checking the signature in the code.", ["Signature", "Hacker"])


       def install_from_Google_Play_check(self):


            #Check if app check for installing from Google Play

            path_getInstallerPackageName = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/content/pm/PackageManager;", "getInstallerPackageName", "(Ljava/lang/String;)Ljava/lang/String;")
            path_getInstallerPackageName = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getInstallerPackageName)

            if path_getInstallerPackageName:
                self.context.writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_NOTICE, "APK Installing Source Checking",
                                   "This app has code checking APK installer sources(e.g. from Google Play, from Amazon, etc.). It might be used to check for whether the app is hacked by the attackers.",
                                   ["Hacker"])
                self.context.writer.show_Paths(self.context.d, path_getInstallerPackageName)
            else:
                self.context.writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_INFO, "APK Installing Source Checking",
                                   "Did not detect this app checks for APK installer sources.", ["Hacker"])

       def adb_backup_check(self):


            #Adb Backup check

            if self.context.a.is_adb_backup_enabled():
                self.context.writer.startWriter("ALLOW_BACKUP", LEVEL_NOTICE, "AndroidManifest Adb Backup Checking",
                                   """ADB Backup is ENABLED for this app (default: ENABLED). ADB Backup is a good tool for backing up all of your files. If it's open for this app, people who have your phone can copy all of the sensitive data for this app in your phone (Prerequisite: 1.Unlock phone's screen 2.Open the developer mode). The sensitive data may include lifetime access token, username or password, etc.
        Security case related to ADB Backup:
        1.http://www.securityfocus.com/archive/1/530288/30/0/threaded
        2.http://blog.c22.cc/advisories/cve-2013-5112-evernote-android-insecure-storage-of-pin-data-bypass-of-pin-protection/
        3.http://nelenkov.blogspot.co.uk/2012/06/unpacking-android-backups.html
        Reference: http://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
        """)
            else:
                self.context.writer.startWriter("ALLOW_BACKUP", LEVEL_INFO, "AndroidManifest Adb Backup Checking",
                                   "This app has disabled Adb Backup.")
