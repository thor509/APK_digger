#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class NativeCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            self.nativecheck()
            #Bangcle check is only for apk  #added by heen
            if self.context.a is not None:
                self.Bangclecheck()
            self.dynamic_load_check()



        def nativecheck(self):




            #List all native method

            """
                Example:
                    const-string v0, "AndroBugsNdk"
                    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
            """

            self.context.cm = self.context.d.get_class_manager()

            dic_NDK_library_classname_to_ndkso_mapping = {}
            self.list_NDK_library_classname_to_ndkso_mapping = []
            path_NDK_library_classname_to_ndkso_mapping = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Ljava/lang/System;", "loadLibrary", "(Ljava/lang/String;)V")
            path_NDK_library_classname_to_ndkso_mapping = self.context.filteringEngine.filter_list_of_paths(self.context.d,
                                                                                               path_NDK_library_classname_to_ndkso_mapping)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_NDK_library_classname_to_ndkso_mapping):
                if (i.getResult()[0] is None) or (not i.is_string(0)):
                    continue
                so_file_name = i.getResult()[0]
                src_class_name, src_method_name, src_descriptor = i.getPath().get_src(self.context.cm)
                if src_class_name is None:
                    continue
                if src_class_name not in dic_NDK_library_classname_to_ndkso_mapping:
                    dic_NDK_library_classname_to_ndkso_mapping[src_class_name] = []

                dic_NDK_library_classname_to_ndkso_mapping[src_class_name].append(toNdkFileFormat(str(i.getResult()[0])))
                self.list_NDK_library_classname_to_ndkso_mapping.append([toNdkFileFormat(str(i.getResult()[0])), i.getPath()])

            if self.list_NDK_library_classname_to_ndkso_mapping:
                self.context.writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_NOTICE, "Native Library Loading Checking",
                                   "Native library loading codes(System.loadLibrary(...)) found:")

                for ndk_location, path in self.list_NDK_library_classname_to_ndkso_mapping:
                    self.context.writer.write("[" + ndk_location + "]")
                    self.context.writer.show_Path(self.context.d, path)
            else:
                self.context.writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_INFO, "Native Library Loading Checking",
                                   "No native library loaded.")

            dic_native_methods = {}
            regexp_sqlcipher_database_class = re.compile(".*/SQLiteDatabase;")
            for method in self.context.d.get_methods():
                if method.is_native():
                    class_name = method.get_class_name()
                    if self.context.filteringEngine.is_class_name_not_in_exclusion(class_name):
                        if class_name not in dic_native_methods:
                            dic_native_methods[class_name] = []
                        dic_native_methods[class_name].append(method)

                    # <<Essential_Block_1>>
                    if regexp_sqlcipher_database_class.match(class_name):
                        if (method.get_name() == "dbopen") or (
                                    method.get_name() == "dbclose"):  #Make it to 2 conditions to add efficiency
                            isUsingSQLCipher = True  #This is for later use

            if dic_native_methods:

                if self.context.args.extra == 2:  #The output may be too verbose, so make it an option

                    dic_native_methods_sorted = collections.OrderedDict(sorted(dic_native_methods.items()))

                    self.context.writer.startWriter("NATIVE_METHODS", LEVEL_NOTICE, "Native Methods Checking", "Native methods found:")

                    for class_name, method_names in dic_native_methods_sorted.items():
                        if class_name in dic_NDK_library_classname_to_ndkso_mapping:
                            self.context.writer.write("Class: %s (Loaded NDK files: %s)" % (
                                class_name, dic_NDK_library_classname_to_ndkso_mapping[class_name]))
                        else:
                            self.context.writer.write("Class: %s" % (class_name))
                        self.context.write("   ->Methods:")
                        for method in method_names:
                            self.context.writer.write("        %s%s" % (method.get_name(), method.get_descriptor()))

            else:
                if self.context.args.extra == 2:  #The output may be too verbose, so make it an option
                    self.context.writer.startWriter("NATIVE_METHODS", LEVEL_INFO, "Native Methods Checking", "No native method found.")

        def Bangclecheck(self):


            #Framework Detection: Bangcle

            is_using_Framework_Bangcle = False
            is_using_Framework_ijiami = False
            is_using_Framework_MonoDroid = False

            #Display only when using the Framework (Notice: This vector depends on "List all native method")
            if self.list_NDK_library_classname_to_ndkso_mapping:

                android_name_in_application_tag = self.context.a.get_android_name_in_application_tag()
                list_NDK_library_classname_to_ndkso_mapping_only_ndk_location = dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(
                    self.list_NDK_library_classname_to_ndkso_mapping)

                if "libsecexe.so" in list_NDK_library_classname_to_ndkso_mapping_only_ndk_location:
                    if android_name_in_application_tag == "com.secapk.wrapper.ApplicationWrapper":
                        is_using_Framework_Bangcle = True
                    else:
                        path_secapk = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Lcom/secapk/wrapper/ACall;",
                                                                                                  "getACall",
                                                                                                  "()Lcom/secapk/wrapper/ACall;")
                        if path_secapk:
                            is_using_Framework_Bangcle = True

                if len(list_NDK_library_classname_to_ndkso_mapping_only_ndk_location) == 2:
                    if ("libexec.so" in list_NDK_library_classname_to_ndkso_mapping_only_ndk_location) and (
                                "libexecmain.so" in list_NDK_library_classname_to_ndkso_mapping_only_ndk_location):
                        paths_ijiami_signature = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                            "Lcom/shell/NativeApplication;", "load", "(Landroid/app/Application; Ljava/lang/String;)Z")
                        if paths_ijiami_signature:
                            is_using_Framework_ijiami = True

                if android_name_in_application_tag == "mono.android.app.Application":
                    for name, _, _ in self.context.a.get_files_information():
                        if (name == "lib/armeabi-v7a/libmonodroid.so") or (name == "lib/armeabi/libmonodroid.so"):
                            is_using_Framework_MonoDroid = True
                            break

                if is_using_Framework_Bangcle:
                    self.context.writer.startWriter("FRAMEWORK_BANGCLE", LEVEL_NOTICE, "Encryption Framework - Bangcle",
                                       "This app is using Bangcle Encryption Framework (http://www.bangcle.com/). Please send your unencrypted apk instead so that we can check thoroughly.",
                                       ["Framework"])
                if is_using_Framework_ijiami:
                    self.context.writer.startWriter("FRAMEWORK_IJIAMI", LEVEL_NOTICE, "Encryption Framework - Ijiami",
                                       "This app is using Ijiami Encryption Framework (http://www.ijiami.cn/). Please send your unencrypted apk instead so that we can check thoroughly.",
                                       ["Framework"])

            if is_using_Framework_MonoDroid:
                self.context.writer.startWriter("FRAMEWORK_MONODROID", LEVEL_NOTICE, "Framework - MonoDroid",
                                   "This app is using MonoDroid Framework (http://xamarin.com/android).", ["Framework"])
            else:
                self.context.writer.startWriter("FRAMEWORK_MONODROID", LEVEL_INFO, "Framework - MonoDroid",
                                   "This app is NOT using MonoDroid Framework (http://xamarin.com/android).", ["Framework"])

        def dynamic_load_check(self):

            #Detect dynamic code loading

            paths_DexClassLoader = self.context.vmx.get_tainted_packages().search_methods("Ldalvik/system/DexClassLoader;", ".", ".")
            paths_DexClassLoader = self.context.filteringEngine.filter_list_of_paths(self.context.d, paths_DexClassLoader)
            if paths_DexClassLoader:
                self.context.writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_WARNING, "Dynamic Code Loading",
                                   "Dynamic code loading(DexClassLoader) found:")
                self.context.writer.show_Paths(self.context.d, paths_DexClassLoader)
            else:
                self.context.writer.startWriter("DYNAMIC_CODE_LOADING", LEVEL_INFO, "Dynamic Code Loading",
                                   "No dynamic code loading(DexClassLoader) found.")
