#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class FilesystemCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            self.WORLD_READABLE_WRITEABLE_check()
            self.External_storage_check()
            self.SQLcipher_check()

        def WORLD_READABLE_WRITEABLE_check(self):


            """
                MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE checking:

                MODE_WORLD_READABLE = 1
                MODE_WORLD_WRITEABLE = 2
                MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE = 3

                http://jimmy319.blogspot.tw/2011/07/android-internal-storagefile-io.html

                Example Java Code:
                    FileOutputStream outputStream = openFileOutput("Hello_World", Activity.MODE_WORLD_READABLE);

                Example Smali Code:
                    const-string v3, "Hello_World"
                    const/4 v4, 0x1
                    invoke-virtual {p0, v3, v4}, Lcom/example/android_mode_world_testing/MainActivity;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
            """

            #Get a list of 'PathP' objects that are vulnerabilities
            list_path_openOrCreateDatabase = []
            list_path_openOrCreateDatabase2 = []
            list_path_getDir = []
            list_path_getSharedPreferences = []
            list_path_openFileOutput = []

            path_openOrCreateDatabase = self.context.vmx.get_tainted_packages().search_methods_exact_match("openOrCreateDatabase",
                                                                                              "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;")
            path_openOrCreateDatabase = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_openOrCreateDatabase)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_openOrCreateDatabase):
                if 0x1 <= i.getResult()[2] <= 0x3:
                    list_path_openOrCreateDatabase.append(i.getPath())

            path_openOrCreateDatabase2 = self.context.vmx.get_tainted_packages().search_methods_exact_match("openOrCreateDatabase",
                                                                                               "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory; Landroid/database/DatabaseErrorHandler;)Landroid/database/sqlite/SQLiteDatabase;")
            path_openOrCreateDatabase2 = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_openOrCreateDatabase2)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_openOrCreateDatabase2):
                if 0x1 <= i.getResult()[2] <= 0x3:
                    list_path_openOrCreateDatabase2.append(i.getPath())

            path_getDir = self.context.vmx.get_tainted_packages().search_methods_exact_match("getDir",
                                                                                "(Ljava/lang/String; I)Ljava/io/File;")
            path_getDir = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getDir)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_getDir):
                if 0x1 <= i.getResult()[2] <= 0x3:
                    list_path_getDir.append(i.getPath())

            path_getSharedPreferences = self.context.vmx.get_tainted_packages().search_methods_exact_match("getSharedPreferences",
                                                                                              "(Ljava/lang/String; I)Landroid/content/SharedPreferences;")
            path_getSharedPreferences = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getSharedPreferences)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_getSharedPreferences):
                if 0x1 <= i.getResult()[2] <= 0x3:
                    list_path_getSharedPreferences.append(i.getPath())

            path_openFileOutput = self.context.vmx.get_tainted_packages().search_methods_exact_match("openFileOutput",
                                                                                        "(Ljava/lang/String; I)Ljava/io/FileOutputStream;")
            path_openFileOutput = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_openFileOutput)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_openFileOutput):
                if 0x1 <= i.getResult()[2] <= 0x3:
                    list_path_openFileOutput.append(i.getPath())

            if list_path_openOrCreateDatabase or list_path_openOrCreateDatabase2 or list_path_getDir or list_path_getSharedPreferences or list_path_openFileOutput:

                self.context.writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_CRITICAL,
                                   "App Sandbox Permission Checking",
                                   "Security issues \"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" found (Please check: https://www.owasp.org/index.php/Mobile_Top_10_2014-M2):")

                if list_path_openOrCreateDatabase:
                    self.context.writer.write("[openOrCreateDatabase - 3 params]")
                    for i in list_path_openOrCreateDatabase:
                        self.context.writer.show_Path(self.context.d, i)
                    self.context.writer.write("--------------------------------------------------")
                if list_path_openOrCreateDatabase2:
                    self.context.writer.write("[openOrCreateDatabase - 4 params]")
                    for i in list_path_openOrCreateDatabase2:
                        self.context.writer.show_Path(self.context.d, i)
                    self.context.writer.write("--------------------------------------------------")
                if list_path_getDir:
                    self.context.writer.write("[getDir]")
                    for i in list_path_getDir:
                        self.context.writer.show_Path(self.context.d, i)
                    self.context.writer.write("--------------------------------------------------")
                if list_path_getSharedPreferences:
                    self.context.writer.write("[getSharedPreferences]")
                    for i in list_path_getSharedPreferences:
                        self.context.writer.show_Path(self.context.d, i)
                    self.context.writer.write("--------------------------------------------------")
                if list_path_openFileOutput:
                    self.context.writer.write("[openFileOutput]")
                    for i in list_path_openFileOutput:
                        self.context.writer.show_Path(self.context.d, i)
                    self.context.writer.write("--------------------------------------------------")

            else:
                self.context.writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_INFO, "App Sandbox Permission Checking",
                                   "No security issues \"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" found on 'openOrCreateDatabase' or 'openOrCreateDatabase2' or 'getDir' or 'getSharedPreferences' or 'openFileOutput'")

        def External_storage_check(self):


            paths_ExternalStorageAccess = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;")
            paths_ExternalStorageAccess = self.context.filteringEngine.filter_list_of_paths(self.context.d, paths_ExternalStorageAccess)
            if paths_ExternalStorageAccess:
                self.context.writer.startWriter("EXTERNAL_STORAGE", LEVEL_WARNING, "External Storage Accessing",
                                   "External storage access found (Remember DO NOT write important files to external storages):")
                self.context.writer.show_Paths(self.context.d, paths_ExternalStorageAccess)
            else:
                self.context.writer.startWriter("EXTERNAL_STORAGE", LEVEL_INFO, "External Storage Accessing",
                                   "External storage access not found.")

        def SQLcipher_check(self):

            #Checking whether the app is using SQLCipher:
            #Reference to <<Essential_Block_1>>
            if self.context.isUsingSQLCipher:
                self.context.writer.startWriter("DB_SQLCIPHER", LEVEL_NOTICE, "Android SQLite Databases Encryption (SQLCipher)",
                                   "This app is using SQLCipher(http://sqlcipher.net/) to encrypt or decrpyt databases.",
                                   ["Database"])

                path_sqlcipher_dbs = self.context.vmx.get_tainted_packages().search_sqlcipher_databases()  #Don't do the exclusion checking on this one because it's not needed

                if path_sqlcipher_dbs:
                    #Get versions:
                    has_version1or0 = False
                    has_version2 = False
                    for _, version in path_sqlcipher_dbs:
                        if version == 1:
                            has_version1or0 = True
                        if version == 2:
                            has_version2 = True

                    if has_version1or0:
                        self.context.writer.write(
                            "It's using \"SQLCipher for Android\" (Library version: 1.X or 0.X), package name: \"info.guardianproject.database\"")
                    if has_version2:
                        self.context.writer.write(
                            "It's using \"SQLCipher for Android\" (Library version: 2.X or higher), package name: \"net.sqlcipher.database\"")

                    #Dumping:
                    for db_path, version in path_sqlcipher_dbs:
                        self.context.writer.show_Path(self.context.d, db_path)

            else:
                self.context.writer.startWriter("DB_SQLCIPHER", LEVEL_INFO, "Android SQLite Databases Encryption (SQLCipher)",
                                   "This app is \"NOT\" using SQLCipher(http://sqlcipher.net/) to encrypt or decrpyt databases.",
                                   ["Database"])

            # ------------------------------------------------------------------------
            #Find "SQLite Encryption Extension (SEE) on Android"
            has_SSE_databases = False
            for cls in self.context.d.get_classes():
                if cls.get_name() == "Lorg/sqlite/database/sqlite/SQLiteDatabase;":  #Don't do the exclusion checking on this one because it's not needed
                    has_SSE_databases = True
                    break

            if has_SSE_databases:
                self.context.writer.startWriter("DB_SEE", LEVEL_NOTICE,
                                   "Android SQLite Databases Encryption (SQLite Encryption Extension (SEE))",
                                   "This app is using SQLite Encryption Extension (SEE) on Android (http://www.sqlite.org/android) to encrypt or decrpyt databases.",
                                   ["Database"])

            else:
                self.context.writer.startWriter("DB_SEE", LEVEL_INFO,
                                   "Android SQLite Databases Encryption (SQLite Encryption Extension (SEE))",
                                   "This app is \"NOT\" using SQLite Encryption Extension (SEE) on Android (http://www.sqlite.org/android) to encrypt or decrpyt databases.",
                                   ["Database"])
