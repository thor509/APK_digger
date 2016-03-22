#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class SQLiteCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            self.TransactionNonExclusive_check()

            self.Information_Disclosure_check()

            self.SSE_check()

            self.PRAGMA_key_check()


        def TransactionNonExclusive_check(self):


           # SQLiteDatabase - beginTransactionNonExclusive() checking:

            if (self.context.int_min_sdk is not None) and (self.context.int_min_sdk < 11):

                path_SQLiteDatabase_beginTransactionNonExclusive = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                    "Landroid/database/sqlite/SQLiteDatabase;", "beginTransactionNonExclusive", "()V")
                path_SQLiteDatabase_beginTransactionNonExclusive = self.context.filteringEngine.filter_list_of_paths(self.context.d,
                                                                                                        path_SQLiteDatabase_beginTransactionNonExclusive)

                if path_SQLiteDatabase_beginTransactionNonExclusive:
                    output_string = StringHandler()
                    output_string.append(
                        "We detect you're using \"beginTransactionNonExclusive\" in your \"SQLiteDatabase\" but your minSdk supports down to " + str(
                            self.context.int_min_sdk) + ".")
                    output_string.append(
                        "\"beginTransactionNonExclusive\" is not supported by API < 11. Please make sure you use \"beginTransaction\" in the earlier version of Android.")
                    output_string.append(
                        "Reference: http://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html#beginTransactionNonExclusive()")
                    self.context.writer.startWriter("DB_DEPRECATED_USE1", LEVEL_CRITICAL, "SQLiteDatabase Transaction Deprecated Checking",
                                       output_string.get(), ["Database"])

                    self.context.writer.show_Paths(self.context.d, path_SQLiteDatabase_beginTransactionNonExclusive)
                else:
                    self.context.writer.startWriter("DB_DEPRECATED_USE1", LEVEL_INFO, "SQLiteDatabase Transaction Deprecated Checking",
                                       "Ignore checking \"SQLiteDatabase:beginTransactionNonExclusive\" you're not using it.",
                                       ["Database"])
            else:
                self.context.writer.startWriter("DB_DEPRECATED_USE1", LEVEL_INFO, "SQLiteDatabase Transaction Deprecated Checking",
                                   "Ignore checking \"SQLiteDatabase:beginTransactionNonExclusive\" because your set minSdk >= 11.",
                                   ["Database"])


        def Information_Disclosure_check(self):


            #SQLite databases

            is_using_android_dbs = self.context.vmx.get_tainted_packages().has_android_databases(self.context.filteringEngine.get_filtering_regexp())
            if is_using_android_dbs:
                if self.context.int_min_sdk < 15:
                    self.context.writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_NOTICE, "Android SQLite Databases Vulnerability Checking",
                                       """This app is using Android SQLite databases.
            Prior to Android 4.0, Android has SQLite Journal Information Disclosure Vulnerability.
            But it can only be solved by users upgrading to Android > 4.0 and YOU CANNOT SOLVE IT BY YOURSELF (But you can use encrypt your databases and Journals by "SQLCipher" or other libs).
            Proof-Of-Concept Reference:
            (1) http://blog.watchfire.com/files/androidsqlitejournal.pdf
            (2) http://www.youtube.com/watch?v=oCXLHjmH5rY """, ["Database"], "CVE-2011-3901")
                else:
                    self.context.writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_NOTICE, "Android SQLite Databases Vulnerability Checking",
                                       "This app is using Android SQLite databases but it's \"NOT\" suffering from SQLite Journal Information Disclosure Vulnerability.",
                                       ["Database"], "CVE-2011-3901")
            else:
                self.context.writer.startWriter("DB_SQLITE_JOURNAL", LEVEL_INFO, "Android SQLite Databases Vulnerability Checking",
                                   "This app is \"NOT\" using Android SQLite databases.", ["Database"], "CVE-2011-3901")


        def SSE_check(self):

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

        def PRAGMA_key_check(self):

            #Searching SQLite "PRAGMA key" encryption:
            result_sqlite_encryption = self.context.efficientStringSearchEngine.get_search_result_by_match_id("$__sqlite_encryption__")
            result_sqlite_encryption = self.context.filteringEngine.filter_efficient_search_result_value(result_sqlite_encryption)
            if result_sqlite_encryption:
                self.context.writer.startWriter("HACKER_DB_KEY", LEVEL_NOTICE, "Key for Android SQLite Databases Encryption",
                                   "Found using the symmetric key(PRAGMA key) to encrypt the SQLite databases. \nRelated code:",
                                   ["Database", "Hacker"])

                for found_string, method in result_sqlite_encryption:
                    self.context.writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
            else:
                self.context.writer.startWriter("HACKER_DB_KEY", LEVEL_INFO, "Key for Android SQLite Databases Encryption",
                                   "Did not find using the symmetric key(PRAGMA key) to encrypt the SQLite databases (It's still possible that it might use but we did not find out).",
                                   ["Database", "Hacker"])



