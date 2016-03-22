#coding:utf8



# Fix settings:

TYPE_REPORT_OUTPUT_ONLY_PRINT = "print"
TYPE_REPORT_OUTPUT_ONLY_FILE = "file"
TYPE_REPORT_OUTPUT_PRINT_AND_FILE = "print_and_file"

TYPE_COMPARE_ALL = 1
TYPE_COMPARE_ANY = 2

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"

#AndroidManifest permission protectionLevel constants
PROTECTION_NORMAL = 0  # "normal" or not set
PROTECTION_DANGEROUS = 1
PROTECTION_SIGNATURE = 2
PROTECTION_SIGNATURE_OR_SYSTEM = 3
PROTECTION_MASK_BASE = 15
PROTECTION_FLAG_SYSTEM = 16
PROTECTION_FLAG_DEVELOPMENT = 32
PROTECTION_MASK_FLAGS = 240

LEVEL_CRITICAL = "Critical"
LEVEL_WARNING = "Warning"
LEVEL_NOTICE = "Notice"
LEVEL_INFO = "Info"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  #100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20
#-----------------------------------------------------------------------------------------------------

#Customized settings:

DEBUG = True
ANALYZE_ENGINE_BUILD_DEFAULT = 1  # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE  #when compiling to Windows executable, switch to "TYPE_REPORT_OUTPUT_ONLY_FILE"
DIRECTORY_REPORT_OUTPUT = "Reports/"  #Only need to specify when (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE) or (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE)
# DIRECTORY_REPORT_OUTPUT = "Massive_Reports/"

#-----------------------------------------------------------------------------------------------------
"""
Package for exclusion:
Lcom/google/
Lcom/aviary/android/
Lcom/parse/
Lcom/facebook/
Lcom/tapjoy/
Lcom/android/
"""

#The exclusion list settings will be loaded into FilteringEngine later
STR_REGEXP_TYPE_EXCLUDE_CLASSES = "^(Landroid/support/|Lcom/actionbarsherlock/|Lorg/apache/)"
ENABLE_EXCLUDE_CLASSES = True

#-----------------------------------------------------------------------------------------------------


