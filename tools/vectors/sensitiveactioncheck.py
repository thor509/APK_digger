#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class ActionCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            self.sending_SMS_check()
            self.shared_user_id_check()
            self.file_delete_check()



        def sending_SMS_check(self):



            #Checking sending SMS code

            """
              Example:
                Landroid/telephony/SmsManager;->sendDataMessage(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
                Landroid/telephony/SmsManager;->sendMultipartTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V
                Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
            """

            list_sms_signatures = [
                ("sendDataMessage",
                 "(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"),
                ("sendMultipartTextMessage",
                 "(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V"),
                ("sendTextMessage",
                 "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V")
            ]

            path_sms_sending = self.context.vmx.get_tainted_packages().search_class_methodlist_exact_match("Landroid/telephony/SmsManager;",
                                                                                              list_sms_signatures)
            path_sms_sending = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_sms_sending)

            if path_sms_sending:
                self.context.writer.startWriter("SENSITIVE_SMS", LEVEL_WARNING, "Codes for Sending SMS",
                                   "This app has code for sending SMS messages (sendDataMessage, sendMultipartTextMessage or sendTextMessage):")
                self.context.writer.show_Paths(self.context.d, path_sms_sending)
            else:
                self.context.writer.startWriter("SENSITIVE_SMS", LEVEL_INFO, "Codes for Sending SMS",
                                   "Did not detect this app has code for sending SMS messages (sendDataMessage, sendMultipartTextMessage or sendTextMessage).")



        def shared_user_id_check(self):

            #Checking shared_user_id

            sharedUserId = self.context.a.get_shared_user_id()
            sharedUserId_in_system = False

            if sharedUserId == "android.uid.system":
                sharedUserId_in_system = True

            if sharedUserId_in_system:
                self.context.writer.startWriter("SHARED_USER_ID", LEVEL_NOTICE, "AndroidManifest sharedUserId Checking",
                                   "This app uses \"android.uid.system\" sharedUserId, which requires the \"system(uid=1000)\" permission. It must be signed with manufacturer's keystore or Google's keystore to be successfully installed on users' devices.",
                                   ["System"])
            else:
                self.context.writer.startWriter("SHARED_USER_ID", LEVEL_INFO, "AndroidManifest sharedUserId Checking",
                                   "This app does not use \"android.uid.system\" sharedUserId.", ["System"])

            # System shared_user_id + Master Key Vulnerability checking: (Depends on "Master Key Vulnerability checking")
            if sharedUserId_in_system and self.context.isMasterKeyVulnerability:
                self.context.writer.startWriter("MASTER_KEY_SYSTEM_APP", LEVEL_CRITICAL, "Rooting System with Master Key Vulnerability",
                                   "This app is a malware, which requests \"system(uid=1000)\" privilege with Master Key vulnerability, leading the devices to be rooted.")

        def file_delete_check(self):



            #File delete alert

            path_FileDelete = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/io/File;", "delete", "()Z")
            path_FileDelete = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_FileDelete)

            if path_FileDelete:
                self.context.writer.startWriter("FILE_DELETE", LEVEL_NOTICE, "File Unsafe Delete Checking",
                                   """Everything you delete may be recovered by any user or attacker, especially rooted devices.
        Please make sure do not use "file.delete()" to delete essential files.
        Check this video: https://www.youtube.com/watch?v=tGw1fxUD-uY""")
                self.context.writer.show_Paths(self.context.d, path_FileDelete)
            else:
                self.context.writer.startWriter("FILE_DELETE", LEVEL_INFO, "File Unsafe Delete Checking",
                                   "Did not detect that you are unsafely deleting files.")

