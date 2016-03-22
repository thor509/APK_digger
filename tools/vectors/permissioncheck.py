#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class PermissionCheck(VulnerabilityVector):

       def __init__(self,context):

            self.context = context





       def analyze(self):

           self.Critical_permission_check()
           self.dangerous_permission_check()
           self.normal_permission_check()

       def Critical_permission_check(self):



            ACCESS_MOCK_LOCATION = "android.permission.ACCESS_MOCK_LOCATION"
            if ACCESS_MOCK_LOCATION in self.context.all_permissions:
                self.context.writer.startWriter("USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_CRITICAL, "Unnecessary Permission Checking",
                                   "Permission 'android.permission.ACCESS_MOCK_LOCATION' only works in emulator environment. Please remove this permission if it is a released application.")
            else:
                self.context.writer.startWriter("USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_INFO, "Unnecessary Permission Checking",
                                   "Permission 'android.permission.ACCESS_MOCK_LOCATION' sets correctly.")

            #----------------------------------------------------------------------------------

            permissionNameOfWrongPermissionGroup = self.context.a.get_permission_tag_wrong_settings_names()

            if permissionNameOfWrongPermissionGroup:  #If the list is not empty
                self.context.startWriter("PERMISSION_GROUP_EMPTY_VALUE", LEVEL_CRITICAL, "AndroidManifest PermissionGroup Checking",
                                   "Setting the 'permissionGroup' attribute an empty value will make the permission definition become invalid and no other apps will be able to use the permission.")

                for name in permissionNameOfWrongPermissionGroup:
                    self.context.write("Permission name '%s' sets an empty value in `permissionGroup` attribute." % (name))
            else:
                self.context.writer.startWriter("PERMISSION_GROUP_EMPTY_VALUE", LEVEL_INFO, "AndroidManifest PermissionGroup Checking",
                                   "PermissionGroup in permission tag of AndroidManifest sets correctly.")

            #----------------------------------------------------------------------------------

            #Critical use-permission check:
            user_permission_critical_manufacturer = ["android.permission.INSTALL_PACKAGES",
                                                     "android.permission.WRITE_SECURE_SETTINGS"]
            user_permission_critical = ["android.permission.MOUNT_FORMAT_FILESYSTEMS",
                                        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS", "android.permission.RESTART_PACKAGES"]

            list_user_permission_critical_manufacturer = []
            list_user_permission_critical = []

            for permission in self.context.all_permissions:
                if permission in user_permission_critical_manufacturer:
                    list_user_permission_critical_manufacturer.append(permission)
                if permission in user_permission_critical:
                    list_user_permission_critical.append(permission)

            if list_user_permission_critical_manufacturer or list_user_permission_critical:
                if list_user_permission_critical_manufacturer:
                    self.context.writer.startWriter("USE_PERMISSION_SYSTEM_APP", LEVEL_CRITICAL,
                                       "AndroidManifest System Use Permission Checking",
                                       "This app should only be released and signed by device manufacturer or Google and put under '/system/app'. If not, it may be a malicious app.")

                    for permission in list_user_permission_critical_manufacturer:
                        self.context.writer.write("System use-permission found: \"" + permission + "\"")

                if list_user_permission_critical:
                    self.context.writer.startWriter("USE_PERMISSION_CRITICAL", LEVEL_CRITICAL,
                                       "AndroidManifest Critical Use Permission Checking",
                                       "This app has very high privileges. Use it carefully.")

                    for permission in list_user_permission_critical:
                        self.context.writer.write("Critical use-permission found: \"" + permission + "\"")
            else:
                self.context.writer.startWriter("USE_PERMISSION_SYSTEM_APP", LEVEL_INFO, "AndroidManifest System Use Permission Checking",
                                   "No system-level critical use-permission found.")


       def dangerous_permission_check(self):


            #Find all "dangerous" permission

            """
                android:permission
                android:readPermission (for ContentProvider)
                android:writePermission (for ContentProvider)
            """

            #Get a mapping dictionary
            self.context.PermissionName_to_ProtectionLevel = self.context.a.get_PermissionName_to_ProtectionLevel_mapping()

            dangerous_custom_permissions = []
            for name, protectionLevel in self.context.PermissionName_to_ProtectionLevel.items():
                if protectionLevel == PROTECTION_DANGEROUS:  # 1:"dangerous"
                    dangerous_custom_permissions.append(name)

            if dangerous_custom_permissions:

                self.context.writer.startWriter("PERMISSION_DANGEROUS", LEVEL_CRITICAL,
                                   "AndroidManifest Dangerous ProtectionLevel of Permission Checking",
                                   """The protection level of the below classes is "dangerous", allowing any other apps to access this permission (AndroidManifest.xml).
        The app should declare the permission with the "android:protectionLevel" of "signature" or "signatureOrSystem" so that other apps cannot register and receive message for this app.
        android:protectionLevel="signature" ensures that apps with request a permission must be signed with same certificate as the application that declared the permission.
        Please check some related cases: http://www.wooyun.org/bugs/wooyun-2010-039697
        Please change these permissions:""")

                for class_name in dangerous_custom_permissions:
                    self.context.writer.write(class_name)

                    who_use_this_permission = get_all_components_by_permission(self.context.a.get_AndroidManifest(), class_name)
                    who_use_this_permission = collections.OrderedDict(sorted(who_use_this_permission.items()))
                    if who_use_this_permission:
                        for key, valuelist in who_use_this_permission.items():
                            for list_item in valuelist:
                                self.context.writer.write("    -> used by (" + key + ") " + self.context.a.format_value(list_item))
            else:
                self.context.writer.startWriter("PERMISSION_DANGEROUS", LEVEL_INFO,
                                   "AndroidManifest Dangerous ProtectionLevel of Permission Checking",
                                   "No \"dangerous\" protection level customized permission found (AndroidManifest.xml).")


       def normal_permission_check(self):

            #Find all "normal" or default permission

            normal_or_default_custom_permissions = []
            for name, protectionLevel in self.context.PermissionName_to_ProtectionLevel.items():
                if protectionLevel == PROTECTION_NORMAL:  # 0:"normal" or not set
                    normal_or_default_custom_permissions.append(name)

            if normal_or_default_custom_permissions:
                self.context.writer.startWriter("PERMISSION_NORMAL", LEVEL_WARNING,
                                   "AndroidManifest Normal ProtectionLevel of Permission Checking",
                                   """The protection level of the below classes is "normal" or default (AndroidManifest.xml).
        The app should declare the permission with the "android:protectionLevel" of "signature" or "signatureOrSystem" so that other apps cannot register and receive message for this app.
        android:protectionLevel="signature" ensures that apps with request a permission must be signed with same certificate as the application that declared the permission.
        Please make sure these permission are all really need to be exported or otherwise change to "signature" or "signatureOrSystem" protection level.""")
                for class_name in normal_or_default_custom_permissions:
                    self.context.writer.write(class_name)
                    who_use_this_permission = get_all_components_by_permission(self.context.a.get_AndroidManifest(), class_name)
                    who_use_this_permission = collections.OrderedDict(sorted(who_use_this_permission.items()))
                    if who_use_this_permission:
                        for key, valuelist in who_use_this_permission.items():
                            for list_item in valuelist:
                                self.context.writer.write("    -> used by (" + key + ") " + self.context.a.format_value(list_item))
            else:
                self.context.writer.startWriter("PERMISSION_NORMAL", LEVEL_INFO,
                                   "AndroidManifest Normal ProtectionLevel of Permission Checking",
                                   "No default or \"normal\" protection level customized permission found (AndroidManifest.xml).")
