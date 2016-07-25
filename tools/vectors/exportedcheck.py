#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class ExportedCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):
            # only for apk analysis #added by heen
            if self.context.a is not None:
                self.prefix_lost_check()
                self.componenent_check()
                self.service_check()
                self.provider_check()
                self.intent_filter_check()
                self.implicit_service_check()


        def prefix_lost_check(self):


            #Lost "android:" prefix in exported components

            list_lost_exported_components = []
            find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
            xml = self.context.a.get_AndroidManifest()
            for tag in find_tags:
                for item in xml.getElementsByTagName(tag):
                    name = item.getAttribute("android:name")
                    exported = item.getAttribute("exported")
                    if (not isNullOrEmptyString(name)) and (not isNullOrEmptyString(exported)):
                        list_lost_exported_components.append((tag, name))

            if list_lost_exported_components:
                self.context.writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", LEVEL_CRITICAL,
                                   "AndroidManifest Exported Lost Prefix Checking",
                                   """Found exported components that forgot to add "android:" prefix (AndroidManifest.xml).
        Related Cases: (1)http://blog.curesec.com/article/blog/35.html
                       (2)http://safe.baidu.com/2014-07/cve-2013-6272.html
                       (3)http://blogs.360.cn/360mobile/2014/07/08/cve-2013-6272/""", None, "CVE-2013-6272")

                for tag, name in list_lost_exported_components:
                    self.context.writer.write(("%10s => %s") % (tag, self.context.a.format_value(name)))

            else:
                self.context.writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", LEVEL_INFO, "AndroidManifest Exported Lost Prefix Checking",
                                   "No exported components that forgot to add \"android:\" prefix.", None, "CVE-2013-6272")

        def componenent_check(self):


            #"exported" checking (activity, activity-alias, service, receiver):

            """
                Remember: Even if the componenet is protected by "signature" level protection,
                it still cannot receive the broadcasts from other apps if the component is set to [exported="false"].
                ---------------------------------------------------------------------------------------------------

                Even if the component is exported, it still can be protected by the "android:permission", for example:

                <permission
                    android:name="com.example.androidpermissionexported.PermissionControl"
                    android:protectionLevel="signature" >
                </permission>
                <receiver
                    android:name=".SimpleBroadcastReceiver"
                    android:exported="true"
                    android:permission="com.example.androidpermissionexported.PermissionControl" >
                    <intent-filter>
                        <action android:name="com.example.androidpermissionexported.PermissionTest" />
                        <category android:name="android.intent.category.DEFAULT" />
                    </intent-filter>
                </receiver>

                Apps with the same signature(signed with the same certificate) can send and receive the broadcasts with each other.
                Conversely, apps that do not have the same signature cannot send and receive the broadcasts with each other.
                If the protectionLevel is "normal" or not set, then the sending and receiving of broadcasts are not restricted.

                Even if the Action is used by the app itself, it can still be initialized from external(3rd-party) apps
                if the [exported="false"] is not specified, for example:
                Intent intent = new Intent("net.emome.hamiapps.am.action.UPDATE_AM");
                intent.setClassName("net.emome.hamiapps.am", "net.emome.hamiapps.am.update.UpdateAMActivity");
                startActivity(intent);

                ---------------------------------------------------------------------------------------

                **[PERMISSION_CHECK_STAGE]:
                    (1)If android:permission not set => Warn it can be accessed from external
                    (2)If android:permission is set =>
                        Check its corresponding android:protectionLevel is "not set(default: normal)" or "normal" or "dangerous"=> Warn it can be accessed from external
                        If the corresponding permission tag is not found => Ignore

                        **If the names of all the Action(s) are prefixing with "com.android." or "android." =>  Notify with a low priority warning
                            <receiver android:name="jp.naver.common.android.billing.google.checkout.BillingReceiver">
                                <intent-filter>
                                    <action android:name="com.android.vending.billing.IN_APP_NOTIFY" />
                                    <action android:name="com.android.vending.billing.RESPONSE_CODE" />
                                    <action android:name="com.android.vending.billing.PURCHASE_STATE_CHANGED" />
                                </intent-filter>
                            </receiver>
                        **You need to consider the Multiple Intent, for example:
                            <receiver android:name=".service.push.SystemBroadcastReceiver">
                                <intent-filter android:enabled="true" android:exported="false">
                                    <action android:name="android.intent.action.BOOT_COMPLETED" />
                                    <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
                                </intent-filter>
                                <intent-filter android:enabled="true" android:exported="false">
                                    <action android:name="android.intent.action.PACKAGE_REPLACED" />
                                    <data android:scheme="package" android:path="jp.naver.line.android" />
                                </intent-filter>
                            </receiver>
                        **The preceding example: intent-filter is set incorrectly. intent-filter does not have the "android:exported" => Warn misconfiguration


                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                [REASON_REGION_1]
                **If exported is not set, the protectionalLevel of android:permission is set to "normal" by default =>
                    1.It "cannot" be accessed by other apps on Android 4.2 devices
                    2.It "can" be accessed by other apps on Android 4.1 devices

                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                If it is receiver, service, activity or activity-alias, check if the exported is set:
                    exported="false" => No problem

                    exported="true" => Go to [PERMISSION_CHECK_STAGE]

                    exported is not set =>
                        If it has any intent-filter:
                            Yes => Go to [PERMISSION_CHECK_STAGE]
                            No  => If the intent-filter is not existed, it is exported="false" by default => X(Ignore)

                    **Main Problem: If it is still necessary to check the setting of "android:permission"


                If it is provider, the intent-filter must not exist, so check if the exported is set:
                    ->[exported="true"] or [exported is not set] :

                        =>1.If [exported is not set] + [android:targetSdkVersion >= 17], add to the Warning List. Check the reason: [REASON_REGION_1]
                            It is suggested to add "exported" and tell the users that the default value is not the same among different platforms
                            => Check Google's document (The default value is "true" for applications that set either android:minSdkVersion or android:targetSdkVersion to "16" or lower.
                                For applications that set either of these attributes to "17" or higher, the default is "false". - http://developer.android.com/guide/topics/manifest/provider-element.html#exported)

                        =>2.[PERMISSION_CHECK_STAGE, and check "android:readPermission" and "android:writePermission", and check android:permission, android:writePermission, android:readPermission]
                                => If any of the corresponding setting for protectionLevel is not found ,then ignore it.
                                   If any of the corresponding setting for protectionLevel is found, warn the users when the protectionLevel is "dangerous" or "normal".

                    ->exported="false":
                        => X(Ignore)
            """

            self.list_ready_to_check = []
            find_tags = ["activity", "activity-alias", "service", "receiver"]
            xml = self.context.a.get_AndroidManifest()
            for tag in find_tags:
                for item in xml.getElementsByTagName(tag):
                    name = item.getAttribute("android:name")
                    exported = item.getAttribute("android:exported")
                    permission = item.getAttribute("android:permission")
                    has_any_actions_in_intent_filter = False
                    if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):

                        is_ready_to_check = False
                        is_launcher = False
                        has_any_non_google_actions = False
                        isSyncAdapterService = False
                        for sitem in item.getElementsByTagName("intent-filter"):
                            for ssitem in sitem.getElementsByTagName("action"):
                                has_any_actions_in_intent_filter = True

                                action_name = ssitem.getAttribute("android:name")
                                if (not action_name.startswith("android.")) and (not action_name.startswith("com.android.")):
                                    has_any_non_google_actions = True

                                if (action_name == "android.content.SyncAdapter"):
                                    isSyncAdapterService = True

                            for ssitem in sitem.getElementsByTagName("category"):
                                category_name = ssitem.getAttribute("android:name")
                                if category_name == "android.intent.category.LAUNCHER":
                                    is_launcher = True

                        # exported="true" or exported not set
                        if exported == "":
                            if has_any_actions_in_intent_filter:
                                #CHECK
                                is_ready_to_check = True

                        elif exported.lower() == "true":  #exported = "true"
                            #CHECK
                            is_ready_to_check = True

                        if (is_ready_to_check) and (not is_launcher):
                            self.list_ready_to_check.append((
                                tag, self.context.a.format_value(name), exported, permission, has_any_non_google_actions,
                                has_any_actions_in_intent_filter, isSyncAdapterService))


        def service_check(self):

            #CHECK procedure
            self.list_implicit_service_components = []

            list_alerting_exposing_components_NonGoogle = []
            list_alerting_exposing_components_Google = []
            for i in self.list_ready_to_check:
                component = i[0]
                permission = i[3]
                hasAnyNonGoogleActions = i[4]
                has_any_actions_in_intent_filter = i[5]
                isSyncAdapterService = i[6]
                is_dangerous = False
                if permission == "":  #permission is not set
                    is_dangerous = True
                else:  #permission is set
                    if permission in self.context.PermissionName_to_ProtectionLevel:
                        protectionLevel = self.context.PermissionName_to_ProtectionLevel[permission]
                        if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
                            is_dangerous = True
                            # else: #cannot find the mapping permission
                            # 	is_dangerous = True

                if is_dangerous:
                    if (component == "service") and has_any_actions_in_intent_filter and (not isSyncAdapterService):
                        self.list_implicit_service_components.append(i[1])

                    if hasAnyNonGoogleActions:
                        if i not in list_alerting_exposing_components_NonGoogle:
                            list_alerting_exposing_components_NonGoogle.append(i)
                    else:
                        if i not in list_alerting_exposing_components_Google:
                            list_alerting_exposing_components_Google.append(i)

            if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google:
                if list_alerting_exposing_components_NonGoogle:
                    self.context.writer.startWriter("PERMISSION_EXPORTED", LEVEL_WARNING, "AndroidManifest Exported Components Checking",
                                       """Found "exported" components(except for Launcher) for receiving outside applications' actions (AndroidManifest.xml).
        These components can be initilized by other apps. You should add or modify the attribute to [exported="false"] if you don't want to.
        You can also protect it with a customized permission with "signature" or higher protectionLevel and specify in "android:permission" attribute.""")

                    for i in list_alerting_exposing_components_NonGoogle:
                        self.context.writer.write(("%10s => %s") % (i[0], i[1]))

                if list_alerting_exposing_components_Google:
                    self.context.writer.startWriter("PERMISSION_EXPORTED_GOOGLE", LEVEL_NOTICE,
                                       "AndroidManifest Exported Components Checking 2",
                                       "Found \"exported\" components(except for Launcher) for receiving Google's \"Android\" actions (AndroidManifest.xml):")

                    for i in list_alerting_exposing_components_Google:
                        self.context.writer.write(("%10s => %s") % (i[0], i[1]))
            else:
                self.context.writer.startWriter("PERMISSION_EXPORTED", LEVEL_INFO, "AndroidManifest Exported Components Checking",
                                   "No exported components(except for Launcher) for receiving Android or outside applications' actions (AndroidManifest.xml).")


        def provider_check(self):

            #"exported" checking (provider):
            # android:readPermission, android:writePermission, android:permission
            list_ready_to_check = []

            xml = self.context.a.get_AndroidManifest()
            for item in xml.getElementsByTagName("provider"):
                name = item.getAttribute("android:name")
                exported = item.getAttribute("android:exported")

                if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):
                    #exported is only "true" or non-set
                    permission = item.getAttribute("android:permission")
                    readPermission = item.getAttribute("android:readPermission")
                    writePermission = item.getAttribute("android:writePermission")
                    has_exported = True if (exported != "") else False

                    list_ready_to_check.append(
                        (self.context.a.format_value(name), exported, permission, readPermission, writePermission, has_exported))

            list_alerting_exposing_providers_no_exported_setting = []  #providers that Did not set exported
            list_alerting_exposing_providers = []  #provider with "true" exported
            for i in list_ready_to_check:  #only exist "exported" provider or not set
                exported = i[1]
                permission = i[2]
                readPermission = i[3]
                writePermission = i[4]
                has_exported = i[5]

                is_dangerous = False
                list_perm = []
                if permission != "":
                    list_perm.append(permission)
                if readPermission != "":
                    list_perm.append(readPermission)
                if writePermission != "":
                    list_perm.append(writePermission)

                if list_perm:  #among "permission" or "readPermission" or "writePermission", any of the permission is set
                    for self_defined_permission in list_perm:  #(1)match any (2)ignore permission that is not found
                        if self_defined_permission in self.context.PermissionName_to_ProtectionLevel:
                            protectionLevel = self.context.PermissionName_to_ProtectionLevel[self_defined_permission]
                            if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
                                is_dangerous = True
                                break
                    if (exported == "") and (self.context.int_target_sdk >= 17) and (
                            is_dangerous):  #permission is not set, it will depend on the Android system
                        list_alerting_exposing_providers_no_exported_setting.append(i)

                else:  #none of any permission
                    if exported.lower() == "true":
                        is_dangerous = True
                    elif (exported == "") and (
                                self.context.int_target_sdk >= 17):  #permission is not set, it will depend on the Android system
                        list_alerting_exposing_providers_no_exported_setting.append(i)

                if is_dangerous:
                    list_alerting_exposing_providers.append(
                        i)  #exported="true" and none of the permission are set => of course dangerous

            if list_alerting_exposing_providers or list_alerting_exposing_providers_no_exported_setting:
                if list_alerting_exposing_providers_no_exported_setting:  #providers that Did not set exported

                    self.context.writer.startWriter("PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_CRITICAL,
                                       "AndroidManifest ContentProvider Exported Checking",
                                       """We strongly suggest you explicitly specify the "exported" attribute (AndroidManifest.xml).
        For Android "android:targetSdkVersion" < 17, the exported value of ContentProvider is "true" by default.
        For Android "android:targetSdkVersion" >= 17, the exported value of ContentProvider is "false" by default.
        Which means if you do not explicitly set the "android:exported", you will expose your ContentProvider to Android < 4.2 devices.
        Even if you set the provider the permission with [protectionalLevel="normal"], other apps still cannot access it on Android >= 4.2 devices because of the default constraint.
        Please make sure to set exported to "true" if you initially want other apps to use it (including protected by "signature" protectionalLevel), and set to "false" if your do not want to.
        Please still specify the "exported" to "true" if you have already set the corresponding "permission", "writePermission" or "readPermission" to "signature" protectionLevel or higher
        because other apps signed by the same signature in Android >= 4.2 devices cannot access it.
        Reference: http://developer.android.com/guide/topics/manifest/provider-element.html#exported
        Vulnerable ContentProvider Case Example:
          (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
          (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
          (3)http://www.wooyun.org/bugs/wooyun-2010-039169
        """)

                    for i in list_alerting_exposing_providers_no_exported_setting:
                        self.context.writer.write(("%10s => %s") % ("provider", i[0]))

                if list_alerting_exposing_providers:  #provider with "true" exported and not enough permission protected on it

                    self.context.writer.startWriter("PERMISSION_PROVIDER_EXPLICIT_EXPORTED", LEVEL_CRITICAL,
                                       "AndroidManifest ContentProvider Exported Checking",
                                       """Found "exported" ContentProvider, allowing any other app on the device to access it (AndroidManifest.xml). You should modify the attribute to [exported="false"] or set at least "signature" protectionalLevel permission if you don't want to.
        Vulnerable ContentProvider Case Example:
          (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
          (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
          (3)http://www.wooyun.org/bugs/wooyun-2010-039169""")
                    for i in list_alerting_exposing_providers:
                        self.context.writer.write(("%10s => %s") % ("provider", i[0]))

            else:
                self.context.writer.startWriter("PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_INFO,
                                   "AndroidManifest ContentProvider Exported Checking",
                                   "No exported \"ContentProvider\" found (AndroidManifest.xml).")


        def intent_filter_check(self):


            """
                Example misconfiguration:
                    <receiver android:name=".service.push.SystemBroadcastReceiver">
                        <intent-filter android:enabled="true" android:exported="false">
                            <action android:name="android.intent.action.BOOT_COMPLETED" />
                            <action android:name="android.intent.action.USER_PRESENT" />
                        </intent-filter>
                        <intent-filter android:enabled="true" android:exported="false">
                        </intent-filter>
                    </receiver>

                Detected1: <intent-filter android:enabled="true" android:exported="false">
                Detected2: No actions in "intent-filter"
            """

            find_tags = ["activity", "activity-alias", "service", "receiver"]
            xml = self.context.a.get_AndroidManifest()
            list_wrong_intent_filter_settings = []
            list_no_actions_in_intent_filter = []
            for tag in find_tags:
                for sitem in xml.getElementsByTagName(tag):
                    isDetected1 = False
                    isDetected2 = False
                    for ssitem in sitem.getElementsByTagName("intent-filter"):
                        if (ssitem.getAttribute("android:enabled") != "") or (ssitem.getAttribute("android:exported") != ""):
                            isDetected1 = True
                        if len(sitem.getElementsByTagName("action")) == 0:
                            isDetected2 = True
                    if isDetected1:
                        list_wrong_intent_filter_settings.append((tag, sitem.getAttribute("android:name")))
                    if isDetected2:
                        list_no_actions_in_intent_filter.append((tag, sitem.getAttribute("android:name")))

            if list_wrong_intent_filter_settings or list_no_actions_in_intent_filter:
                if list_wrong_intent_filter_settings:
                    self.context.writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_WARNING,
                                       "AndroidManifest \"intent-filter\" Settings Checking",
                                       """Misconfiguration in "intent-filter" of these components (AndroidManifest.xml).
        Config "intent-filter" should not have "android:exported" or "android:enabled" attribute.
        Reference: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
        """)
                    for tag, name in list_wrong_intent_filter_settings:
                        self.context.writer.write(("%10s => %s") % (tag, self.context.a.format_value(name)))

                if list_no_actions_in_intent_filter:
                    self.context.writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_CRITICAL,
                                       "AndroidManifest \"intent-filter\" Settings Checking",
                                       """Misconfiguration in "intent-filter" of these components (AndroidManifest.xml).
        Config "intent-filter" should have at least one "action".
        Reference: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
        """)
                    for tag, name in list_no_actions_in_intent_filter:
                        self.context.writer.write(("%10s => %s") % (tag, self.context.a.format_value(name)))
            else:
                self.context.writer.startWriter("PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_INFO,
                                   "AndroidManifest \"intent-filter\" Settings Checking",
                                   "\"intent-filter\" of AndroidManifest.xml check OK.")


        def implicit_service_check(self):

            #Implicit Service (** Depend on: "exported" checking (activity, activity-alias, service, receiver) **)

            if self.list_implicit_service_components:
                self.context.writer.startWriter("PERMISSION_IMPLICIT_SERVICE", LEVEL_CRITICAL, "Implicit Service Checking",
                                   """To ensure your app is secure, always use an explicit intent when starting a Service and DO NOT declare intent filters for your services. Using an implicit intent to start a service is a security hazard because you cannot be certain what service will respond to the intent, and the user cannot see which service starts.
        Reference: http://developer.android.com/guide/components/intents-filters.html#Types""", ["Implicit_Intent"])

                for name in self.list_implicit_service_components:
                    self.context.writer.write(("=> %s") % (self.context.a.format_value(name)))

            else:
                self.context.writer.startWriter("PERMISSION_IMPLICIT_SERVICE", LEVEL_INFO, "Implicit Service Checking",
                                   "No dangerous implicit service.", ["Implicit_Intent"])


