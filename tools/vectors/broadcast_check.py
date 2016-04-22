#coding:utf_8
#added by heen


from .. import *
from VulnerabilityVector import VulnerabilityVector

class  BroadcastCheck(VulnerabilityVector):

    def __init__(self,context):

        self.context = context

    def analyze(self):

        # check methods related to sendBroadcast, which may include sensitive information in broadcast bundles
        """
        sendBroadcast(Intent intent)
        sendBroadcast(Intent intent, String receiverPermission)
        sendOrderedBroadcast(Intent intent, String receiverPermission, BroadcastReceiver resultReceiver
                            ,Handler scheduler, int initialCode, String initialData, Bundle initialExtras)
        sendStickyBroadcast(Intent intent)

        example smali code:
            sendBroadcast(Landroid/content/Intent;)V

        reference:
            http://drops.wooyun.org/tips/4393

        """
        path_broadcast_normal = self.context.vmx.get_tainted_packages().search_methods_exact_match("sendBroadcast",
                           "(Landroid/content/Intent;)V")
        path_broadcast_normal = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_broadcast_normal)

        if path_broadcast_normal:
            self.context.writer.startWriter("Broadcast Information", LEVEL_NOTICE, "Broadcast Sending Checking",
                                            "Broadcast Found: ",["BROADCAST_INFO"])
            for path in path_broadcast_normal:
                self.context.writer.show_Path(self.context.d, path)
            self.context.writer.write("Please confirm if sensitive information is in the broadcast! ")


