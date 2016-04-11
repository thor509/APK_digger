#coding:utf8
#added by heen


from .. import *
from VulnerabilityVector import VulnerabilityVector

class  DynamicReceiverCheck(VulnerabilityVector):

    def __init__(self,context):

        self.context = context



    def analyze(self):

        # find dynamic receiver which cannot shown in AndroidMainifest.xml
        """
            example java code:
                IntentFilter filter = new IntentFilter("android.provider.Telephony.SMS_RECEIVED");
                filter.setPriority(2147483647);
                MySmsReceiver smsReceiver = new MySmsReceiver();
                registerReceiver(smsReceiver, filter);

            example smali code:
                invoke-direct {v0, v4}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V
                invoke-virtual {p0, v3, v0}, Lcom/heen/mysmsmonitor/MainActivity;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

            it is an abstract method in
                 Context.registerReceiver

        """

         # note, there is a white space between multi args !!!
        path_dyn_receiver = self.context.vmx.get_tainted_packages().search_methods_exact_match("registerReceiver","(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;)Landroid/content/Intent;")
       # path_dyn_receiver = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/content/IntentFilter;","<init>","(Ljava/lang/String;)V")
        path_dyn_receiver = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_dyn_receiver)

        if path_dyn_receiver:
            self.context.writer.startWriter("Dynamic Receiver Info", LEVEL_NOTICE, "Dynamic Receiver Checking",
                                            "Dynamic Receiver Found: ",["DYN_RECEIVER"])
            for path in path_dyn_receiver:
                self.context.writer.show_Path(self.context.d, path)

