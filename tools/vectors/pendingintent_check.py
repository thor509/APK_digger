#coding:utf_8
#added by heen


from .. import *
from VulnerabilityVector import VulnerabilityVector

class  PendingIntentLeakCheck(VulnerabilityVector):

    def __init__(self,context):

        self.context = context

    def analyze(self):

        # check if PendingIntent with null intent is leaked to third party,
        # so that the third party can change the original intent

        """
        example vulnerable Java Code:
                Intent intent = new Intent("PENDINGINTENT.VULAPP.SERVICE.ACTION") ;

                intent.putExtra("app", PendingIntent.getBroadcast(m_context, 0, new Intent(),0));
                //getActivity or getService or getActivities
                // put a PendingIntent with null intent as bundle extra in another intent for IPC !!

                ResolveInfo resolveInfo = getPackageManager().resolveService(intent, 0);
                intent.setPackage(resolveInfo.serviceInfo.packageName);

                startService(intent);


        example smali code, note the sequence!:
                new-instance v4, Landroid/content/Intent;

                invoke-direct {v4}, Landroid/content/Intent;-><init>()V

                invoke-static {v3, v5, v4, v5}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

                move-result-object v3

                invoke-virtual {v0, v2, v3}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

        reference:
            http://drops.wooyun.org/papers/3912
            https://t.co/xEZLRUw17x

        """
        ##Step 1: find all method of PendingIntent
        list_path_suspicious_method = []
        path_getbroadcast = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                                "Landroid/app/PendingIntent;",
                                 "getBroadcast" ,
                                "(Landroid/content/Context; I Landroid/content/Intent; I)Landroid/app/PendingIntent;")
        path_getbroadcast = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getbroadcast)
        if path_getbroadcast: list_path_suspicious_method.extend(path_getbroadcast)

        path_getactivity = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
            "Landroid/app/PendingIntent;",
            "getActivity" ,
            "(Landroid/content/Context; I Landroid/content/Intent; I)Landroid/app/PendingIntent;")
        path_getactivity= self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getactivity)
        if path_getactivity: list_path_suspicious_method.extend(path_getactivity)

        path_getService= self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
            "Landroid/app/PendingIntent;",
            "getService" ,
            "(Landroid/content/Context; I Landroid/content/Intent; I)Landroid/app/PendingIntent;")
        path_getService= self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getService)
        if path_getService: list_path_suspicious_method.extend(path_getService)

        ##Step 2: Find the method which calls the PendingIntent method and analyze all instructions in it
        list_path_sure_method = []
        if list_path_suspicious_method:
            for pathp in list_path_suspicious_method:
                if (self.__analysis(pathp)): list_path_sure_method.append(pathp)

        if list_path_sure_method:
            self.context.writer.startWriter("PendingIntent Leaking", LEVEL_WARNING, "PendingIntent Leaking Checking",
                                            "PendingIntent Leaking Found: ",["PENDING_INTENT_LEAKING"])
            for path in list_path_sure_method:
                self.context.writer.show_Path(self.context.d, path)
            self.context.writer.write("Please confirm if PendingIntent with null intent is leaking! ")



        list_path_other = []
        print "sure pending intent method:"
        print list_path_sure_method

        print "suspicious pending intent method:"
        print list_path_suspicious_method

        if list_path_suspicious_method:
            list_path_other = list(set(list_path_suspicious_method) - set(list_path_sure_method))

        if list_path_other:
            print "other pending intent method:"
            print list_path_other
            self.context.writer.startWriter("PendingIntent Info", LEVEL_NOTICE, "PendingIntent Leaking Checking",
                                            "PendingIntent Found: ",["PENDING_INTENT_INFO"])

            for pathp in list_path_other:
                for path in pathp:
                        self.context.writer.show_Path(self.context.d, path)
            self.context.writer.write("Please confirm if PendingIntent with null intent is leaking! ")

    def __analysis(self,path_pending_intent_method):
        '''
        :param path_pending_intent_method: all  PathP object of suspicious method
        :return: isLeaking: True of False
        '''
        isLeaking = False
        method_call_pending_intent = None

        # find out who call the suspicious method
        src_class_name, src_method_name, src_descriptor  = path_pending_intent_method.get_src(self.context.cm)
        for cls in self.context.d.get_classes():
            if (cls.get_name() != src_class_name):
                continue
            for method in cls.get_methods():
                if (method.get_name() != src_method_name):
                    continue
                method_call_pending_intent = method

        ## Analyze the instruction, if a nulll intent is used in the PendingIntent->getXXXX, PendingIntent Leaking happens
        register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(method_call_pending_intent.get_instructions())
        #######################################################
        # For Debugging, print all the instructions in stack#
        #
        #print register_analyzer.show()
        ######################################################k
        i = 0
        match_once = 0
        match_twice = 100000 #just a very big integer
        for ins in register_analyzer.get_stack().gets():
            #invoke-direct {v4}, Landroid/content/Intent;-><init>()V
            if (ins[0] == 0x70 and ins[1][-1][-1] == "Landroid/content/Intent;-><init>()V"):
                match_once = i
            #invoke-static {v3, v5, v4, v5}, Landroid/app/PendingIntent;->getBroadcast(Landro id/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
            if (ins[0] == 0x71 and ins[1][-1][-1] == "Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context; I Landroid/content/Intent; I)Landroid/app/PendingIntent;"):
                match_twice = i
            i = i + 1

        if (match_twice - match_once < 5): #means the two instruction is close to each other
            isLeaking = True
        else:
            isLeaking = False
        return  isLeaking

