#coding:utf8






from .. import *
from VulnerabilityVector import VulnerabilityVector




class ScreenshotprentCheck(VulnerabilityVector):

       def __init__(self,context):

            self.context = context




       def  analyze(self):

            #Developers preventing screenshot capturing checking:

            """
                Example:
                    const/16 v1, 0x2000
                    invoke-super {p0, p1}, Landroid/support/v7/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V
                    invoke-virtual {p0}, Lcom/example/preventscreencapture/MainActivity;->getWindow()Landroid/view/Window;
                    move-result-object v0
                    invoke-virtual {v0, v1, v1}, Landroid/view/Window;->setFlags(II)V


                    getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
            """

            list_code_for_preventing_screen_capture = []
            path_code_for_preventing_screen_capture = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/view/Window;", "setFlags", "(I I)V")
            path_code_for_preventing_screen_capture = self.context.filteringEngine.filter_list_of_paths(self.context.d,
                                                                                           path_code_for_preventing_screen_capture)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_code_for_preventing_screen_capture):
                if (i.getResult()[1] is None) or (i.getResult()[2] is None):
                    continue
                if (not isinstance(i.getResult()[1], (int, long))) or (not isinstance(i.getResult()[2], (int, long))):
                    continue
                if (i.getResult()[1] & 0x2000) and (i.getResult()[2] & 0x2000):
                    list_code_for_preventing_screen_capture.append(i.getPath())

            if list_code_for_preventing_screen_capture:
                self.context.writer.startWriter("HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_NOTICE,
                                   "Code Setting Preventing Screenshot Capturing",
                                   """This app has code setting the preventing screenshot capturing.
        Example: getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        It is used by the developers to protect the app:""", ["Hacker"])
                for interesting_code in list_code_for_preventing_screen_capture:
                    self.context.writer.show_Path(self.context.d, interesting_code)
            else:
                self.context.writer.startWriter("HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_INFO,
                                   "Code Setting Preventing Screenshot Capturing",
                                   "Did not detect this app has code setting preventing screenshot capturing.", ["Hacker"])


