#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class ExecCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            #Runtime exec checking:

            """
                Example Java code:
                    1. Runtime.getRuntime().exec("");
                    2. Runtime rr = Runtime.getRuntime(); Process p = rr.exec("ls -al");

                Example Bytecode code (The same bytecode for those two Java code):
                    const-string v2, "ls -al"
                    invoke-virtual {v1, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
            """

            list_Runtime_exec = []

            path_Runtime_exec = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/lang/Runtime;", "exec",
                                                                                            "(Ljava/lang/String;)Ljava/lang/Process;")
            path_Runtime_exec = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_Runtime_exec)

            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_Runtime_exec):
                if i.getResult()[1] is None:
                    continue
                if i.getResult()[1] == "su":
                    list_Runtime_exec.append(i.getPath())

            if path_Runtime_exec:
                self.context.writer.startWriter("COMMAND", LEVEL_CRITICAL, "Runtime Command Checking",
                                   "This app is using critical function 'Runtime.getRuntime().exec(\"...\")'.\nPlease confirm these following code secions are not harmful:",
                                   ["Command"])

                self.context.writer.show_Paths(self.context.d, path_Runtime_exec)

                if list_Runtime_exec:
                    self.context.writer.startWriter("COMMAND_SU", LEVEL_CRITICAL, "Runtime Critical Command Checking",
                                       "Requesting for \"root\" permission code sections 'Runtime.getRuntime().exec(\"su\")' found (Critical but maybe false positive):",
                                       ["Command"])

                    for path in list_Runtime_exec:
                        self.context.writer.show_Path(self.context.d, path)
            else:
                self.context.writer.startWriter("COMMAND", LEVEL_INFO, "Runtime Command Checking",
                                   "This app is not using critical function 'Runtime.getRuntime().exec(\"...\")'.", ["Command"])





