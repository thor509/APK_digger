#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class RootCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            #Searching checking root or not:
            result_possibly_check_root = self.context.efficientStringSearchEngine.get_search_result_by_match_id("$__possibly_check_root__")
            result_possibly_check_su = self.context.efficientStringSearchEngine.get_search_result_by_match_id("$__possibly_check_su__")
            result_possibly_root_total = []

            if result_possibly_check_root:
                result_possibly_root_total.extend(result_possibly_check_root)

            if result_possibly_check_su:
                result_possibly_root_total.extend(result_possibly_check_su)

            result_possibly_root_total = self.context.filteringEngine.filter_efficient_search_result_value(result_possibly_root_total)

            if result_possibly_root_total:
                self.context.writer.startWriter("COMMAND_MAYBE_SYSTEM", LEVEL_NOTICE, "Executing \"root\" or System Privilege Checking",
                                   "The app may has the code checking for \"root\" permission, mounting filesystem operations or monitoring system:",
                                   ["Command"])

                list_possible_root = []
                list_possible_remount_fs = []
                list_possible_normal = []

                for found_string, method in set(result_possibly_root_total):  #strip the duplicated items
                    if ("'su'" == found_string) or ("/su" in found_string):
                        list_possible_root.append((found_string, method, True))  #3rd parameter: show string or not
                    elif "mount" in found_string:  #mount, remount
                        list_possible_remount_fs.append((found_string, method, True))
                    else:
                        list_possible_normal.append((found_string, method, True))

                lst_ordered_finding = []
                lst_ordered_finding.extend(list_possible_root)
                lst_ordered_finding.extend(list_possible_remount_fs)
                lst_ordered_finding.extend(list_possible_normal)

                for found_string, method, show_string in lst_ordered_finding:
                    if show_string:
                        self.context.writer.write(
                            method.get_class_name() + "->" + method.get_name() + method.get_descriptor() + "  => " + found_string)
                    else:
                        self.context.writer.write(method.get_class_name() + "->" + method.get_name() + method.get_descriptor())
            else:

                self.context.writer.startWriter("COMMAND_MAYBE_SYSTEM", LEVEL_INFO, "Executing \"root\" or System Privilege Checking",
                                   "Did not find codes checking \"root\" permission(su) or getting system permission (It's still possible we did not find out).",
                                   ["Command"])






