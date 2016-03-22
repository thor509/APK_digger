#coding:utf8




import base64

from .. import *
from VulnerabilityVector import VulnerabilityVector




class Base64check(VulnerabilityVector):

       def __init__(self,context):

            self.context = context




       def  analyze(self):





            #Base64 String decoding:

            organized_list_base64_success_decoded_string_to_original_mapping = []
            for decoded_string, original_string in self.context.list_base64_success_decoded_string_to_original_mapping.items():
                dict_class_to_method_mapping = self.context.efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                    original_string)
                if self.context.filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
                    """
                        All of same string found are inside the excluded packages.
                        Only the strings found the original class will be added.
                    """
                    organized_list_base64_success_decoded_string_to_original_mapping.append(
                        (decoded_string, original_string, dict_class_to_method_mapping))

            if organized_list_base64_success_decoded_string_to_original_mapping:  #The result is from the upper code section

                list_base64_decoded_urls = {}

                self.context.writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_CRITICAL, "Base64 String Encryption",
                                   "Found Base64 encoding \"String(s)\" (Total: " + str(len(
                                       organized_list_base64_success_decoded_string_to_original_mapping)) + "). We cannot guarantee all of the Strings are Base64 encoding and also we will not show you the decoded binary file:",
                                   ["Hacker"])

                for decoded_string, original_string, dict_class_to_method_mapping in organized_list_base64_success_decoded_string_to_original_mapping:

                    self.context.writer.write(decoded_string)
                    self.context.writer.write("    ->Original Encoding String: " + original_string)

                    if dict_class_to_method_mapping:
                        for class_name, result_method_list in dict_class_to_method_mapping.items():
                            for result_method in result_method_list:
                                source_classes_and_functions = (
                                    result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
                                self.context.writer.write("    ->From class: " + source_classes_and_functions)

                    if "http://" in decoded_string:
                        list_base64_decoded_urls[decoded_string] = original_string

                if list_base64_decoded_urls:

                    self.context.writer.startWriter("HACKER_BASE64_URL_DECODE", LEVEL_CRITICAL, "Base64 String Encryption",
                                       "Base64 encoding \"HTTP URLs without SSL\" from all the Strings (Total: " + str(
                                           len(list_base64_decoded_urls)) + ")", ["SSL_Security", "Hacker"])

                    for decoded_string, original_string in list_base64_decoded_urls.items():

                        dict_class_to_method_mapping = self.context.efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                            original_string)

                        if not self.context.filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(
                                dict_class_to_method_mapping):  #All of the same string found are inside the excluded packages
                            continue

                        self.context.writer.write(decoded_string)
                        self.context.writer.write("    ->Original Encoding String: " + original_string)

                        if dict_class_to_method_mapping:
                            for class_name, result_method_list in dict_class_to_method_mapping.items():
                                for result_method in result_method_list:
                                    source_classes_and_functions = (
                                        result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
                                    self.context.writer.write("    ->From class: " + source_classes_and_functions)

            else:
                self.context.writer.startWriter("HACKER_BASE64_STRING_DECODE", LEVEL_INFO, "Base64 String Encryption",
                                   "No encoded Base64 String or Urls found.", ["Hacker"])
