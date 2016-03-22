#coding:utf8




from VulnerabilityVector import VulnerabilityVector
from .. import *



class URLs_check(VulnerabilityVector):

       def __init__(self,context):

            self.context = context




       def  analyze(self):


            exception_url_string = ["http://example.com",
                                "http://example.com/",
                                "http://www.example.com",
                                "http://www.example.com/",
                                "http://www.google-analytics.com/collect",
                                "http://www.google-analytics.com",
                                "http://hostname/?",
                                "http://hostname/"]

            for line in self.context.allstrings:
                if re.match('http\:\/\/(.+)', line):  #^https?\:\/\/(.+)$
                    self.context.allurls_strip_duplicated.append(line)

            allurls_strip_non_duplicated = sorted(set(self.context.allurls_strip_duplicated))
            allurls_strip_non_duplicated_final = []

            if allurls_strip_non_duplicated:
                for url in allurls_strip_non_duplicated:
                    if (url not in exception_url_string) and (not url.startswith("http://schemas.android.com/")) and \
                            (not url.startswith("http://www.w3.org/")) and \
                            (not url.startswith("http://apache.org/")) and \
                            (not url.startswith("http://xml.org/")) and \
                            (not url.startswith("http://localhost/")) and \
                            (not url.startswith("http://java.sun.com/")) and \
                            (not url.endswith("/namespace")) and \
                            (not url.endswith("-dtd")) and \
                            (not url.endswith(".dtd")) and \
                            (not url.endswith("-handler")) and \
                            (not url.endswith("-instance")):
                        # >>>>STRING_SEARCH<<<<
                        self.context.efficientStringSearchEngine.addSearchItem(url, url, False)  #use url as "key"

                        allurls_strip_non_duplicated_final.append(url)



            # ------------------------------------------------------------------------

            # >>>>STRING_SEARCH<<<<

            #start the search core engine
            self.context.efficientStringSearchEngine.search(self.context.d, self.context.allstrings)

            # ------------------------------------------------------------------------

            #pre-run to avoid all the urls are in exclusion list but the results are shown
            allurls_strip_non_duplicated_final_prerun_count = 0
            for url in allurls_strip_non_duplicated_final:
                dict_class_to_method_mapping = self.context.efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                    url)
                if self.context.filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
                    allurls_strip_non_duplicated_final_prerun_count = allurls_strip_non_duplicated_final_prerun_count + 1

            if allurls_strip_non_duplicated_final_prerun_count != 0:
                self.context.writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_CRITICAL, "SSL Connection Checking",
                                   "URLs that are NOT under SSL (Total:" + str(
                                       allurls_strip_non_duplicated_final_prerun_count) + "):", ["SSL_Security"])

                for url in allurls_strip_non_duplicated_final:

                    dict_class_to_method_mapping = self.context.efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
                        url)
                    if not self.context.filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
                        continue

                    self.context.writer.write(url)

                    try:
                        if dict_class_to_method_mapping:  #Found the corresponding url in the code
                            for _, result_method_list in dict_class_to_method_mapping.items():
                                for result_method in result_method_list:  #strip duplicated item
                                    if self.context.filteringEngine.is_class_name_not_in_exclusion(result_method.get_class_name()):
                                        source_classes_and_functions = (
                                            result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
                                        self.context.writer.write("    => " + source_classes_and_functions)

                    except KeyError:
                        pass

            else:
                self.context.writer.startWriter("SSL_URLS_NOT_IN_HTTPS", LEVEL_INFO, "SSL Connection Checking",
                                   "Did not discover urls that are not under SSL (Notice: if you encrypt the url string, we can not discover that).",
                                   ["SSL_Security"])


