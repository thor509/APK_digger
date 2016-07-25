#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class HttpCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):
            #only for apk analysis #added by heen
            if self.context.a is not None:
                self.httpconnection_check()

        def  httpconnection_check(self):
                #HttpURLConnection bug checking:

                """
                    Example Java code:
                        private void disableConnectionReuseIfNecessary() {
                            // Work around pre-Froyo bugs in HTTP connection reuse.
                            if (Integer.parseInt(Build.VERSION.SDK) < Build.VERSION_CODES.FROYO) {
                                System.setProperty("http.keepAlive", "false");
                            }
                        }

                    Example Bytecode code:
                        const-string v0, "http.keepAlive"
                        const-string v1, "false"
                        invoke-static {v0, v1}, Ljava/lang/System;->setProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

                """

                if (self.context.int_min_sdk is not None) and (self.context.int_min_sdk <= 8):

                    pkg_HttpURLConnection = self.context.vmx.get_tainted_packages().search_packages("Ljava/net/HttpURLConnection;")
                    pkg_HttpURLConnection = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_HttpURLConnection)

                    #Check only when using the HttpURLConnection
                    if pkg_HttpURLConnection:

                        list_pre_Froyo_HttpURLConnection = []
                        path_pre_Froyo_HttpURLConnection = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                            "Ljava/lang/System;", "setProperty", "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;")
                        path_pre_Froyo_HttpURLConnection = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_pre_Froyo_HttpURLConnection)

                        has_http_keepAlive_Name = False
                        has_http_keepAlive_Value = False

                        for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_pre_Froyo_HttpURLConnection):
                            if i.getResult()[0] == "http.keepAlive":
                                has_http_keepAlive_Name = True
                                list_pre_Froyo_HttpURLConnection.append(i.getPath())  #Only list the "false" one
                                if i.getResult()[1] == "false":
                                    has_http_keepAlive_Value = True
                                    break

                        if has_http_keepAlive_Name:
                            if has_http_keepAlive_Value:
                                self.context.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android Bug Checking",
                                                   "System property \"http.keepAlive\" for \"HttpURLConnection\" sets correctly.")

                            else:
                                output_string = """You should set System property "http.keepAlive" to "false"
            You're using "HttpURLConnection". Prior to Android 2.2 (Froyo), "HttpURLConnection" had some frustrating bugs.
            In particular, calling close() on a readable InputStream could poison the connection pool. Work around this by disabling connection pooling:
            Please check the reference:
             (1)http://developer.android.com/reference/java/net/HttpURLConnection.html
             (2)http://android-developers.blogspot.tw/2011/09/androids-http-clients.html"""
                                self.context.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE, "HttpURLConnection Android Bug Checking",
                                                   output_string)

                                self.context.writer.show_Paths(self.context.d, list_pre_Froyo_HttpURLConnection)  #Notice: list_pre_Froyo_HttpURLConnection
                        else:
                            output_string = """You're using "HttpURLConnection". Prior to Android 2.2 (Froyo), "HttpURLConnection" had some frustrating bugs.
            In particular, calling close() on a readable InputStream could poison the connection pool. Work around this by disabling connection pooling.
            Please check the reference:
             (1)http://developer.android.com/reference/java/net/HttpURLConnection.html
             (2)http://android-developers.blogspot.tw/2011/09/androids-http-clients.html"""

                            self.context.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_NOTICE, "HttpURLConnection Android Bug Checking",
                                               output_string)
                            #Make it optional to list library
                            self.context.writer.show_Paths(self.context.d, pkg_HttpURLConnection)  #Notice: pkg_HttpURLConnection

                    else:
                        self.context.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android Bug Checking",
                                           "Ignore checking \"http.keepAlive\" because you're not using \"HttpURLConnection\".")

                else:
                    self.context.writer.startWriter("HTTPURLCONNECTION_BUG", LEVEL_INFO, "HttpURLConnection Android Bug Checking",
                                       "Ignore checking \"http.keepAlive\" because you're not using \"HttpURLConnection\" and min_Sdk > 8.")





