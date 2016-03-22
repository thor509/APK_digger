#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class WebviewCheck(VulnerabilityVector):

       def __init__(self,context):

            self.context = context




       def analyze(self):

            self.addJavascriptcheck()

            self.setJavaScriptcheck()

            self.setAllowFileAccess_check()



       def addJavascriptcheck(self):



            #WebView addJavascriptInterface checking:

            #Don't match class name because it might use the subclass of WebView
            path_WebView_addJavascriptInterface = self.context.vmx.get_tainted_packages().search_methods_exact_match(
                "addJavascriptInterface", "(Ljava/lang/Object; Ljava/lang/String;)V")
            path_WebView_addJavascriptInterface = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_WebView_addJavascriptInterface)

            if path_WebView_addJavascriptInterface:

                output_string = """Found a critical WebView "addJavascriptInterface" vulnerability. This method can be used to allow JavaScript to control the host application.
        This is a powerful feature, but also presents a security risk for applications targeted to API level JELLY_BEAN(4.2) or below, because JavaScript could use reflection to access an injected object's public fields. Use of this method in a WebView containing untrusted content could allow an attacker to manipulate the host application in unintended ways, executing Java code with the permissions of the host application.
        Reference:
          1."http://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String) "
          2.https://labs.mwrinfosecurity.com/blog/2013/09/24/webview-addjavascriptinterface-remote-code-execution/
          3.http://50.56.33.56/blog/?p=314
          4.http://blog.trustlook.com/2013/09/04/alert-android-webview-addjavascriptinterface-code-execution-vulnerability/
        Please modify the below code:"""

                self.context.writer.startWriter("WEBVIEW_RCE", LEVEL_CRITICAL, "WebView RCE Vulnerability Checking", output_string,
                                   ["WebView", "Remote Code Execution"], "CVE-2013-4710")
                self.context.writer.show_Paths(self.context.d, path_WebView_addJavascriptInterface)

            else:

                self.context.writer.startWriter("WEBVIEW_RCE", LEVEL_INFO, "WebView RCE Vulnerability Checking",
                                   "WebView addJavascriptInterface vulnerabilities not found.",
                                   ["WebView", "Remote Code Execution"], "CVE-2013-4710")


       def setJavaScriptcheck(self):

            #WebView setJavaScriptEnabled - Potential XSS:

            """
                Java Example code:
                    webView1 = (WebView)findViewById(R.id.webView1);
                    webView1.setWebViewClient(new ExtendedWebView());
                    WebSettings webSettings = webView1.getSettings();
                    webSettings.setJavaScriptEnabled(true);

                Smali Example code:
                    const/4 v1, 0x1
                    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
            """

            list_setJavaScriptEnabled_XSS = []
            path_setJavaScriptEnabled_XSS = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V")
            path_setJavaScriptEnabled_XSS = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_setJavaScriptEnabled_XSS)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_setJavaScriptEnabled_XSS):
                if i.getResult()[1] is None:
                    continue
                if i.getResult()[1] == 0x1:
                    list_setJavaScriptEnabled_XSS.append(i.getPath())

            if list_setJavaScriptEnabled_XSS:
                self.context.writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_WARNING, "WebView Potential XSS Attacks Checking",
                                   "Found \"setJavaScriptEnabled(true)\" in WebView, which could exposed to potential XSS attacks. Please check the web page code carefully and sanitize the output:",
                                   ["WebView"])
                for i in list_setJavaScriptEnabled_XSS:
                    self.context.writer.show_Path(self.context.d, i)
            else:
                self.context.writer.startWriter("WEBVIEW_JS_ENABLED", LEVEL_INFO, "WebView Potential XSS Attacks Checking",
                                   "Did not detect \"setJavaScriptEnabled(true)\" in WebView.", ["WebView"])



       def setAllowFileAccess_check(self):

            #WebView setAllowFileAccess:

            """
                Get all "dst" class: Landroid/webkit/WebSettings;
                  => Categorized by src function,
                     If the src function:
                       1.setAllowFileAccess does not exist    OR
                       2.setAllowFileAccess(true)
                           =>src function may be vulnerable

                **Why check WebSettings? It's because WebView almost always uses the method: WebView->getSettings()

                **Even if the below example, it will finally call WebSettings:
                  class TestWebView extends WebView {
                    public TestWebView(Context context) {
                      super(context);
                    }
                  }
            """

            pkg_WebView_WebSettings = self.context.vmx.get_tainted_packages().search_packages("Landroid/webkit/WebSettings;")
            pkg_WebView_WebSettings = self.context.filteringEngine.filter_list_of_paths(self.context.d, pkg_WebView_WebSettings)

            dict_WebSettings_ClassMethod_to_Path = {}

            for path in pkg_WebView_WebSettings:
                src_class_name, src_method_name, src_descriptor = path.get_src(self.context.cm)
                dst_class_name, dst_method_name, dst_descriptor = path.get_dst(self.context.cm)

                dict_name = src_class_name + "->" + src_method_name + src_descriptor
                if dict_name not in dict_WebSettings_ClassMethod_to_Path:
                    dict_WebSettings_ClassMethod_to_Path[dict_name] = []

                dict_WebSettings_ClassMethod_to_Path[dict_name].append((dst_method_name + dst_descriptor, path))

            path_setAllowFileAccess_vulnerable_ready_to_test = []
            path_setAllowFileAccess_confirm_vulnerable_src_class_func = []

            for class_fun_descriptor, value in dict_WebSettings_ClassMethod_to_Path.items():
                has_Settings = False
                for func_name_descriptor, path in value:
                    if func_name_descriptor == "setAllowFileAccess(Z)V":
                        has_Settings = True

                        # Add ready-to-test Path list
                        path_setAllowFileAccess_vulnerable_ready_to_test.append(path)
                        break

                if not has_Settings:
                    # Add vulnerable Path list
                    path_setAllowFileAccess_confirm_vulnerable_src_class_func.append(class_fun_descriptor)

            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d,
                                                                            path_setAllowFileAccess_vulnerable_ready_to_test):
                if (i.getResult()[1] == 0x1):  # setAllowFileAccess is true

                    path = i.getPath()
                    src_class_name, src_method_name, src_descriptor = path.get_src(self.context.cm)
                    dict_name = src_class_name + "->" + src_method_name + src_descriptor

                    if dict_name not in path_setAllowFileAccess_confirm_vulnerable_src_class_func:
                        path_setAllowFileAccess_confirm_vulnerable_src_class_func.append(dict_name)

            if path_setAllowFileAccess_confirm_vulnerable_src_class_func:

                path_setAllowFileAccess_confirm_vulnerable_src_class_func = sorted(
                    set(path_setAllowFileAccess_confirm_vulnerable_src_class_func))

                self.context.writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_WARNING, "WebView Local File Access Attacks Checking",
                                   """Found "setAllowFileAccess(true)" or not set(enabled by default) in WebView. The attackers could inject malicious script into WebView and exploit the opportunity to access local resources. This can be mitigated or prevented by disabling local file system access. (It is enabled by default)
        Note that this enables or disables file system access only. Assets and resources are still accessible using file:///android_asset and file:///android_res.
        The attackers can use "mWebView.loadUrl("file:///data/data/[Your_Package_Name]/[File]");" to access app's local file.
        Reference: (1)https://labs.mwrinfosecurity.com/blog/2012/04/23/adventures-with-android-webviews/
                   (2)http://developer.android.com/reference/android/webkit/WebSettings.html#setAllowFileAccess(boolean)
        Please add or modify "yourWebView.getSettings().setAllowFileAccess(false)" to your WebView:
        """, ["WebView"])
                for i in path_setAllowFileAccess_confirm_vulnerable_src_class_func:
                    self.context.writer.write(i)

            else:
                self.context.writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", LEVEL_INFO, "WebView Local File Access Attacks Checking",
                                   "Did not find potentially critical local file access settings.", ["WebView"])

