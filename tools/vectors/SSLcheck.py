#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class SSLCheck(VulnerabilityVector):

        def __init__(self,context):

            self.context = context




        def analyze(self):

            self.ssl_hostname_check()

            self.ssl_getInsecure_check()

            self.ssl_httphost_check()
            self.ssl_WebView_check()

            self.certificate_verify_check()




        def ssl_hostname_check(self):



            #HTTPS ALLOW_ALL_HOSTNAME_VERIFIER checking:

            """
                Example Java code:
                    HttpsURLConnection.setDefaultHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

                Example Bytecode code (The same bytecode for those two Java code):
                    (1)
                    sget-object v11, Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;
                    invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

                    (2)
                    new-instance v11, Lcom/example/androidsslconnecttofbtest/MainActivity$2;
                    invoke-direct {v11, p0}, Lcom/example/androidsslconnecttofbtest/MainActivity$2;-><init>(Lcom/example/androidsslconnecttofbtest/MainActivity;)V
                    invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

                Scenario:
                    https://www.google.com/  => Google (SSL certificate is valid, CN: www.google.com)
                    https://60.199.175.18   => IP of Google (SSL certificate is invalid, See Chrome error message.
            """

            # (1)inner class checking

            # First, find out who calls it
            path_HOSTNAME_INNER_VERIFIER = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier", "(Ljavax/net/ssl/HostnameVerifier;)V")
            path_HOSTNAME_INNER_VERIFIER2 = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier",
                "(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V")
            path_HOSTNAME_INNER_VERIFIER.extend(path_HOSTNAME_INNER_VERIFIER2)

            path_HOSTNAME_INNER_VERIFIER = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_HOSTNAME_INNER_VERIFIER)

            dic_path_HOSTNAME_INNER_VERIFIER_new_instance = self.context.filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(
                self.context.d, analysis, path_HOSTNAME_INNER_VERIFIER, 1)  #parameter index 1

            # Second, find the called custom classes
            list_HOSTNAME_INNER_VERIFIER = []

            methods_hostnameverifier = get_method_ins_by_implement_interface_and_method(self.context.d, ["Ljavax/net/ssl/HostnameVerifier;"],
                                                                                        TYPE_COMPARE_ANY, "verify",
                                                                                        "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z")
            for method in methods_hostnameverifier:
                register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(method.get_instructions())
                if register_analyzer.get_ins_return_boolean_value():  #Has security problem
                    list_HOSTNAME_INNER_VERIFIER.append(method)

            list_HOSTNAME_INNER_VERIFIER = self.context.filteringEngine.filter_list_of_methods(list_HOSTNAME_INNER_VERIFIER)

            if list_HOSTNAME_INNER_VERIFIER:

                output_string = """This app allows Self-defined HOSTNAME VERIFIER to accept all Common Names(CN).
        This is a critical vulnerability and allows attackers to do MITM attacks with his valid certificate without your knowledge.
        Case example:
        (1)http://osvdb.org/96411
        (2)http://www.wooyun.org/bugs/wooyun-2010-042710
        (3)http://www.wooyun.org/bugs/wooyun-2010-052339
        Also check Google doc: http://developer.android.com/training/articles/security-ssl.html (Caution: Replacing HostnameVerifier can be very dangerous).
        OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
        Check this book to see how to solve this issue: http://goo.gl/BFb65r

        To see what's the importance of Common Name(CN) verification.
        Use Google Chrome to navigate:
         - https://www.google.com   => SSL certificate is valid
         - https://60.199.175.158/  => This is the IP address of google.com, but the CN is not match, making the certificate invalid. You still can go Google.com but now you cannot distinguish attackers from normal users

        Please check the code inside these methods:"""

                self.context.writer.startWriter("SSL_CN1", LEVEL_CRITICAL,
                                   "SSL Implementation Checking (Verifying Host Name in Custom Classes)", output_string,
                                   ["SSL_Security"])

                for method in list_HOSTNAME_INNER_VERIFIER:
                    self.context.writer.write(method.easy_print())

                    # because one class may initialize by many new instances of it
                    method_class_name = method.get_class_name()
                    if method_class_name in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
                        self.context.writer.show_Paths(self.context.d, dic_path_HOSTNAME_INNER_VERIFIER_new_instance[method_class_name])
            else:
                self.context.writer.startWriter("SSL_CN1", LEVEL_INFO, "SSL Implementation Checking (Verifying Host Name in Custom Classes)",
                                   "Self-defined HOSTNAME VERIFIER checking OK.", ["SSL_Security"])


            # (2)ALLOW_ALL_HOSTNAME_VERIFIER fields checking

            if "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;" in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
                path_HOSTNAME_INNER_VERIFIER_new_instance = dic_path_HOSTNAME_INNER_VERIFIER_new_instance[
                    "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"]
            else:
                path_HOSTNAME_INNER_VERIFIER_new_instance = None

            # "vmx.get_tainted_field" will return "None" if nothing found
            field_ALLOW_ALL_HOSTNAME_VERIFIER = self.context.vmx.get_tainted_field("Lorg/apache/http/conn/ssl/SSLSocketFactory;",
                                                                      "ALLOW_ALL_HOSTNAME_VERIFIER",
                                                                      "Lorg/apache/http/conn/ssl/X509HostnameVerifier;")

            if field_ALLOW_ALL_HOSTNAME_VERIFIER:
                filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = self.context.filteringEngine.filter_list_of_variables(self.context.d,
                                                                                                      field_ALLOW_ALL_HOSTNAME_VERIFIER.get_paths())
            else:
                filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = None

            if path_HOSTNAME_INNER_VERIFIER_new_instance or filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:

                output_string = """This app does not check the validation of the CN(Common Name) of the SSL certificate ("ALLOW_ALL_HOSTNAME_VERIFIER" field or "AllowAllHostnameVerifier" class).
        This is a critical vulnerability and allows attackers to do MITM attacks with his valid certificate without your knowledge.
        Case example:
        (1)http://osvdb.org/96411
        (2)http://www.wooyun.org/bugs/wooyun-2010-042710
        (3)http://www.wooyun.org/bugs/wooyun-2010-052339
        Also check Google doc: http://developer.android.com/training/articles/security-ssl.html (Caution: Replacing HostnameVerifier can be very dangerous).
        OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
        Check this book to see how to solve this issue: http://goo.gl/BFb65r

        To see what's the importance of Common Name(CN) verification.
        Use Google Chrome to navigate:
         - https://www.google.com   => SSL certificate is valid
         - https://60.199.175.158/  => This is the IP address of google.com, but the CN is not match, making the certificate invalid. You still can go Google.com but now you cannot distinguish attackers from normal users

        Please check the code inside these methods:"""

                self.context.writer.startWriter("SSL_CN2", LEVEL_CRITICAL, "SSL Implementation Checking (Verifying Host Name in Fields)",
                                   output_string, ["SSL_Security"])

                if filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
                    """
                        Example code:
                        SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
                        factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                    """

                    for path in filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
                        self.context.writer.show_single_PathVariable(self.context.d, path)

                if path_HOSTNAME_INNER_VERIFIER_new_instance:
                    """
                        Example code:
                        SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
                        factory.setHostnameVerifier(new AllowAllHostnameVerifier());
                    """
                    #For this one, the exclusion procedure is done on earlier
                    self.context.writer.show_Paths(self.context.d, path_HOSTNAME_INNER_VERIFIER_new_instance)
            else:
                self.context.writer.startWriter("SSL_CN2", LEVEL_INFO, "SSL Implementation Checking (Verifying Host Name in Fields)",
                                   "Critical vulnerability \"ALLOW_ALL_HOSTNAME_VERIFIER\" field setting or \"AllowAllHostnameVerifier\" class instance not found.",
                                   ["SSL_Security"])


        def ssl_getInsecure_check(self):


            list_getInsecure = []
            path_getInsecure = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/net/SSLCertificateSocketFactory;", "getInsecure",
                "(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;")
            path_getInsecure = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_getInsecure)

            if path_getInsecure:

                output_string = """Sockets created using this factory(insecure method "getInsecure") are vulnerable to man-in-the-middle attacks.
        Check the reference: http://developer.android.com/reference/android/net/SSLCertificateSocketFactory.html#getInsecure(int, android.net.SSLSessionCache).
        Please remove the insecure code:"""

                self.context.writer.startWriter("SSL_CN3", LEVEL_CRITICAL, "SSL Implementation Checking (Insecure component)", output_string,
                                   ["SSL_Security"])
                self.context.writer.show_Paths(self.context.d, path_getInsecure)
            else:
                self.context.writer.startWriter("SSL_CN3", LEVEL_INFO, "SSL Implementation Checking (Insecure component)",
                                   "Did not detect SSLSocketFactory by insecure method \"getInsecure\".", ["SSL_Security"])


        def ssl_httphost_check(self):


            #HttpHost default scheme "http"

            """
                Check this paper to see why I designed this vector: "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"


                Java Example code:
                    HttpHost target = new HttpHost(uri.getHost(), uri.getPort(), HttpHost.DEFAULT_SCHEME_NAME);

                Smali Example code:
                    const-string v4, "http"
                    invoke-direct {v0, v2, v3, v4}, Lorg/apache/http/HttpHost;-><init>(Ljava/lang/String; I Ljava/lang/String;)V
            """

            list_HttpHost_scheme_http = []
            path_HttpHost_scheme_http = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Lorg/apache/http/HttpHost;", "<init>", "(Ljava/lang/String; I Ljava/lang/String;)V")
            path_HttpHost_scheme_http = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_HttpHost_scheme_http)
            for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_HttpHost_scheme_http):
                if i.getResult()[3] is None:
                    continue
                if (i.is_string(i.getResult()[3])) and ((i.getResult()[3]).lower() == "http"):
                    list_HttpHost_scheme_http.append(i.getPath())

            if list_HttpHost_scheme_http:
                self.context.writer.startWriter("SSL_DEFAULT_SCHEME_NAME", LEVEL_CRITICAL, "SSL Implementation Checking (HttpHost)",
                                   "This app uses \"HttpHost\", but the default scheme is \"http\" or \"HttpHost.DEFAULT_SCHEME_NAME(http)\". Please change to \"https\":",
                                   ["SSL_Security"])

                for i in list_HttpHost_scheme_http:
                    self.context.writer.show_Path(self.context.d, i)
            else:
                self.context.writer.startWriter("SSL_DEFAULT_SCHEME_NAME", LEVEL_INFO, "SSL Implementation Checking (HttpHost)",
                                   "DEFAULT_SCHEME_NAME for HttpHost check: OK", ["SSL_Security"])


        def ssl_WebView_check(self):
            #WebViewClient onReceivedSslError errors

            # First, find out who calls setWebViewClient
            path_webviewClient_new_instance = self.context.vmx.get_tainted_packages().search_class_methods_exact_match(
                "Landroid/webkit/WebView;", "setWebViewClient", "(Landroid/webkit/WebViewClient;)V")
            dic_webviewClient_new_instance = self.context.filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(self.context.d,
                                                                                                                         analysis,
                                                                                                                         path_webviewClient_new_instance,
                                                                                                                         1)

            # Second, find which class and method extends it
            list_webviewClient = []
            methods_webviewClient = get_method_ins_by_superclass_and_method(self.context.d, ["Landroid/webkit/WebViewClient;"],
                                                                            "onReceivedSslError",
                                                                            "(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V")
            for method in methods_webviewClient:
                if is_kind_string_in_ins_method(method, "Landroid/webkit/SslErrorHandler;->proceed()V"):
                    list_webviewClient.append(method)

            list_webviewClient = self.context.filteringEngine.filter_list_of_methods(list_webviewClient)

            if list_webviewClient:
                self.context.writer.startWriter("SSL_WEBVIEW", LEVEL_CRITICAL, "SSL Implementation Checking (WebViewClient for WebView)",
                                   """DO NOT use "handler.proceed();" inside those methods in extended "WebViewClient", which allows the connection even if the SSL Certificate is invalid (MITM Vulnerability).
        References:
        (1)A View To A Kill: WebView Exploitation: https://www.iseclab.org/papers/webview_leet13.pdf
        (2)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
        (3)https://jira.appcelerator.org/browse/TIMOB-4488
        Vulnerable codes:
        """, ["SSL_Security"])

                for method in list_webviewClient:
                    self.context.writer.write(method.easy_print())

                    # because one class may initialize by many new instances of it
                    method_class_name = method.get_class_name()
                    if method_class_name in dic_webviewClient_new_instance:
                        self.context.writer.show_Paths(self.context.d, dic_webviewClient_new_instance[method_class_name])

            else:
                self.context.writer.startWriter("SSL_WEBVIEW", LEVEL_INFO, "SSL Implementation Checking (WebViewClient for WebView)",
                                   "Did not detect critical usage of \"WebViewClient\"(MITM Vulnerability).", ["SSL_Security"])


        def certificate_verify_check(self):


            #SSL Verification Fail (To check whether the code verifies the certificate)

            methods_X509TrustManager_list = get_method_ins_by_implement_interface_and_method_desc_dict(self.context.d, [
                "Ljavax/net/ssl/X509TrustManager;"], TYPE_COMPARE_ANY,
                                                                                                       [
                                                                                                           "getAcceptedIssuers()[Ljava/security/cert/X509Certificate;",
                                                                                                           "checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V",
                                                                                                           "checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"])

            list_X509Certificate_Critical_class = []
            list_X509Certificate_Warning_class = []

            for class_name, method_list in methods_X509TrustManager_list.items():
                ins_count = 0

                for method in method_list:
                    for ins in method.get_instructions():
                        ins_count = ins_count + 1

                if ins_count <= 4:
                    #Critical
                    list_X509Certificate_Critical_class.append(class_name)
                else:
                    #Warning
                    list_X509Certificate_Warning_class.append(class_name)

            if list_X509Certificate_Critical_class or list_X509Certificate_Warning_class:

                log_level = LEVEL_WARNING
                log_partial_prefix_msg = "Please make sure this app has the conditions to check the validation of SSL Certificate. If it's not properly checked, it MAY allows self-signed, expired or mismatch CN certificates for SSL connection."

                if list_X509Certificate_Critical_class:
                    log_level = LEVEL_CRITICAL
                    log_partial_prefix_msg = "This app DOES NOT check the validation of SSL Certificate. It allows self-signed, expired or mismatch CN certificates for SSL connection."

                list_X509Certificate_merge_list = []
                list_X509Certificate_merge_list.extend(list_X509Certificate_Critical_class)
                list_X509Certificate_merge_list.extend(list_X509Certificate_Warning_class)

                dict_X509Certificate_class_name_to_caller_mapping = {}

                for method in self.context.d.get_methods():
                    for i in method.get_instructions():  # method.get_instructions(): Instruction
                        if i.get_op_value() == 0x22:  # 0x22 = "new-instance"
                            if i.get_string() in list_X509Certificate_merge_list:
                                referenced_class_name = i.get_string()
                                if referenced_class_name not in dict_X509Certificate_class_name_to_caller_mapping:
                                    dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name] = []

                                dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name].append(method)

                self.context.writer.startWriter("SSL_X509", log_level, "SSL Certificate Verification Checking",
                                   log_partial_prefix_msg + """
        This is a critical vulnerability and allows attackers to do MITM attacks without your knowledge.
        If you are transmitting users' username or password, these sensitive information may be leaking.
        Reference:
        (1)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
        (2)Android Security book: http://goo.gl/BFb65r
        (3)https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=134807561
        This vulnerability is much more severe than Apple's "goto fail" vulnerability: http://goo.gl/eFlovw
        Please do not try to create a "X509Certificate" and override "checkClientTrusted", "checkServerTrusted", and "getAcceptedIssuers" functions with blank implementation.
        We strongly suggest you use the existing API instead of creating your own X509Certificate class.
        Please modify or remove these vulnerable code:
        """, ["SSL_Security"])
                if list_X509Certificate_Critical_class:
                    self.context.writer.write("[Confirm Vulnerable]")
                    for name in list_X509Certificate_Critical_class:
                        self.context.writer.write("=> " + name)
                        if name in dict_X509Certificate_class_name_to_caller_mapping:
                            for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
                                self.context.writer.write(
                                    "      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

                if list_X509Certificate_Warning_class:
                    self.context.writer.write("--------------------------------------------------")
                    self.context.writer.write("[Maybe Vulnerable (Please manually confirm)]")
                    for name in list_X509Certificate_Warning_class:
                        self.context.writer.write("=> " + name)
                        if name in dict_X509Certificate_class_name_to_caller_mapping:
                            for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
                                self.context.writer.write(
                                    "      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

            else:
                self.context.writer.startWriter("SSL_X509", LEVEL_INFO, "SSL Certificate Verification Checking",
                                   "Did not find vulnerable X509Certificate code.", ["SSL_Security"])










