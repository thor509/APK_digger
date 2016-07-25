#coding:utf8



from .. import *
from VulnerabilityVector import VulnerabilityVector



class MasterkeyCheck(VulnerabilityVector):

       def __init__(self,context):

            self.context = context




       def  analyze(self):

           # master key check is only for apk analysis #added by heen

           if self.context.a is None:
               return

           dexes_count = 0
           all_files = self.context.a.get_files()
           for f in all_files:
               if f == 'classes.dex':
                   dexes_count += 1

           if dexes_count > 1:
               self.context.isMasterKeyVulnerability = True

           if self.context.isMasterKeyVulnerability:
               self.context.writer.startWriter("MASTER_KEY", LEVEL_CRITICAL, "Master Key Type I Vulnerability",
                                               "This APK is suffered from Master Key Type I Vulnerability.", None, "CVE-2013-4787")
           else:
               self.context.writer.startWriter("MASTER_KEY", LEVEL_INFO, "Master Key Type I Vulnerability",
                                               "No Master Key Type I Vulnerability in this APK.", None, "CVE-2013-4787")

               #------------------------------------------------------------------------------------------------------
               # Certificate checking (Prerequisite: 1.directory name "tmp" available  2.keytool command is available)

               # Comment out this code because chilkat may not be supported easily by every Linux
               # You can uncomment it if you have successfully installed the chilkat

           """
           import chilkat

           rsa_signature_filename = a.get_signature_name()    #a.get_signature_name() return a signature file name

           if rsa_signature_filename is None:
               writer.startWriter("CERT_SIGNED", LEVEL_CRITICAL, "Android App Signature", "This app is not signed. It can not be installed or upgraded on Android system.", ["Signature"])
           else:
               try:
                   success, cert = a.get_certificate(rsa_signature_filename)
                   if success:
                       if (cert.subjectCN() == 'Android Debug') or (cert.issuerCN() == 'Android Debug') :
                           writer.startWriter("CERT_SIGNED", LEVEL_CRITICAL, "Android App Signature", "This app is signed by 'Android Debug' certificate which is only for testing. DO NOT release this app in production!", ["Signature"])
                       else:
                           writer.startWriter("CERT_SIGNED", LEVEL_INFO, "Android App Signature", "This app is signed by your own certificate (SubjectCN: %s, IssuerCN: %s)." % (cert.subjectCN(), cert.issuerCN()), ["Signature"])
                   else:
                       writer.startWriter("CERT_SIGNED", LEVEL_INFO, "Android App Signature", "We cannot tell whether the app is signed or not because we are unable to load the certificate of app.", ["Signature"])

               except IOError:
                   pass
           """

