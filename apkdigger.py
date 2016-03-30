#coding:utf8




from zipfile import BadZipfile
from tools import *
from tools.AnalyzerContext import AnalyzerContext
from tools.vectors.VulnerabilityVector import  VulnerabilityVector

from importlib import import_module




class module_args(object):

      def __init__(self):

          self.analyze_engine_build=1
          self.analyze_mode='single'
          self.analyze_tag=None
          self.apk_file='sieve.apk'
          self.extra=1
          self.line_max_output_characters=None
          self.report_output_dir='Reports/'
          self.show_vector_id=False
          self.store_analysis_result_in_db=False




class Analyzer():


    def __init__(self,filepath=None,single=False):

        self.stopwatch_start = ''
        self.analyze_start = ''

        self.vector_path = os.path.join(os.path.dirname(__file__),"tools","vectors")

        self.modules = []
        self.vectors = []
        self.single_mode = single
        self.analyze_time = ''

        self.load_vectors()
        self.writer = Writer()


        if single:
            self.args = parseArgument()
        else:
            self.args = module_args()

        if filepath is not None:
           self.args.apk_file = filepath


    def time_format(self, timedelta):

        ret = []

        total = str(timedelta)

        a = total.split(':')

        if len(a) != 3:
            return None

        if a[0] != '0':
            ret.append("%s小时"%a[0])


        if a[1] != '00':
            ret.append("%s分钟"%a[1])


        ret.append("%.5s秒"%a[2].strip('0'))


        return ''.join(ret)












    def finish_writer(self):

        #Must complete the last writer

        self.writer.completeWriter()

        self.writer.writeInf_ForceNoPrint("vector_total_count", self.writer.get_total_vector_count())

        #----------------------------------------------------------------
        #End of Checking

        #StopWatch
        now = datetime.now()
        stopwatch_total_elapsed_time = now - self.stopwatch_start
        stopwatch_analyze_time = now - self.analyze_start
        stopwatch_loading_vm = self.analyze_start - self.stopwatch_start


        self.analyze_time = self.time_format(stopwatch_total_elapsed_time)


        self.writer.writeInf_ForceNoPrint("time_total", stopwatch_total_elapsed_time.total_seconds())
        self.writer.writeInf_ForceNoPrint("time_analyze", stopwatch_analyze_time.total_seconds())
        self.writer.writeInf_ForceNoPrint("time_loading_vm", stopwatch_loading_vm.total_seconds())

        self.writer.update_analyze_status("success")
        self.writer.writeInf_ForceNoPrint("time_finish_analyze", datetime.utcnow())


    def locate_modules(self):



        for dirpath, dirnames, filenames in os.walk(self.vector_path):
            for filename in filenames:
                module_path = os.path.join(dirpath[len(self.vector_path) + len(os.path.sep):], filename)
                module_name, ext = os.path.splitext(module_path)

                if ext in [".py", ".pyc", ".pyo"]:
                    filepath = os.path.join(self.vector_path, module_path)

                    module = filepath[len(self.vector_path)+1:filepath.rindex(".")].replace(os.path.sep, ".")


                    if module != "__init__":
                       self.modules.append( "tools.vectors." + module)



    def load_vectors(self):

        self.locate_modules()



        for i in self.modules:

                try:

                    if self.single_mode:
                        import_module(i)

                    else:

                        import_module("." + i, package="APK_digger_Framework")



                except ImportError,e:
                    sys.stderr.write("Skipping source file at %s. Unable to load Python module.\n" % i)
                    print e

                    pass
                except IndentationError:
                    sys.stderr.write("Skipping source file at %s. Indentation Error.\n" % i)
                    pass


        self.vectors =  VulnerabilityVector.__subclasses__()





    def print_banner(self):


        print       "\n"

        print         "   *************************************************************************     "
        print         "   **   APKDigger Framework - Android App Security Vulnerability Scanner  **     "
        print         "   **                            version: 1.0.0                           **     "
        print         "   **                             author: thor                            **     "
        print         "   **                            contact: thor@ms509.com                  **     "
        print         "   *************************************************************************     "



        print        "                         ______     __      __       "
        print        "                        /\  ___\  /'__`\  /'_ `\     "
        print        "        ___ ___     ____\ \ \__/ /\ \/\ \/\ \L\ \    "
        print       r"      /' __` __`\  /',__\\ \___``\ \ \ \ \ \___, \   "
        print       r"      /\ \/\ \/\ \/\__, `\\/\ \L\ \ \ \_\ \/__,/\ \  "
        print       r"      \ \_\ \_\ \_\/\____/ \ \____/\ \____/    \ \_\ "
        print       r"       \/_/\/_/\/_/\/___/   \/___/  \/___/      \/_/ "
        print       "\n\n"


    def run(self):


        self.print_banner()


        try:

            #Analyze

            self.stopwatch_start = datetime.now()

            context = AnalyzerContext(self.writer,self.args)
            self.md5 = context.md5
            self.sig = context.sig


            self.analyze_start = datetime.now()

            print("------------------------------------------------------------")
            for vul_vector in self.vectors:

                vul_vector(context).analyze()



            self.finish_writer()

        

            analyze_signature = get_hash_scanning(self.writer)
            self.writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                         analyze_signature)  #For uniquely distinguish the analysis report
            self.writer.append_to_file_io_information_output_list("Analyze Signature: " + analyze_signature)
            self.writer.append_to_file_io_information_output_list(
                "------------------------------------------------------------------------------------------------")

        except ExpectedException as err_expected:

            self.writer.update_analyze_status("fail")

            self.writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
            self.writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
            self.writer.writeInf_ForceNoPrint("analyze_error_id", err_expected.get_err_id())
            self.writer.writeInf_ForceNoPrint("analyze_error_message", err_expected.get_err_message())

            self.writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                         get_hash_scanning(self.writer))  #For uniquely distinguish the analysis report
            self.writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(self.writer))

            if DEBUG:
                print(err_expected)

        except BadZipfile as zip_err:  #This may happen in the "a = apk.APK(apk_Path)"

            self.writer.update_analyze_status("fail")

            #Save the fail message to db
            self.writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

            self.writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
            self.writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
            self.writer.writeInf_ForceNoPrint("analyze_error_id", "fail_to_unzip_apk_file")
            self.writer.writeInf_ForceNoPrint("analyze_error_message", str(zip_err))

            self.writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                         get_hash_scanning(self.writer))  #For uniquely distinguish the analysis report
            self.writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(self.writer))

            if DEBUG:
                print("[Unzip Error]")
                traceback.print_exc()

        except Exception as err:

            self.writer.update_analyze_status("fail")

            #Save the fail message to db
            self.writer.writeInf_ForceNoPrint("analyze_error_detail_traceback", traceback.format_exc())

            self.writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
            self.writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
            self.writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
            self.writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

            self.writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                         get_hash_scanning(self.writer))  #For uniquely distinguish the analysis report
            self.writer.writeInf_ForceNoPrint("signature_unique_exception", get_hash_exception(self.writer))

            if DEBUG:
                traceback.print_exc()





        #Save to the DB
        if self.args.store_analysis_result_in_db:
            persist_db(self.writer, self.args)

        if self.writer.get_analyze_status() == "success":

            if REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_PRINT:
                self.writer.show(self.args)
            elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE:
                persist_file(self.writer, self.args)  #write report to "disk"
            elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_PRINT_AND_FILE:
                self.writer.show(self.args)
                persist_file(self.writer, self.args)  #write report to "disk"


    def get_package_name(self):

        return self.writer.getInf("package_name")

    def get_signature_unique_analyze(self):

        return self.writer.getInf("signature_unique_analyze")




if __name__ == "__main__":




    Analyzer(single=True).run()

