
#coding:utf8
##added by heen
from .. import *
from VulnerabilityVector import VulnerabilityVector

class  OpenPortCheck(VulnerabilityVector):

       def __init__(self,context):

           self.context = context

       def analyze(self):
       
            #Openport checking:

            """
            find open port code and add information to the context writer

                Example Java code:
                    new ServerSocket(port)

                Example Bytecode code:
                tcp:
                    new-instance v0, Ljava/net/ServerSocket;
                    const/16 v1, 0x1388
                    invoke-direct {v0, v1}, Ljava/net/ServerSocket;-><init>(I)V
                udp:
                    new-instance v1, Ljava/net/DatagramSocket;
                    const v0, 0xffde
                    invoke-direct {v1, v0}, Ljava/net/DatagramSocket;-><init>(I)V

            """
            path_tcpport = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/net/ServerSocket;","<init>", "(I)V")
            path_tcpport = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_tcpport)

            path_udpport = self.context.vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/net/DatagramSocket;","<init>", "(I)V")
            path_udpport = self.context.filteringEngine.filter_list_of_paths(self.context.d, path_udpport)

            """
            if you want to get the port number, refer to nativecheck.py
            """



            if (path_tcpport or path_udpport):
                self.context.writer.startWriter("OPEN PORT INFO", LEVEL_CRITICAL, "Open Port Checking", "Open Port Code Found: ",["OPEN_PORT"])

                if path_tcpport:
                    for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_tcpport):
                        # the class ServerSocket is getResult()[0] and tcp port number is getResult()[1]
                        tcp_port_num = i.getResult()[1]
                        if tcp_port_num is not None:
                            self.context.writer.write("TCP Port: "+str(tcp_port_num))
                        else:
                            self.context.writer.write("TCP Port: args in runtime. ")

                    self.context.writer.write("Which are in the following sequence:  ")
                    for path in path_tcpport:
                        self.context.writer.show_Path(self.context.d, path)

                if path_udpport:
                    for i in analysis.trace_Register_value_by_Param_in_source_Paths(self.context.d, path_udpport):
                        # the class DatagramSocket is getResult()[0] and udp port number is getResult()[1]
                        udp_port_num = i.getResult()[1]
                        if udp_port_num is not None:
                            self.context.writer.write("UDP Port: "+str(udp_port_num))
                        else:
                            self.context.writer.write("UDP Port: args in runtime. ")

                    self.context.writer.write("Which are in the following sequence:  ")
                    for path in path_udpport:
                        self.context.writer.show_Path(self.context.d, path)
