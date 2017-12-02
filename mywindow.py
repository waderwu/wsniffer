from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.Qt import QWidget,QApplication,QTableWidgetItem
from PyQt5.QtCore import pyqtSignal,QTimer,QThread
# import time
import socket
# import traceback
# import netifaces
# import threading
from util import str2hex
from protocol import Packet

from UIforsniffer import Ui_MainWindow
import sys

class mywindow(QtWidgets.QMainWindow,Ui_MainWindow):
    def __init__(self):
        super(mywindow,self).__init__()
        self.setupUi(self)

        thread = SniffThread('enx000ec6ca1bde')  # 创建一个线程
        thread.sniff_signal.connect(self.load)  # 线程发过来的信号挂接到槽：update
        self.pushButton_2.clicked.connect(lambda: thread.start())
        self.pushButton_3.clicked.connect(lambda: thread.terminate())
    def load(self,packets):
        row = len(packets)
        self.tableWidget.setRowCount(row)
        self.tableWidget.setColumnCount(5)
        for i in range(row):
            for j in range(1):
                data = QTableWidgetItem(packets[i].proto)
                self.tableWidget.setItem(i,j,data)

class SniffThread(QThread):

    # sniff_signal = pyqtSignal(int,int)  # 信号类型：int
    #
    # def __init__(self, sec=1000, parent=None):
    #         super().__init__(parent)
    #         self.sec = sec  # 默认1000秒
    #
    # def run(self):
    #     for i in range(self.sec):
    #             self.sec_changed_signal.emit(i,5)  # 发射信号
    #             time.sleep(1)
    packets = []
    numbers = 0
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniff_signal = pyqtSignal(type([]))
    def __init__(self,interface='wlp3s0',parent=None):
        super().__init__(parent)
        self.interface = interface

    def run(self):
        self.sniffer.bind((self.interface, 0))
        while True:
            packet = self.sniffer.recvfrom(65565)
            header = packet[0]
            try:
                p = Packet(str2hex(header))
                self.packets.append(p)
                print(self.numbers)
            except:
                self.numbers += 1
            if len(self.packets) > self.numbers:
                self.sniff_signal.emit(self.packets)
            self.numbers = len(self.packets)

# class ProcessThread(QThread):




if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    myshow = mywindow()
    myshow.show()
    app.exec_()