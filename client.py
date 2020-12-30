from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMessageBox
from datetime import datetime
from aescipher import AESCipher
from Crypto.Util import number
import socket, sys, threading

class Ui_MainWindow(object):
    def setup(self, server_socket):
        self.server_ip, self.server_port = server_socket.split(':')
        self.username = input('Enter your username: ')
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = socket.gethostname()
        print(f'Trying to connect to server {self.server_ip}:{self.server_port} from {self.host}...')
        self.socket.connect((self.server_ip, self.server_port))
        self.socket.send(self.username.encode())
        print('Connected')
        print('Encrypting traffic...')
        self.encrypt_traffic()
        print('Secure connection established')

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(512, 625)
        
        #Central Widget
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        
        #Layouts
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setSpacing(4)
        self.verticalLayout.setObjectName("verticalLayout")
        
        #List Widget
        self.list_widget = QtWidgets.QListWidget(self.centralwidget)
        self.list_widget.setWordWrap(True)
        self.list_widget.setSpacing(10)
        self.verticalLayout.addWidget(self.list_widget)
        
        
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        
        #Text Box
        self.plainTextEdit = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit.setObjectName("plainTextEdit")
        self.plainTextEdit.setFont(QtGui.QFont('Arial', 12))
        self.horizontalLayout.addWidget(self.plainTextEdit)
        
        #Send Button
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setMinimumSize(QtCore.QSize(0, 111))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setFont(QtGui.QFont('Arial', 15))
        self.horizontalLayout.addWidget(self.pushButton)
        self.horizontalLayout.setStretch(0, 5)
        self.horizontalLayout.setStretch(1, 1)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.verticalLayout.setStretch(0, 4)
        self.verticalLayout.setStretch(1, 1)
        self.gridLayout.addLayout(self.verticalLayout, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        MainWindow.show()
        
        self.pushButton.clicked.connect(self.send_msg)
        p1 = threading.Thread(target=self.recv_msg)
        p1.daemon = True
        p1.start()

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Chat App"))
        self.pushButton.setText(_translate("MainWindow", "Send"))

    def mod_exp(self, x, e, m):
        X = x
        E = e
        Y = 1
        while E > 0:
            if E % 2 == 0:
                X = (X * X) % m
                E = E/2
            else:
                Y = (X * Y) % m
                E = E - 1
        return Y

    def encrypt_traffic(self):
        # diffie hellman implementation
        mykey = number.getPrime(128)
        msg = self.socket.recv(1024).decode().split('|')
        base, mod = int(msg[0]), int(msg[1])
        self.socket.send(str(self.mod_exp(base, mykey, mod)).encode())
        msg = int(self.socket.recv(1024).decode())
        self.sk = str(self.mod_exp(msg, mykey, mod))
        print('AES secret key for this session: ', self.sk)
        self.cipher = AESCipher(self.sk)
    
    def send_msg(self):
        msg = self.plainTextEdit.toPlainText()
        self.socket.send(self.cipher.encrypt(msg))
        self.create_msg_box(msg, 'Me')
        self.plainTextEdit.clear()

    def recv_msg(self):
        while True:
            try:
                msg = self.cipher.decrypt(self.socket.recv(1024)).split('|')
                if len(msg) == 0:
                    break
                elif msg[1] == '~':
                    self.err_msg_box(msg[0])
                else:
                    self.create_msg_box(msg[1], msg[0])
            except:
                break
    
    def create_msg_box(self, msg, user):
        font = QtGui.QFont('Arial', 10)
        self.list_widget.setWordWrap(True)
        out = user + ' at ' + f'{datetime.now().strftime("%Y-%m-%d %H:%M")}' + "\n" + msg
        inf = QtWidgets.QListWidgetItem(out)
        inf.setFont(font)
        if user == 'Me':
            inf.setTextAlignment(QtCore.Qt.AlignRight)
        else:
            inf.setTextAlignment(QtCore.Qt.AlignLeft)
        self.list_widget.addItem(inf)

    def err_msg_box(self, user):
        font = QtGui.QFont('Arial', 10)
        font.setBold(True)
        self.list_widget.setWordWrap(True)
        out = 'Client '+ user + ' has left the conversation'
        inf = QtWidgets.QListWidgetItem(out)
        inf.setFont(font)
        self.list_widget.addItem(inf)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    server_socket = input('(SERVER IP):(SERVER PORT)> ')
    ui.setup(server_socket)
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
