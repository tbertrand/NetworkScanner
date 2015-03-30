import sys
import nmap
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

class GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):

        #menu actions
        exitAction = QAction(QIcon('icons/exit.png'), 'Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.triggered.connect(qApp.exit)

        #toolbar actions
        cancelAction = QAction(QIcon('icons/cancel.png'), 'Cancel Scan', self)
        #scanAction.triggered.connect()

        scanAction = QAction(QIcon('icons/scan.png'), 'Scan Network', self)
        scanAction.setShortcut('Ctrl+D')
        scanAction.triggered.connect(self.scan)

        saveAction = QAction(QIcon('icons/save.png'), 'Save Report', self)
        saveAction.setShortcut('Ctrl+S')
        #saveAction.triggered.connect()

        #menu
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(exitAction)

        #toolbar
        toolbar = self.addToolBar('Exit')
        toolbar.addAction(saveAction)
        toolbar.addAction(scanAction)
        toolbar.addAction(cancelAction)
        
        #flag checkboxes
        self.CBsn = QCheckBox('Find Hosts', self)
        self.CBsn.move(130,35)
        
        self.CBos = QCheckBox('OS Detection', self)
        self.CBos.move(225, 35)
        
        self.CBv = QCheckBox('Verbosity', self)
        self.CBv.move(335, 35)
        
        self.CBout = QCheckBox('Save to File', self)
        self.CBout.move(420, 35)
        self.outFileName = QLineEdit(self)
        self.outFileName.setGeometry(520, 35, 105, 25)
        self.outFileName.setPlaceholderText("File name...")
        #outFileName.move(520, 35)
        
        
        #TextBoxes For IP Addresses
        self.fromIPText = QLineEdit(self)
        self.fromIPText.setGeometry(220, 70, 150, 26)
        self.fromIPText.setPlaceholderText("From IP Address...")

        self.toIPText = QLineEdit(self)
        self.toIPText.setGeometry(400, 70, 150, 25)
        self.toIPText.setPlaceholderText("To IP Address...")

        #IP Address Labels
        ipAddressLabel = QLabel('IP Range:', self)
        ipAddressLabel.move(100, 70)

        #FromLabel = QLabel('-', self)
        #FromLabel.move(380, 70)

        #toLabel = QLabel('To: ', self)
        #toLabel.move(380, 70)
        
        hostnameLabel = QLabel('OR, Hostname:', self)
        hostnameLabel.move(70, 100)  
        
        self.hostnameText = QLineEdit(self)
        self.hostnameText.setGeometry(220, 100, 150, 25)    
        self.hostnameText.setPlaceholderText("Hostname...")

        #report label
        #reportLabel = QLabel('Scan Report:', self)
        #reportLabel.move(15, 70)

        #report textarea
        self.report = QTextEdit(self)
        self.report.setGeometry(15, 130, 610, 300)
        self.report.setReadOnly(True)

        #application window
        self.setGeometry(300, 300, 640, 445)
        self.setWindowTitle('Network Scanning Utility')
        self.setWindowIcon(QIcon('icons/window.png'))
        self.show()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message', "Are you sure you want to exit?", QMessageBox.Yes, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()
            
    def validateIP(self, IP):
        array = IP.split('.')
        if len(array) != 4: return False
        for each in array:
            if not (0 <= int(each) <= 255):
                return False
        return True
                
        
    
    def getHosts(self):
        fromIP = self.fromIPText.text().replace(' ', '')
        toIP = self.toIPText.text().replace(' ', '')
        hostname = self.hostnameText.text().replace(' ', '')
        argIP = ''
        
        if not fromIP and not hostname:
            #no ip or host entered
            print("cancel 0")
            return False
            
        elif (fromIP or toIP) and hostname:
            #both entered
            print('cancel 1')
            return False
            
        elif fromIP and not self.validateIP(fromIP):
            print('cancel 2')
            return False
        
        elif toIP and not self.validateIP(toIP):
            print('cancel 3')
            return False
        
        elif fromIP and toIP and not hostname:
            #ip ranges
            fromIP = fromIP.split('.')
            toIP = toIP.split('.')
            
            for i in range(0, 4):
                if fromIP[i] == toIP[i]:
                    argIP += fromIP[i]
                else:
                    if fromIP[i] <= toIP[i]:
                        argIP += fromIP[i] + '-' + toIP[i]
                    else:
                        argIP += toIP[i] + '-' + fromIP[i]
                if i != 3:
                    argIP += '.'
            print(argIP)        
            return argIP
        
        elif fromIP and not toIP and not hostname:
            print(fromIP)
            return fromIP
        
        elif hostname:
            print(hostname)
            return hostname
        
        
    def createArguments(self):
        #create arguments string
        args = ""
        
        #v flag check
        if self.CBv.isChecked(): args += '-v '
        
        #sC and sn flag check
        if self.CBos.isChecked(): args += '-sC '
        elif self.CBsn.isChecked(): args += '-sn '        

        #out flag check
        if self.CBout.isChecked():
            filename = self.outFileName.text()
            filename = filename.replace('.txt','')
            filename = filename.replace('.','')
            filename += '.txt'
            outfile = '-oN ' + filename
            args += outfile
        
        return args

    def scan(self):
        nm = nmap.PortScanner()
        targets = self.getHosts()
        args = self.createArguments()
        nm.scan(hosts = targets, arguments = args)
        self.report.setText(str(nm.scan_result()))
    
        
if __name__ == '__main__':

    app = QApplication(sys.argv)
    window = GUI()
    sys.exit(app.exec_())
