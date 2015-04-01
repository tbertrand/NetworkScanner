import sys
import os
import nmap
#import sipconfig
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):

        #menu actions
        clearAction = QAction(QIcon('icons/clear.png'), 'Clear', self)
        clearAction.setShortcut('Ctrl+E')
        clearAction.triggered.connect(self.clearText)

        #toolbar actions
        clearAction = QAction(QIcon('icons/clear.png'), 'Clear', self)
        clearAction.setShortcut('Ctrl+E')
        clearAction.triggered.connect(self.clearText)

        scanAction = QAction(QIcon('icons/scan.png'), 'Scan Network', self)
        scanAction.setShortcut('Ctrl+D')
        scanAction.triggered.connect(self.scan)

        saveAction = QAction(QIcon('icons/save.png'), 'Save Report', self)
        saveAction.setShortcut('Ctrl+S')
        saveAction.triggered.connect(self.saveResults)

        #menu
        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&Menu')
        fileMenu.addAction(saveAction)
        fileMenu.addAction(scanAction)
        fileMenu.addAction(clearAction)

        #toolbar
        toolbar = self.addToolBar('Exit')
        toolbar.addAction(saveAction)
        toolbar.addAction(scanAction)
        toolbar.addAction(clearAction)
        
        #flag checkboxes
        self.CBsn = QCheckBox('Find Hosts', self)
        self.CBsn.move(130,25)
        
        self.CBos = QCheckBox('OS Detection', self)
        self.CBos.move(225, 25)
        
        self.CBv = QCheckBox('Verbosity', self)
        self.CBv.move(335, 25)
        
        self.outFileName = QLineEdit(self)
        self.outFileName.setGeometry(520, 25, 150, 25)
        self.outFileName.setPlaceholderText("Save file name...")
        self.outFileName.move(475, 25)
        
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
        
        hostnameLabel = QLabel('OR, Hostname:', self)
        hostnameLabel.move(70, 100)  
        
        self.hostnameText = QLineEdit(self)
        self.hostnameText.setGeometry(220, 100, 150, 25)    
        self.hostnameText.setPlaceholderText("Hostname...")

        #report textarea
        self.report = QTextEdit(self)
        self.report.setGeometry(15, 130, 610, 300)
        self.report.setReadOnly(True)
        self.report.setPlaceholderText("If using a single IP instead of an IP range, put the single IP in the \"From IP Address...\" box.\n\nIP addresses and a hostname cannot be entered at the same time.\n\nIP addresses must be in a correct format.\n\nThe OS Detection flag supercedes the Find Hosts flag, therefore selecting both will result in only the OS Detection flag being used.\n\nEnter a file name in the \"Save file name...\" box before saving. Your log file will be located in the \'logs\' directory.")

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
    
    def saveResults(self, event):
        saveName = self.outFileName.text()
        saveName = saveName.replace('.txt','')
        saveName = saveName.replace('.','')
        saveName += '.txt'
        fileName = 'logs/' + saveName
        
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        file = open(fileName, 'a')
        file.write(self.report.toPlainText())
        file.close()
        
        self.report.setText("File saved to logs directory under file name \'" + saveName + "\'.")
    
    def clearText(self):
        self.report.clear()
            
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
            self.setWindowTitle('Network Scanning Utility')
            self.report.setText("IP or Hostname must be entered.")
            return False
            
        elif (fromIP or toIP) and hostname:
            self.setWindowTitle('Network Scanning Utility')
            self.report.setText("You cannot enter both an IP address and a hostname.")
            return False
            
        elif fromIP and not self.validateIP(fromIP):
            self.setWindowTitle('Network Scanning Utility')
            self.report.setText("Entered IP address is not a valid IP address.")
            return False
        
        elif toIP and not self.validateIP(toIP):
            self.setWindowTitle('Network Scanning Utility')
            self.report.setText("Entered IP address is not a valid IP address.")
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
                   
            return argIP
        
        elif fromIP and not toIP and not hostname:
            return fromIP
        
        elif hostname:
            return hostname
        
        
    def getArguments(self):
        #create arguments string
        args = ""
        
        #v flag check
        if self.CBv.isChecked(): args += '-v '
        
        #sC and sn flag check
        if self.CBos.isChecked(): args += '-sC '
        elif self.CBsn.isChecked(): args += '-sn '        
        
        return args

    def scan(self):
        self.report.clear()
        self.setWindowTitle('Network Scanning Utility (Scanning...)')
        hostlist = self.getHosts()
        arglist = self.getArguments()
        nm = nmap.PortScanner()
        nm.scan(hosts = hostlist, arguments = arglist)

    
        scanString = "Scan on:  " + nm.scanstats()['timestr'] + "\n  Time Elapsed:  " + nm.scanstats()['elapsed']
        scanString += "\n  Total Hosts:  " + nm.scanstats()['totalhosts'] + " -- " + nm.scanstats()['uphosts'] + " hosts up, " + nm.scanstats()['downhosts'] + " hosts down\n\n"
    
        for host in nm.all_hosts():
            hostString = ""
            hostString += "Host:  " + host + "\n"
    
            if('hostscript' in nm[host]):
                hostString += "Script Results:\n"
                for script in nm[host]['hostscript']:
                    scriptText = script['output'].strip()
                    if(scriptText[0] == "N"): scriptArray = scriptText.split(", ")
                    else: scriptArray = scriptText.split("\n")
    
                    for item in scriptArray:
                        hostString += "    " + item + "\n"
                    hostString += "\n"
            hostString += "---------------\n\n"
    
            scanString += hostString
        
        self.report.setText(scanString)
        self.setWindowTitle('Network Scanning Utility')
        return scanString
    
        
if __name__ == '__main__':

    app = QApplication(sys.argv)
    window = GUI()
    sys.exit(app.exec_())
