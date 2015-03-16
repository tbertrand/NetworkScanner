import sys
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
        #scanAction.triggered.connect()

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

        #report label
        reportLabel = QLabel('Scan Report:', self)
        reportLabel.move(15, 60)

        #report textarea
        report = QTextEdit(self)
        report.setGeometry(15, 85, 610, 300)
        report.setReadOnly(True)

        #application window
        self.setGeometry(300, 300, 640, 400)
        self.setWindowTitle('Network Scanning Utility')
        self.setWindowIcon(QIcon('icons/window.png'))
        self.show()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message', "Are you sure you want to exit?", QMessageBox.Yes, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()


if __name__ == '__main__':

    app = QApplication(sys.argv)
    window = GUI()
    sys.exit(app.exec_())
