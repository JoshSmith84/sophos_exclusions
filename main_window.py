import os
import sys
from pathlib import Path
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QThread
from qt_thread_worker import Worker


class Ui_MainWindow(object):

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(494, 328)
        MainWindow.setWindowOpacity(4.0)

        self.main_widget = QtWidgets.QWidget(parent=MainWindow)
        self.main_widget.setObjectName("main_widget")

        self.input_frame = QtWidgets.QFrame(parent=self.main_widget)
        self.input_frame.setGeometry(QtCore.QRect(0, 0, 461, 170)) # x, y, width , height
        self.input_frame.setAutoFillBackground(True)
        self.input_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.input_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.input_frame.setObjectName("input_frame")

        font = QtGui.QFont()
        font.setPointSize(12)

        self.co_label = QtWidgets.QLabel(parent=self.input_frame)
        self.co_label.setGeometry(QtCore.QRect(20, 5, 231, 16))
        self.co_label.setFont(font)
        self.co_label.setObjectName("co_label")

        self.id_label = QtWidgets.QLabel(parent=self.input_frame)
        self.id_label.setGeometry(QtCore.QRect(20, 55, 71, 16))
        self.id_label.setFont(font)
        self.id_label.setObjectName("id_label")

        self.secret_label = QtWidgets.QLabel(parent=self.input_frame)
        self.secret_label.setGeometry(QtCore.QRect(20, 105, 101, 16))
        self.secret_label.setFont(font)
        self.secret_label.setObjectName("id_label_2")

        self.co_input = QtWidgets.QLineEdit(parent=self.input_frame)
        self.co_input.setGeometry(QtCore.QRect(20, 25, 231, 21))
        self.co_input.setObjectName("co_input")

        self.id_input = QtWidgets.QLineEdit(parent=self.input_frame)
        self.id_input.setGeometry(QtCore.QRect(20, 75, 231, 21))
        self.id_input.setObjectName("id_input")

        self.secret_input = QtWidgets.QLineEdit(parent=self.input_frame)
        self.secret_input.setGeometry(QtCore.QRect(20, 125, 421, 21))
        self.secret_input.setObjectName("secret_input")

        self.button_frame = QtWidgets.QFrame(parent=self.main_widget)
        self.button_frame.setGeometry(QtCore.QRect(0, 175, 141, 121))
        self.button_frame.setAutoFillBackground(True)
        self.button_frame.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.button_frame.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        self.button_frame.setObjectName("button_frame")

        self.pushButton_dir = QtWidgets.QPushButton(parent=self.button_frame)
        self.pushButton_dir.setGeometry(QtCore.QRect(20, 10, 101, 24))
        self.pushButton_dir.setObjectName("pushButton")

        self.pushButton_run = QtWidgets.QPushButton(parent=self.button_frame)
        self.pushButton_run.setGeometry(QtCore.QRect(20, 40, 101, 24))
        self.pushButton_run.setObjectName("pushButton_2")

        self.pushButton_quit = QtWidgets.QPushButton(parent=self.button_frame)
        self.pushButton_quit.setGeometry(QtCore.QRect(20, 70, 101, 24))
        self.pushButton_quit.setObjectName("pushButton_3")

        MainWindow.setCentralWidget(self.main_widget)

        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 494, 22))
        self.menubar.setObjectName("menubar")

        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        self.statusbar.setStatusTip("")

        self.selected_folder = Path.home()
        self.sophos_id = ""
        self.sophos_secret = ""

        self.statusbar.showMessage(
            f"Output Folder: {self.selected_folder}. Click choose folder to change."
        )
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Sophos Exclusion Export"))
        self.co_label.setText(_translate("MainWindow", "Customer (Optional)"))
        self.id_label.setText(_translate("MainWindow", "Client ID"))
        self.secret_label.setText(_translate("MainWindow", "Client Secret"))
        self.pushButton_dir.setText(_translate("MainWindow", "Choose Folder"))
        self.pushButton_run.setText(_translate("MainWindow", "Run"))
        self.pushButton_quit.setText(_translate("MainWindow", "Quit"))

        self.pushButton_dir.clicked.connect(self._on_change_dir)
        self.pushButton_run.clicked.connect(self._on_run)
        self.pushButton_quit.clicked.connect(self._on_quit)

    def update_status_message(self, message):
        self.statusbar.showMessage(message)

    def _on_change_dir(self):
        self.selected_folder = QtWidgets.QFileDialog.getExistingDirectory(self.main_widget,
                                                                 'Select Folder',
                                                                 os.path.expanduser('~'),
                                                                 )
        if self.selected_folder == "":
            self.selected_folder = Path.home()
        self.update_status_message(f"Output folder now set to: {self.selected_folder}... Click run when ready.")


    def _on_run(self):

        self.co_id = self.co_input.text().replace(' ', '').replace('.', '').strip()
        if self.co_id == "":
            self.ex_out_file = f"{self.selected_folder}/sophos_exclusions.csv"
            self.al_out_file = f"{self.selected_folder}/sophos_allowed.csv"
        else:
            self.ex_out_file = f"{self.selected_folder}/{self.co_id}_sophos_exclusions.csv"
            self.al_out_file = f"{self.selected_folder}/{self.co_id}_sophos_allowed.csv"

        self.sophos_id = self.id_input.text().strip()
        self.sophos_secret = self.secret_input.text().strip()

        if self.sophos_id == "" or self.sophos_secret == "":
            self.on_error("Sophos ID or Secret Key is empty. Please paste these values and try again.")
            return

        # Disable run button to prevent double-clicks
        self.pushButton_run.setEnabled(False)
        self.update_status_message("Processing...")

        # Set up thread and worker
        self.thread = QThread()
        self.worker = Worker(
            self.sophos_id,
            self.sophos_secret,
            self.ex_out_file,
            self.al_out_file,
        )
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.run)
        self.worker.status.connect(self.update_status_message)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)

        # Cleanup connections
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def on_finished(self):
        self.update_status_message(f"Export Complete! {self.worker.exclude_count} exclusion(s) found."
                                   f" {self.worker.allowed_count} allowed app(s) found.")
        self.pushButton_run.setEnabled(True)

    def on_error(self, error_msg):
        self.update_status_message(f"Error: {error_msg}")
        self.pushButton_run.setEnabled(True)

    def _on_quit(self):
        sys.exit()