from PyQt6.QtCore import QObject, pyqtSignal
from functions import *

class Worker(QObject):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, sophos_id, sophos_secret, exclusions_out, allowed_out):
        super().__init__()
        self.sophos_id = sophos_id
        self.sophos_secret = sophos_secret
        self.exclusions_out = exclusions_out
        self.allowed_out = allowed_out
        self.exclude_count = 0
        self.allowed_count = 0

    def run(self):
        try:
            self.status.emit("Authenticating...")
            # pass the status signal into process_export so it can emit updates
            self.exclude_count, self.allowed_count = process_export(
                                                                    self.sophos_id,
                                                                    self.sophos_secret,
                                                                    self.exclusions_out,
                                                                    self.allowed_out,
                                                                    status_callback=self.status.emit
                                                                )
            if self.exclude_count:
                self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))