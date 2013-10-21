from collections import deque
import hashlib
import math
import os
import pickle
import sys
import threading
import time
import traceback

from PyQt4 import QtGui as gui
from PyQt4 import QtCore as core

from addnewkey import AddNewKeyDialog
from bitcoin import Bitcoin
from common import *
from msgwatch import Callbacks as BitmsgMsgWatchCallbacks
from network import BitcoinNetwork

class BitmsgMainWindow(gui.QMainWindow, BitmsgMsgWatchCallbacks):
    TRANSACTIONS_PER_SECOND_WINDOW = 10

    def __init__(self):
        gui.QWidget.__init__(self)
        BitmsgMsgWatchCallbacks.__init__(self)

        self.saved_keys = []
        try:
            self.saved_keys = pickle.Unpickler(open('keys.dat', 'rb')).load()
        except FileNotFoundError:
            pass
        except:
            traceback.print_exc()

        self.transactions_per_second_deque = deque()
        self.transactions_per_second_deque_lock = threading.Lock()

        self.init()

        self.watch_public()

        for name, algorithm, key in self.saved_keys:
            if algorithm == ENCRYPT_RSA:
                key = load_private_key_from_der(key)
            self.watch_and_add_key(name, algorithm, key)

        self.start()

    def quit(self):
        self.bitcoin_network.stop()
        self.bitcoin_network.join()
        gui.qApp.quit()

    def closeEvent(self, event):
        self.quit()
        event.accept()

    def init(self):
        self.setWindowTitle('Bitmsg')

        tabbed = gui.QTabWidget()
        tabbed.setTabShape(gui.QTabWidget.Triangular)

        tabbed.addTab(self.make_messages_page(), "Messages")
        tabbed.addTab(self.make_keys_page(), "Keys / Identities")
        tabbed.addTab(self.make_addressbook_page(), "Addressbook")

        self.setCentralWidget(tabbed)

        exitAction = gui.QAction(gui.QIcon('exit.png'), '&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(self.quit)

        menubar = self.menuBar()
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(exitAction)

        self.connection_status = gui.QLabel("Initializing network...")
        self.transactions_per_second = gui.QLabel("")

        self.statusbar = self.statusBar()
        self.statusbar.addWidget( self.connection_status )
        self.statusbar.addWidget( self.transactions_per_second )

        self.resize(600, 400)
        self.center()

    def center(self):
        qr = self.frameGeometry()
        cp = gui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def make_messages_page(self):
        return gui.QWidget()

    def make_keys_page(self):
        self.keys_table = gui.QTableWidget(self)
        self.keys_table.setAlternatingRowColors(True)
        self.keys_table.setSelectionMode(gui.QAbstractItemView.SingleSelection)
        self.keys_table.setSelectionBehavior(gui.QAbstractItemView.SelectRows)
        self.keys_table.setWordWrap(False)
        self.keys_table.setObjectName("keys_table")
        self.keys_table.setColumnCount(3)
        self.keys_table.setRowCount(0)
        self.keys_table.setSortingEnabled(True)

        self.keys_table.horizontalHeader().setCascadingSectionResizes(True)
        self.keys_table.horizontalHeader().setDefaultSectionSize(200)
        self.keys_table.horizontalHeader().setHighlightSections(False)
        self.keys_table.horizontalHeader().setMinimumSectionSize(27)
        self.keys_table.horizontalHeader().setSortIndicatorShown(False)
        self.keys_table.horizontalHeader().setStretchLastSection(True)
        self.keys_table.verticalHeader().setVisible(False)
        self.keys_table.verticalHeader().setDefaultSectionSize(26)

        self.keys_table.setHorizontalHeaderItem(0, gui.QTableWidgetItem())
        self.keys_table.setHorizontalHeaderItem(1, gui.QTableWidgetItem())
        self.keys_table.setHorizontalHeaderItem(2, gui.QTableWidgetItem())

        self.keys_table.horizontalHeaderItem(0).setText("Name")
        self.keys_table.horizontalHeaderItem(1).setText("Type")
        self.keys_table.horizontalHeaderItem(2).setText("Key")

        add_key_button = gui.QPushButton("Add new...")
        add_key_button.clicked.connect(self.add_new_key_clicked)

        buttons_box = gui.QHBoxLayout()
        buttons_box.addWidget(add_key_button)
        buttons_box.addStretch(1)

        vbox = gui.QVBoxLayout()
        vbox.addWidget(self.keys_table)
        vbox.addLayout(buttons_box)

        page = gui.QWidget()
        page.setLayout(vbox)

        return page

    def make_addressbook_page(self):
        return gui.QWidget()

    def start(self):
        # start network thread
        self.bitcoin_network = BitcoinNetwork(self)
        self.bitcoin_network.start()

        def update_status_bar():
            nonlocal self
            self.connection_status.setText('Connected to {}/{} nodes'.format(self.bitcoin_network.count_fully_connected_peers(), self.bitcoin_network.num_peer_goal))

            with self.transactions_per_second_deque_lock:
                now = time.time()
                while len(self.transactions_per_second_deque):
                    if (now - self.transactions_per_second_deque[0]) >= BitmsgMainWindow.TRANSACTIONS_PER_SECOND_WINDOW:
                        self.transactions_per_second_deque.popleft()
                        continue
                    break

                if len(self.transactions_per_second_deque) == 0:
                    self.transactions_per_second.setText("Network is idle")
                else:
                    self.transactions_per_second.setText("{:.2f} tx/sec".format(round(len(self.transactions_per_second_deque)/BitmsgMainWindow.TRANSACTIONS_PER_SECOND_WINDOW, 2)))

        self.connection_status_timer = core.QTimer()
        self.connection_status_timer.timeout.connect(update_status_bar)
        self.connection_status_timer.start(2333)

    def got_transaction(self, tx):
        with self.transactions_per_second_deque_lock:
            self.transactions_per_second_deque.append(time.time())
        return BitmsgMsgWatchCallbacks.got_transaction(self, tx)

    def add_new_key_clicked(self):
        dlg = AddNewKeyDialog()
        result = dlg.exec_()
        if result:
            saved_key = dlg.key
            if dlg.encryption == ENCRYPT_RSA:
                saved_key = saved_key.der()

            self.saved_keys.append(('', dlg.encryption, saved_key))
            try:
                # TODO - improve this to use proper atomic renaming
                pickle.Pickler(open('keys.dat.new', 'wb')).dump(self.saved_keys)
                if os.path.exists('keys.dat.old'):
                    os.remove('keys.dat.old')
                if os.path.exists('keys.dat'):
                    os.rename('keys.dat', 'keys.dat.old')
                os.rename('keys.dat.new', 'keys.dat')
            except:
                traceback.print_exc()

            self.watch_and_add_key('', dlg.encryption, dlg.key)

    def watch_and_add_key(self, name, encryption_algorithm, key):
        if encryption_algorithm == ENCRYPT_RC4:
            self.watch_rc4(key)
        elif encryption_algorithm == ENCRYPT_AES128:
            self.watch_aes128(key)
        elif encryption_algorithm == ENCRYPT_AES256:
            self.watch_aes256(key)
        elif encryption_algorithm == ENCRYPT_RSA:
            self.watch_rsa(key)

        self.keys_table.insertRow(0)

        w = gui.QTableWidgetItem('name')
        w.setToolTip('name')
        w.setFlags(core.Qt.ItemIsSelectable | core.Qt.ItemIsEnabled | core.Qt.ItemIsEditable)
        #w.setData(Qt.UserRole, 'name')
        self.keys_table.setItem(0, 0, w)

        name_map = {
            ENCRYPT_RC4   : 'RC4',
            ENCRYPT_AES128: 'AES-128',
            ENCRYPT_AES256: 'AES-256',
            ENCRYPT_RSA   : 'RSA',
        }

        w = gui.QTableWidgetItem(name_map[encryption_algorithm])
        w.setToolTip(name_map[encryption_algorithm])
        w.setFlags(core.Qt.ItemIsSelectable | core.Qt.ItemIsEnabled)
        self.keys_table.setItem(0, 1, w)

        if encryption_algorithm == ENCRYPT_RSA:
            der = key.der()
            hasher = hashlib.md5()
            hasher.update(der)
            display_key = hasher.hexdigest().upper()
        else:
            display_key = Bitcoin.bytes_to_hexstring(key, reverse=False)

        w = gui.QTableWidgetItem(display_key)
        w.setToolTip(display_key)
        w.setFlags(core.Qt.ItemIsSelectable | core.Qt.ItemIsEnabled)
        self.keys_table.setItem(0, 2, w)

def main():
    app = gui.QApplication(sys.argv)
    ex = BitmsgMainWindow()
    ex.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
    
