import os

from PyQt4 import QtGui as gui
from addnewkey_ui import Ui_AddNewKey

from bitcoin import Bitcoin
from common import *

class AddNewKeyDialog(gui.QDialog, Ui_AddNewKey):
    def __init__(self, *args, **kwargs):
        gui.QDialog.__init__(self, *args, **kwargs)
        Ui_AddNewKey.__init__(self)
        self.setupUi(self)

        self.pushButton_ok.clicked.connect(self.ok_clicked)
        self.pushButton_cancel.clicked.connect(self.reject)
        self.comboBox_key_type.currentIndexChanged.connect(self.selected_encryption_changed)
        self.radioButton_hex.clicked.connect(self.key_format_changed)
        self.radioButton_utf8.clicked.connect(self.key_format_changed)
        self.textEdit_key.textChanged.connect(self.key_changed)
        self.pushButton_open_keyfile.clicked.connect(self.open_keyfile_pressed)

        self.rsa_key = False
        self.selected_key_format = 'utf8'
        self.set_selected_encryption(ENCRYPT_AES256)

    def set_selected_encryption(self, key_type):
        self.selected_encryption = key_type

        index_map = {
            ENCRYPT_RC4: 0,
            ENCRYPT_AES128: 1,
            ENCRYPT_AES256: 2,
            ENCRYPT_RSA: 3,
        }

        self.comboBox_key_type.setCurrentIndex(index_map[key_type])

        show_key_button = (key_type == ENCRYPT_RSA)

        self.textEdit_key.setVisible(not show_key_button)
        self.radioButton_hex.setVisible(not show_key_button)
        self.radioButton_utf8.setVisible(not show_key_button)
        self.label_key_requirements.setVisible(not show_key_button)
        self.pushButton_open_keyfile.setVisible(show_key_button)

        self.update_key_requirements_label()

    def update_key_requirements_label(self):
        text_length = self.get_key_as_bytes()

        if self.selected_encryption == ENCRYPT_RC4:
            self.label_key_requirements.setText('(Any key length of at least 1 byte allowed)')
        elif self.selected_encryption == ENCRYPT_AES128:
            self.label_key_requirements.setText('(Key of length 16 bytes required ({}/16))'.format(len(text_length)))
        elif self.selected_encryption == ENCRYPT_AES256:
            self.label_key_requirements.setText('(Key of length 32 bytes required ({}/32))'.format(len(text_length)))

    def ok_clicked(self):
        if self.selected_encryption == ENCRYPT_RSA:
            if self.rsa_key is None:
                self.QMessageBox.information(self, "Key not provided", "You must select a private key file.")
                return
            else:
                self.encryption = self.selected_encryption
                self.key = self.rsa_key
                self.accept()
        else:
            key = self.get_key_as_bytes()
            if self.selected_encryption == ENCRYPT_RC4 and len(key) < 1:
                self.QMessageBox.information(self, "Key not provided", "You must provide a key of at least 1 byte in size for RC4.")
                return
            if self.selected_encryption == ENCRYPT_AES128 and len(key) != 16:
                self.QMessageBox.information(self, "Key not provided", "You must provide a key of exactly 16 bytes in size for AES-128.")
                return
            if self.selected_encryption == ENCRYPT_AES256 and len(key) != 32:
                self.QMessageBox.information(self, "Key not provided", "You must provide a key of exactly 32 bytes in size for AES-256.")
                return
 
            self.encryption = self.selected_encryption
            self.key = key

        self.accept()

    def selected_encryption_changed(self):
        index = self.comboBox_key_type.currentIndex()

        encrypt_map = {
            0: ENCRYPT_RC4,
            1: ENCRYPT_AES128,
            2: ENCRYPT_AES256,
            3: ENCRYPT_RSA,
        }

        self.set_selected_encryption(encrypt_map[index])

    def get_key_as_bytes(self):
        if self.selected_key_format == 'utf8':
            text = self.textEdit_key.toPlainText()
            return str(text).encode('utf8')
        elif self.selected_key_format == 'hex':
            text = self.textEdit_key.toPlainText()
            text = text.replace(':', '').replace(' ', '').replace('\t','').replace('\n', '').replace('\r', '').replace(',','').lower()
            return Bitcoin.hexstring_to_bytes(str(text), reverse=False)

    def key_format_changed(self):
        is_utf8 = self.radioButton_utf8.isChecked()
        is_hex  = self.radioButton_hex.isChecked()
        assert is_utf8 ^ is_hex

        if self.selected_key_format == 'utf8':
            if is_utf8:
                return
            # change to hex from utf8
            text = self.textEdit_key.toPlainText()
            text = Bitcoin.bytes_to_hexstring(str(text).encode('utf8'), reverse=False)
            self.selected_key_format = 'hex'
            self.textEdit_key.setText(text)
        elif self.selected_key_format == 'hex':
            if is_hex:
                return
            # change to utf8 from hex
            try:
                text = self.textEdit_key.toPlainText()
                text = Bitcoin.hexstring_to_bytes(str(text), reverse=False).decode('utf8')
                self.selected_key_format = 'utf8'
                self.textEdit_key.setText(text)
            except UnicodeDecodeError:
                gui.QMessageBox.information(self, "Unicode Error", "The hex content cannot be converted to UTF-8")
                self.radioButton_utf8.setChecked(False)
                self.radioButton_hex.setChecked(True)
    
    def key_changed(self):
        self.update_key_requirements_label()

    def open_keyfile_pressed(self):
        r = gui.QFileDialog.getOpenFileName(self, "Open Private Key File", '', "Key Files (*.key; *.pem)")
        if r is not None and os.path.exists(r):
            with open(r, "rb") as fp:
                contents = fp.read().decode('ascii')
            key = load_private_key(contents)
            if key is None:
                gui.QMessageBox.information(self, "Key file error", "The selected key file is not in PEM format.")
            else:
                self.rsa_key = key
                self.pushButton_open_keyfile.setText('{}'.format(r))
                return
        self.pushButton_open_keyfile.setText('Open Private Key File...')
        self.rsa_key = None


