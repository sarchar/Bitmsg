# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'addnewkey.ui'
#
# Created: Sat Oct 19 02:21:40 2013
#      by: PyQt4 UI code generator 4.10.1
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_AddNewKey(object):
    def setupUi(self, AddNewKey):
        AddNewKey.setObjectName(_fromUtf8("AddNewKey"))
        AddNewKey.resize(562, 315)
        self.verticalLayout = QtGui.QVBoxLayout(AddNewKey)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.groupBox = QtGui.QGroupBox(AddNewKey)
        self.groupBox.setTitle(_fromUtf8(""))
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.groupBox)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.label = QtGui.QLabel(self.groupBox)
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayout_2.addWidget(self.label)
        self.comboBox_key_type = QtGui.QComboBox(self.groupBox)
        self.comboBox_key_type.setObjectName(_fromUtf8("comboBox_key_type"))
        self.comboBox_key_type.addItem(_fromUtf8(""))
        self.comboBox_key_type.addItem(_fromUtf8(""))
        self.comboBox_key_type.addItem(_fromUtf8(""))
        self.comboBox_key_type.addItem(_fromUtf8(""))
        self.horizontalLayout_2.addWidget(self.comboBox_key_type)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.label_2 = QtGui.QLabel(self.groupBox)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.verticalLayout_2.addWidget(self.label_2)
        self.horizontalLayout_4 = QtGui.QHBoxLayout()
        self.horizontalLayout_4.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.radioButton_utf8 = QtGui.QRadioButton(self.groupBox)
        self.radioButton_utf8.setChecked(True)
        self.radioButton_utf8.setObjectName(_fromUtf8("radioButton_utf8"))
        self.horizontalLayout_4.addWidget(self.radioButton_utf8)
        self.radioButton_hex = QtGui.QRadioButton(self.groupBox)
        self.radioButton_hex.setObjectName(_fromUtf8("radioButton_hex"))
        self.horizontalLayout_4.addWidget(self.radioButton_hex)
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_4.addItem(spacerItem1)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.textEdit_key = QtGui.QTextEdit(self.groupBox)
        self.textEdit_key.setObjectName(_fromUtf8("textEdit_key"))
        self.verticalLayout_2.addWidget(self.textEdit_key)
        self.label_key_requirements = QtGui.QLabel(self.groupBox)
        self.label_key_requirements.setObjectName(_fromUtf8("label_key_requirements"))
        self.verticalLayout_2.addWidget(self.label_key_requirements)
        self.horizontalLayout_3 = QtGui.QHBoxLayout()
        self.horizontalLayout_3.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.pushButton_open_keyfile = QtGui.QPushButton(self.groupBox)
        self.pushButton_open_keyfile.setObjectName(_fromUtf8("pushButton_open_keyfile"))
        self.horizontalLayout_3.addWidget(self.pushButton_open_keyfile)
        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem2)
        self.verticalLayout_2.addLayout(self.horizontalLayout_3)
        spacerItem3 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem3)
        self.horizontalLayout = QtGui.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem4 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem4)
        self.pushButton_ok = QtGui.QPushButton(self.groupBox)
        self.pushButton_ok.setObjectName(_fromUtf8("pushButton_ok"))
        self.horizontalLayout.addWidget(self.pushButton_ok)
        self.pushButton_cancel = QtGui.QPushButton(self.groupBox)
        self.pushButton_cancel.setObjectName(_fromUtf8("pushButton_cancel"))
        self.horizontalLayout.addWidget(self.pushButton_cancel)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.verticalLayout.addWidget(self.groupBox)

        self.retranslateUi(AddNewKey)
        QtCore.QMetaObject.connectSlotsByName(AddNewKey)

    def retranslateUi(self, AddNewKey):
        AddNewKey.setWindowTitle(_translate("AddNewKey", "Add New Key", None))
        self.label.setText(_translate("AddNewKey", "Key Type:", None))
        self.comboBox_key_type.setItemText(0, _translate("AddNewKey", "RC4 (Weak)", None))
        self.comboBox_key_type.setItemText(1, _translate("AddNewKey", "AES-128 (Good)", None))
        self.comboBox_key_type.setItemText(2, _translate("AddNewKey", "AES-256 (Best)", None))
        self.comboBox_key_type.setItemText(3, _translate("AddNewKey", "RSA (Public key)", None))
        self.label_2.setText(_translate("AddNewKey", "Key:", None))
        self.radioButton_utf8.setText(_translate("AddNewKey", "UTF-8", None))
        self.radioButton_hex.setText(_translate("AddNewKey", "Hex", None))
        self.label_key_requirements.setText(_translate("AddNewKey", "(16 bytes required)", None))
        self.pushButton_open_keyfile.setText(_translate("AddNewKey", "Open Private Key File...", None))
        self.pushButton_ok.setText(_translate("AddNewKey", "OK", None))
        self.pushButton_cancel.setText(_translate("AddNewKey", "Cancel", None))

