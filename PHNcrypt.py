# -*- coding: utf-8 -*-
"""
Created on Sun Feb 20 13:07:04 2022

@author: andym
"""

import sys
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QPushButton, QAction, QLineEdit, QMessageBox, QLabel, QFileDialog

from PyQt5.QtGui import QIcon,QPainter,QFont
from PyQt5.QtCore import pyqtSlot, Qt
import pandas as pd

import os
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'PHN encrytion application'
        self.left = 50
        self.top = 50
        self.width = 900
        self.height = 400
        self.aes = AESCipher(self.read_key())
        
        self.initUI()
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
        
        # Set up font
        bold=QFont('Arial', 10)
        bold.setBold(True)
        
        # =============================================================================
        # Draw the encrypt from file    
        # =============================================================================
        
        # Create a line of text above the textbox
        self.header_files = QLabel(self)
        self.header_files.move(0,20)
        self.header_files.resize(450,20)
        self.header_files.setAlignment(Qt.AlignCenter)
        self.header_files.setFont(bold)
        self.header_files.setText('Encrypt / decrypt column from file')
        
        # Create a line of text above the textbox
        self.textbox_label = QLabel(self)
        self.textbox_label.move(20,40)
        self.textbox_label.resize(280,20)
        self.textbox_label.setText('Column name to encrypt')
        
        # Create textbox
        self.column_textbox = QLineEdit(self)
        self.column_textbox.move(20,60)
        self.column_textbox.resize(280,30)
        
        # Create a line of text above the textbox
        self.browse_label = QLabel(self)
        self.browse_label.move(20,90)
        self.browse_label.resize(280,20)
        self.browse_label.setText('File path')
        
        # Create textbox
        self.browse_textbox = QLineEdit(self)
        self.browse_textbox.move(20,110)
        self.browse_textbox.resize(280,30)
        
        # Create a browse button
        self.browse_button = QPushButton('Browse', self)
        self.browse_button.move(310,110)
        self.browse_button.resize(90, 30)
        self.browse_button.clicked.connect(self.browse_on_click)
        
        # Create a button in the window
        self.encrypt_column_button = QPushButton('Encrypt column', self)
        self.encrypt_column_button.move(20,150)
        
        # Create a button in the window
        self.decrypt_column_button = QPushButton('Decrypt column', self)
        self.decrypt_column_button.move(180,150)
        

        # connect button to function on_click
        self.encrypt_column_button.clicked.connect(self.encrypt_file_on_click)
        self.decrypt_column_button.clicked.connect(self.decrypt_file_on_click)
        
        # =============================================================================
        # Draw the encrypt / decrype from string    
        # =============================================================================
        
        # Create a line of text above the textbox
        self.header_single = QLabel(self)
        self.header_single.move(450,20)
        self.header_single.resize(450,20)
        self.header_single.setAlignment(Qt.AlignCenter)
        self.header_single.setFont(bold)
        self.header_single.setText('Encrypt / decrypt single value')
        
        
        # Create a label for encryping a single value
        self.textbox_label = QLabel(self)
        self.textbox_label.move(470,40)
        self.textbox_label.resize(280,20)
        self.textbox_label.setText('Value to encrypt')
        
        # Create textbox
        self.encrypt_textbox = QLineEdit(self)
        self.encrypt_textbox.move(470,60)
        self.encrypt_textbox.resize(280,30)
        
        # Create a encrypt button
        self.encrypt_value_button = QPushButton('Encrypt', self)
        self.encrypt_value_button.move(760,60)
        self.encrypt_value_button.resize(90, 30)
        self.encrypt_value_button.clicked.connect(self.encrypt_single_value_on_click)
        
        # Create a label for decryping a single value
        self.textbox_label = QLabel(self)
        self.textbox_label.move(470,90)
        self.textbox_label.resize(280,20)
        self.textbox_label.setText('Value to decrypt')
        
        # Create textbox
        self.decrypt_textbox = QLineEdit(self)
        self.decrypt_textbox.move(470,110)
        self.decrypt_textbox.resize(280,30)
        
        # Create a decrypt button
        self.decrypt_value_button = QPushButton('Decrypt', self)
        self.decrypt_value_button.move(760,110)
        self.decrypt_value_button.resize(90, 30)
        self.decrypt_value_button.clicked.connect(self.decrypt_single_value_on_click)
        
        # Create a label for decryping a single value
        self.textbox_label = QLabel(self)
        self.textbox_label.move(470,140)
        self.textbox_label.resize(280,20)
        self.textbox_label.setText('Return value')
        
        # Create textbox
        self.return_textbox = QLineEdit(self)
        self.return_textbox.move(470,160)
        self.return_textbox.resize(280,30)
        
        self.show()
    
    # =============================================================================
    # Helpers / backend functions    
    # =============================================================================
    
    # paint center line
    def paintEvent(self, a0):
        painter = QPainter(self)
        # self.painter.setPen(QT.black)
        painter.drawLine(450,10,450,225)
    
    ## Show an error message and reset the console
    def error_message(self, message, reset_column = True):
        QMessageBox.question(self, 'ERROR', message, QMessageBox.Ok, QMessageBox.Ok)
        if reset_column:
            self.column_textbox.setText("")
        self.browse_textbox.setText("")
        
    # Read or create the key file
    def read_key(self):
        # TODO
        key = 'ACD32938EF2A2cd3'
        return key

    # Import and return dataframe
    def import_file(self, path, col):
        if path.endswith(('.xlsx','.xls')):
            df = pd.read_excel(path, dtype= {col:str})
        elif '.csv' in path:
            df = pd.read_csv(path, dtype= {col:str})
        elif path.endswith('.tsv'):
            df = pd.read_csv(path, sep = '\t', dtype= {col:str})
        else:
            self.error_message("File extension must be one of the following: .tsv .csv .xlsx .xls", reset_column = False)
            return None
        if col not in df.columns:
            self.error_message("%s not in file columns" % col)
            return None
        return df

    ## This will actually encrypt the file
    def encrypt_file(self, path, col):
        df = self.import_file(path, col)
        if df is None: return None
        df['%s_encrypted' % col] = df[col].apply(lambda x: self.aes.encrypt(x).decode('UTF-8'))
        
        save_loc = os.path.splitext(path)[0]+'_encrypted.tsv'
        map_loc = os.path.splitext(path)[0]+'_encryptionMap.tsv'
        df.drop(col, axis = 1).to_csv(save_loc, index = None, sep = '\t')
        df[[col,'%s_encrypted' % col]].to_csv(map_loc, index = None, sep = '\t')
        return "File saved at: %s" % save_loc
    
    ## This will actually decrypt the file
    def decrypt_file(self, path, col):
        if col.endswith('_encrypted'): newcol = col.split('_')[0]+'_decrypted'
        else: newcol = col+'_decrypted'
        df = self.import_file(path, col)
        if df is None: return None
        df[newcol] = df[col].apply(lambda x: self.aes.decrypt(x.encode()))
        
        if path.endswith('_encrypted.tsv'):
            save_loc = path.split('_encrypted')[0]+'_decrypted.tsv'
        else:
            save_loc = os.path.splitext(path)[0]+'_decrypted.tsv'
        df.to_csv(save_loc, index = None, sep = '\t')
        return "File saved at: %s" % save_loc
    
    # Encrypt a single value base64.b64encode(cipher.encrypt(raw.encode()))
    @pyqtSlot()
    def encrypt_single_value_on_click(self):
        val = self.encrypt_textbox.text()
        enc = self.aes.encrypt(val)
        self.return_textbox.setText(enc.decode('UTF-8'))
        return
    
    @pyqtSlot()
    def decrypt_single_value_on_click(self):
        val = self.decrypt_textbox.text()
        enc = self.aes.decrypt(val.encode())
        self.return_textbox.setText(enc)
        return

    @pyqtSlot()
    def encrypt_file_on_click(self):
        col = self.column_textbox.text()
        path = self.browse_textbox.text()
        message = self.encrypt_file(path, col)
        if not message is None:
            QMessageBox.question(self, 'Message', message, QMessageBox.Ok, QMessageBox.Ok)
        self.column_textbox.setText("")
        self.browse_textbox.setText("")
        
    def decrypt_file_on_click(self):
        col = self.column_textbox.text()
        path = self.browse_textbox.text()
        message = self.decrypt_file(path, col)
        if not message is None:
            QMessageBox.question(self, 'Message - pythonspot.com', message, QMessageBox.Ok, QMessageBox.Ok)
        self.column_textbox.setText("")
        self.browse_textbox.setText("")
        
    @pyqtSlot()
    def browse_on_click(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"QFileDialog.getOpenFileName()", 
                                                  "C:/",
                                                  filter="All Files (*)", options=options)
        if fileName:
            self.browse_textbox.setText(fileName)
    

# =============================================================================
# Run main
# =============================================================================


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())