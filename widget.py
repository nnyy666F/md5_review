import hashlib
import sys
import hmac
import zlib
import threading
import time
import os
from PySide6.QtWidgets import QApplication, QWidget, QCheckBox, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QFileDialog, QListView, QComboBox, QMessageBox, QGroupBox
from PySide6.QtGui import QIcon, QStandardItemModel, QStandardItem, QFont
from PySide6.QtCore import Qt, QObject, Signal
import subprocess
# from zlibcrc64 import crc64
from xxhash import xxh64
import math

file1_md5 = None
file2_md5 = None
read_size = 0
local_file1=""
local_file2=""
base_chunk_size = 0


class SettingsWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        global base_chunk_size
        try:
            with open('settings.txt', 'r') as file:
                config_data = file.readlines()

                if config_data:
                    parts = config_data[0].strip().split(',')  
                    if len(parts) >= 2:
                        log_file_path = parts[0]
                        base_chunk_size = parts[1]
                    else:
                        print("文件内容格式不符合预期，无法获取到足够的字段")
                        print(len(parts))
                        base_chunk_size = 10
                else:
                    print("文件为空")
        except FileNotFoundError:
            log_file_path = "hashed_results.txt"
            base_chunk_size = "10"

        path_label = QLabel("日志文件保存路径:")
        self.path_edit = QLineEdit()
        self.path_edit.setText(log_file_path)  # 设置读取到的日志文件路径或者默认值
        self.path_edit.setPlaceholderText("默认hashed_results.txt")
        layout.addWidget(path_label)
        layout.addWidget(self.path_edit)

        chunk_size_label = QLabel("文件读取块大小（MB）建议不超过1024:")
        self.chunk_size_edit = QLineEdit()
        self.chunk_size_edit.setText(base_chunk_size)  # 设置读取到的块大小或者默认值
        self.chunk_size_edit.setPlaceholderText("最小10MB")
        layout.addWidget(chunk_size_label)
        layout.addWidget(self.chunk_size_edit)

        save_button = QPushButton("保存设置")
        save_button.clicked.connect(self.saveSettings)
        layout.addWidget(save_button)

        self.setLayout(layout)
        self.setWindowTitle("设置")
        self.setFixedSize(300, 200)

    def saveSettings(self):
        # 获取输入的设置值
        new_path = self.path_edit.text().strip()
        new_chunk_size_str = self.chunk_size_edit.text().strip()

        try:
            new_chunk_size = int(new_chunk_size_str)
            if new_chunk_size <= 0:
                raise ValueError("块大小必须为正整数")
            # 构建要写入文件的内容，以逗号隔开
            settings_content = f"{new_path},{new_chunk_size}"

            # 指定保存设置的文件路径，这里使用相对路径示例，可根据实际情况调整
            current_path = os.getcwd()
            settings_file_path = os.path.join(current_path, "settings.txt")

            print(settings_file_path)
            with open(settings_file_path, 'w') as file:
                file.write(settings_content)

            # 这里可以添加实际的保存设置逻辑，比如将设置值保存到配置文件等，以下只是简单示例提示信息
            # QMessageBox.information(self, "提示", "设置已保存成功！")
        except ValueError as e:
            QMessageBox.warning(self, "错误", f"设置保存失败，请检查输入是否正确：{str(e)}")

class HashCalculator(QObject):
    progressUpdated = Signal(float, str)
    hashCalculated = Signal(dict, str)
    errorOccurred = Signal(str, str)
    logUpdated = Signal(str)

    def __init__(self, filePath):
        super().__init__()
        self.filePath = filePath
        self.finished = False


    def calculateHashes(self):
        try:
            print("111")

            file_size = 0
            # self.addToLog(f"计算文件: {self.filePath} 开始")
            with open(self.filePath, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)

                data = b''
                if file_size < 1024 * 1024 * 1:
                    print("1")
                    read_size=1024 * 1024 * 1
                    with open(self.filePath, 'rb') as f:
                        data = f.read()
                elif file_size > 1024 * 1024 * 1:
                    print("2")
                    # 初始较小的块大小
                    #base_chunk_size = 1024 * 1024 * 10  # 例如初始设为10MB，可以调整
                    # 最大内存 1024 * 1024 * 100，后面同理，file_size单位字节
                    if (base_chunk_size * 10 < file_size) :
                        multiplier = min(round(file_size / (base_chunk_size * 10), 1), 100)  # 最大不超过10倍初始块大小
                    else :
                        multiplier = min(round(file_size / (base_chunk_size * 10), 1) * (base_chunk_size/1024/1024)/10, 100)
                    print(multiplier,file_size,base_chunk_size,round(file_size / (base_chunk_size * 10), 1) * (base_chunk_size/1024/1024)/10)
                    if multiplier==0 :
                        multiplier=10
                    read_size=math.ceil(base_chunk_size * multiplier)
                    read_bytes = 0
                    with open(self.filePath, 'rb') as f:
                        while True:
                            chunk = f.read(read_size)
                            if not chunk:
                               break
                            data += chunk
                            read_bytes += len(chunk)
                            progress = read_bytes / file_size
                            self.progressUpdated.emit(progress, self.filePath)
                else :
                    print("3")
                    with open(self.filePath, 'rb') as f:
                        data = f.read()

            start_time = time.time()

            # 创建多个线程分别计算不同的哈希值
            md5_thread = threading.Thread(target=self.calculate_md5, args=(data,))
            sha1_thread = threading.Thread(target=self.calculate_sha1, args=(data,))
            sha256_thread = threading.Thread(target=self.calculate_sha256, args=(data,))
            sha384_thread = threading.Thread(target=self.calculate_sha384, args=(data,))
            sha512_thread = threading.Thread(target=self.calculate_sha512, args=(data,))
            ripemd160_thread = threading.Thread(target=self.calculate_ripemd160, args=(data,))
            mac_tripledes_thread = threading.Thread(target=self.calculate_mac_tripledes, args=(data,))
            crc32_thread = threading.Thread(target=self.calculate_crc32, args=(data,))
            # crc64_thread = threading.Thread(target=self.calculate_crc64)
            # blake2sp_thread = threading.Thread(target=self.calculate_blake2sp, args=(data,))
            xxh64_thread = threading.Thread(target=self.calculate_xxh64, args=(data,))

            md5_thread.start()
            sha1_thread.start()
            sha256_thread.start()
            sha384_thread.start()
            sha512_thread.start()
            ripemd160_thread.start()
            mac_tripledes_thread.start()
            crc32_thread.start()
            # crc64_thread.start()
            # blake2sp_thread.start()
            xxh64_thread.start()

            # 等待所有线程完成
            md5_thread.join()
            sha1_thread.join()
            sha256_thread.join()
            sha384_thread.join()
            sha512_thread.join()
            ripemd160_thread.join()
            mac_tripledes_thread.join()
            crc32_thread.join()
            # crc64_thread.join()
            # blake2sp_thread.join()
            xxh64_thread.join()

            end_time = time.time()
            elapsed_time = end_time - start_time

            self.logUpdated.emit(f"传递结果，用时：{elapsed_time:.2f}秒")

            self.hashCalculated.emit({
                "md5": self.md5_result,
                "sha1": self.sha1_result,
                "sha256": self.sha256_result,
                "sha384": self.sha384_result,
                "sha512": self.sha512_result,
                "ripemd160": self.ripemd160_result,
                "mac_tripledes": self.mac_tripledes_result,
                "crc32": self.crc32_result,
                # "crc64": self.crc64_result,
                # "blake2sp": self.blake2sp_result,
                "xxh64": self.xxh64_result
            }, self.filePath)

            self.finished = True
        except Exception as e:
            self.errorOccurred.emit(f"计算哈希时出错：{str(e)}", self.filePath)
            self.finished = True

    def calculate_md5(self, data):
        start_time = time.time()
        self.md5_result = hashlib.md5(data).hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-md5秒")

    def calculate_sha1(self, data):
        start_time = time.time()
        self.sha1_result = hashlib.sha1(data).hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-sha1秒")

    def calculate_sha256(self, data):
        start_time = time.time()
        self.sha256_result = hashlib.sha256(data).hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-sha256秒")

    def calculate_sha384(self, data):
        start_time = time.time()
        self.sha384_result = hashlib.sha384(data).hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-sha384秒")

    def calculate_sha512(self, data):
        start_time = time.time()
        self.sha512_result = hashlib.sha512(data).hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-sha512秒")

    def calculate_ripemd160(self, data):
        start_time = time.time()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(data)
        self.ripemd160_result = ripemd160.hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-160秒")

    def calculate_mac_tripledes(self, data):
        start_time = time.time()
        key = b'dummy_key'
        mac = hmac.new(key, data, hashlib.sha256).digest()
        triple_des = hashlib.new('md5')
        triple_des.update(mac)
        self.mac_tripledes_result = triple_des.hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-mac秒")

    def calculate_crc32(self, data):
        start_time = time.time()
        # 分块大小，可根据实际情况调整，这里设为4096字节，较大的数据块能减少循环次数
        block_size = 4096
        crc_value = 0
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            crc_value = zlib.crc32(block, crc_value)
        self.crc32_result = hex(crc_value & 0xffffffff)[2:].zfill(8)
        end_time = time.time()
        print((end_time - start_time))
        print("-crc32秒")

    def _prepare_file_paths(self):
        file_path1 = local_file1 if local_file1 else ""

        file_path2 = local_file2 if local_file2 else ""
        return f"{file_path1},{file_path2}"

    def calculate_crc64(self):
        file_paths_str = self._prepare_file_paths()
        hash_call_exe_path = os.path.join(os.getcwd(), "Hash_Call.exe")
        if not os.path.exists(hash_call_exe_path):
           print("Hash_Call.exe不存在，请确保其在当前目录下")
           return

        try:
            print("?")
            result = subprocess.run([hash_call_exe_path, file_paths_str], capture_output=True, text=True)
            if result.returncode == 0:
                line = result.stdout
                print(line)
                parts = line.split("的CRC64值为: ")
                if len(parts) > 1:
                   self.crc64_result = parts[1].strip()  # 提取并去除首尾空白字符后赋值
                   # print(self.crc64_result)
            else:
               print(f"调用Hash_Call.exe出现错误: {result.stderr}")
        except Exception as e:
            print(f"发生异常: {e}")

    # def calculate_blake2sp(self, data):
    #     hash_object = BLAKE2s.new(digest_bits=256)
    #     hash_object.update(data)
    #     self.blake2sp_result = hash_object.hexdigest()

    def calculate_xxh64(self, data):
        start_time = time.time()
        self.xxh64_result = xxh64(data).hexdigest()
        end_time = time.time()
        print((end_time-start_time))
        print("-xxh64秒")


class MD5Checker(QWidget):
    last_used_model = None
    def __init__(self, parent=None):
        super().__init__(parent)

        self.initUI()

        self.file1 = None
        self.file2 = None
        self.calculators = {}
        self.smallFileHashes = {}
        self.lastSelectedFile1 = None
        self.lastSelectedFile2 = None

    def initUI(self):
        font = QFont()
        font.setPointSize(10)

        mainLayout = QVBoxLayout()

        # 添加标题
        titleLabel = QLabel("哈希校验工具")
        titleLabel.setFont(QFont("", 15, QFont.Bold))
        titleLabel.setAlignment(Qt.AlignCenter)
        mainLayout.addWidget(titleLabel)

        # 文件选择区域
        fileGroupBox = QGroupBox("选择文件")
        fileLayout = QVBoxLayout()

        self.file1Label = QLabel("选择文件 1:")
        self.file1Button = QPushButton("浏览")
        self.file1Button.clicked.connect(self.selectFile1)
        self.file1Circle = QLabel()
        self.file1Circle.setFixedSize(15, 15)
        self.file1Name = QLabel()

        self.file2Label = QLabel("选择文件 2:")
        self.file2Button = QPushButton("浏览")
        self.file2Button.clicked.connect(self.selectFile2)
        self.file2Circle = QLabel()
        self.file2Circle.setFixedSize(15, 15)
        self.file2Name = QLabel()

        fileLayout.addWidget(self.file1Label)
        fileLayout.addWidget(self.file1Button)
        fileLayout.addWidget(self.file1Circle)
        fileLayout.addWidget(self.file1Name)
        fileLayout.addWidget(self.file2Label)
        fileLayout.addWidget(self.file2Button)
        fileLayout.addWidget(self.file2Circle)
        fileLayout.addWidget(self.file2Name)

        fileGroupBox.setLayout(fileLayout)
        mainLayout.addWidget(fileGroupBox)

        # 加密列表区域
        listGroupBox = QGroupBox("哈希结果")
        resultLayout = QHBoxLayout()

        self.md5List1 = QListView()
        self.model1 = QStandardItemModel()
        self.md5List1.setModel(self.model1)
        self.md5List1.setFont(font)

        self.md5List2 = QListView()
        self.model2 = QStandardItemModel()
        self.md5List2.setModel(self.model2)
        self.md5List2.setFont(font)

        resultLayout.addWidget(self.md5List1)
        resultLayout.addWidget(self.md5List2)

        listGroupBox.setLayout(resultLayout)
        mainLayout.addWidget(listGroupBox)

        # 添加日志列表框
        self.logList = QListView()
        self.logModel = QStandardItemModel()
        self.logList.setModel(self.logModel)
        self.logList.setFont(font)
        mainLayout.addWidget(QLabel("日志:"))
        mainLayout.addWidget(self.logList)

        # MD5 输入框和校验选择框
        self.md5InputLayout = QHBoxLayout()
        self.md5Label = QLabel("选择校验算法:")
        self.md5ComboBox = QComboBox()
        self.md5ComboBox.addItems(["md5", "sha1", "sha256", "sha384", "sha512", "ripemd160", "mac_tripledes", "crc32"])
        self.checkBox = QCheckBox("校验")

        self.hashInputLabel = QLabel("输入哈希值:")
        self.hashInput = QLineEdit()

        self.md5InputLayout.addWidget(self.md5Label)
        self.md5InputLayout.addWidget(self.md5ComboBox)
        self.md5InputLayout.addWidget(self.checkBox)
        self.md5InputLayout.addWidget(self.hashInputLabel)
        self.md5InputLayout.addWidget(self.hashInput)

        mainLayout.addLayout(self.md5InputLayout)

        # 按钮区域
        buttonLayout = QHBoxLayout()

        self.checkButton = QPushButton("校验")
        self.checkButton.clicked.connect(self.checkMD5)

        self.clearButton = QPushButton("清除")
        self.clearButton.clicked.connect(self.clearLists)

        self.aboutButton = QPushButton("关于")
        self.aboutButton.clicked.connect(self.showAbout)

        buttonLayout.addWidget(self.checkButton)
        buttonLayout.addWidget(self.clearButton)
        buttonLayout.addWidget(self.aboutButton)

        settingLayout = QHBoxLayout()
        self.SettingButton = QPushButton("设置")
        self.SettingButton.clicked.connect(self.showSettingsWindow)

        settingLayout.addWidget(self.SettingButton)

        mainLayout.addLayout(buttonLayout)
        mainLayout.addLayout(settingLayout)

        self.setLayout(mainLayout)
        self.setWindowTitle("哈希校验工具")
        self.setFixedSize(800, 600)

    def showSettingsWindow(self):
        self.settings_window = SettingsWindow()
        self.settings_window.setWindowModality(Qt.ApplicationModal)  # 设置窗口为模态，阻止对原窗口操作
        self.settings_window.show()

    def save_hashes_to_file(self, hashes, index):
        """ 将哈希值保存到文件，只更新指定索引的哈希值 """
        temp_content = []
        try:
            with open("hashed_results.txt", "r") as file:
                temp_content = file.readlines()
        except FileNotFoundError:
            pass

        new_content = []
        in_block = False
        new_content_block = []

        for line in temp_content:
            stripped_line = line.strip()
            if stripped_line == str(index):
                if in_block:
                    # 之前已经在该索引的块内，不再处理
                    new_content.extend(new_content_block)
                    new_content.append(f"{stripped_line}\n")
                    new_content_block = []  # 重新开始新的块
                else:
                    in_block = True
                    new_content.append(f"{stripped_line}\n")
                    for hash_type, value in hashes.items():
                        new_content_block.append(f"{hash_type}: {value}\n")
            elif in_block and stripped_line.isdigit():
                # 到达新的索引，结束当前块
                in_block = False
                new_content.extend(new_content_block)
                new_content.append(line)  # 保留当前索引行
                new_content_block = []
            elif not in_block:
                new_content.append(line)

        # 如果在文件末尾仍处于块内，要写入最后一个块
        if in_block:
            new_content.extend(new_content_block)

        with open("hashed_results.txt", "w") as file:
            file.writelines(new_content)


    def load_previous_hashes(self, index):
        """ 从文件读取之前计算的哈希值 """
        hashes = {}
        block_started = False
        block_content = []
        try:
            with open("hashed_results.txt", "r") as file:
                for line in file:
                    if line.strip() == str(index):
                        block_started = True
                    elif block_started and line.strip() == str(index):
                        block_started = False
                        break
                    elif block_started:
                        block_content.append(line.strip())
        except FileNotFoundError:
            pass
        i=0
        for item in block_content:
            # print(block_content)
            i+=1
            #防止数组移除当前索引组
            if(i>8):
                break
            # print(i)
            hash_type, value = item.split(": ")
            hashes[hash_type] = value
        return hashes


    def selectFile1(self):
        global local_file1
        fileName, _ = QFileDialog.getOpenFileName(self, "选择文件 1", "", "All Files (*)")
        if fileName:
            self.file1 = fileName
            self.file1Name.setText(fileName.split('/')[-1])
            self.lastSelectedFile1 = fileName
            local_file1=self.file1

    def selectFile2(self):
        global local_file2
        fileName, _ = QFileDialog.getOpenFileName(self, "选择文件 2", "", "All Files (*)")
        if fileName:
            self.file2 = fileName
            self.file2Name.setText(fileName.split('/')[-1])
            self.lastSelectedFile2 = fileName
            local_file2=self.file2

    def calculateHashesAndAddToModel(self, filePath, index):
        calculator = HashCalculator(filePath)
        self.calculators[filePath] = calculator
        thread = threading.Thread(target=calculator.calculateHashes)
        thread.start()

        calculator.logUpdated.connect(self.addToLog)

        def update_progress(progress, file_path):
            if file_path == self.file1:
                self.addToLog(f"读取进度（文件 1）：{progress * 100:.2f}%")
            elif file_path == self.file2:
                self.addToLog(f"读取进度（文件 2）：{progress * 100:.2f}%")

        calculator.progressUpdated.connect(update_progress)

        def handle_hash_result(result, file_path):
            if index == 1:
                model = self.model1
                # MD5Checker.last_used_model = model  # 更新类属性
            elif index == 2:
                model = self.model2
                # MD5Checker.last_used_model = model  # 更新类属性
            else:
                return

            for hash_type, value in result.items():
                model.appendRow(QStandardItem(f"{hash_type}: {value}"))

            # MD5Checker.last_used_model=model
            if index == 1:
                self.save_hashes_to_file(result,1)
            elif index == 2:
                self.save_hashes_to_file(result,2)

            if self.file1 and self.file2 and self.calculators[self.file1].finished and self.calculators[self.file2].finished:
                if not self.checkBox.isChecked():
                    self.compareHashes()

        calculator.hashCalculated.connect(handle_hash_result)

        def handle_error(error_message, file_path):
            if index == 1:
                model = self.model1
            elif index == 2:
                model = self.model2
            else:
                return
            model.appendRow(QStandardItem(error_message))

        calculator.errorOccurred.connect(handle_error)

    def compareHashes(self):
        selected_algorithm = self.md5ComboBox.currentText().lower()

        hash1 = self.model1.findItems(f"{selected_algorithm}: ", Qt.MatchContains)
        hash2 = self.model2.findItems(f"{selected_algorithm}: ", Qt.MatchContains)

        if hash1 and hash2:
            hash_value1 = hash1[0].text().split(": ")[1].strip()
            hash_value2 = hash2[0].text().split(": ")[1].strip()

            if hash_value1 == hash_value2:
                self.addToLog("校验成功，两个文件哈希值匹配！")
                self.file1Circle.setStyleSheet(f"background-color: {self.getColor('green')}")
                self.file2Circle.setStyleSheet(f"background-color: {self.getColor('green')}")
            else:
                if self.checkBox.isChecked():
                    return
                self.addToLog("校验失败，两个文件哈希值不匹配！")
                self.file1Circle.setStyleSheet(f"background-color: {self.getColor('red')}")
                self.file2Circle.setStyleSheet(f"background-color: {self.getColor('red')}")

    def checkMD5(self):
        global file1_md5
        global file2_md5
        file1_go = 0
        file2_go = 0

        global read_size
        global base_chunk_size

        # 打开文件读取内容
        with open('settings.txt', 'r') as file:
            lines = file.readlines()
            print(lines)
            if lines:
                parts = lines[0].strip().split(',')  # 按逗号分割每行内容，先获取第一行，你可以根据实际情况调整读取哪一行
                if len(parts) >= 2:
                    base_chunk_size = 1024 * 1024 * int(parts[1])  # 将第二个值转换为整数后赋给base_chunk_size
                else:
                    print("文件内容格式不符合预期，无法获取到足够的字段")
                    print(len(parts))
                    base_chunk_size = 1024 * 1024 * 10
            else:
                print("文件为空")

        if self.file1:
            current_file1_md5 = None
            file_stat = os.stat(self.file1)
            last_modified_time = file_stat.st_mtime
            combined_info = f"{self.file1}{last_modified_time}"
            current_file1_md5 = hashlib.md5(combined_info.encode()).hexdigest()
            # print(current_file1_md5,file1_md5)
            if current_file1_md5 == file1_md5:
                self.addToLog("文件1的综合信息MD5值与之前记录相同，无需再次校验。")
                file1_go=1
            else:
                file1_md5 = current_file1_md5


        if self.file2:
            current_file2_md5 = None
            file_stat = os.stat(self.file2)
            last_modified_time = file_stat.st_mtime
            combined_info = f"{self.file2}{last_modified_time}"
            current_file2_md5 = hashlib.md5(combined_info.encode()).hexdigest()
            if current_file2_md5 == file2_md5:
                self.addToLog("文件2的综合信息MD5值与之前记录相同，无需再次校验。")
                file2_go=1
            else:
                file2_md5 = current_file2_md5

        # 清除现有的哈希结果
        if file1_go!=1:
            self.model1.clear()
        if file2_go!=1:
            self.model2.clear()

        # 当勾选校验框
        if self.checkBox.isChecked():
            if self.file1:
                #print("11")
                selected_algorithm = self.md5ComboBox.currentText().lower()
                if file1_go!=1:
                    self.calculateHashesAndAddToModel(self.file1, 1)

                input_hash = self.hashInput.text().strip()

                # 获取哈希列表
                # def wait_for_file1():
                #     while True:
                #         hashList = self.load_previous_hashes(1)
                #         if hashList:
                #             return hashList
                #         time.sleep(0.1)

                hashList = self.load_previous_hashes(1)
                #print(hashList)

                # 将字典转换为列表形式的字符串对
                hashList_strings = [f"{key}: {value}" for key, value in hashList.items()]

                # 从转换后的列表中获取哈希值
                items1 = {}
                for item_str in hashList_strings:
                    parts = item_str.split(": ")
                    if len(parts) == 2:
                        key = parts[0].lower()
                        value = parts[1].strip()
                        items1[key] = value

                # 输出比对的过程
                # print(f"选中的算法: {selected_algorithm}")
                # print(f"输入的哈希值: {input_hash}")
                # print(f"文件1的哈希项: {items1}")

                if selected_algorithm in items1 and input_hash == items1[selected_algorithm]:
                    self.file1Circle.setStyleSheet(f"background-color: {self.getColor('green')}")
                    self.addToLog(f"文件1的哈希值与输入值匹配！")
                    #print("匹配结果: 文件1的哈希值与输入值匹配！")
                else:
                    self.file1Circle.setStyleSheet(f"background-color: {self.getColor('red')}")
                    self.addToLog(f"文件1的哈希值与输入值不匹配！")
                    #print("匹配结果: 文件1的哈希值与输入值不匹配！")

            if self.file2:
                selected_algorithm = self.md5ComboBox.currentText().lower()
                if file2_go!=1:
                    self.calculateHashesAndAddToModel(self.file2, 2)

                input_hash = self.hashInput.text().strip()

                # 获取哈希列表
                # def wait_for_file2():
                #     while True:
                #         hashList = self.load_previous_hashes(2)
                #         if hashList:
                #             return hashList
                #         time.sleep(0.1)

                hashList = self.load_previous_hashes(2)

                # 将字典转换为列表形式的字符串对
                hashList_strings = [f"{key}: {value}" for key, value in hashList.items()]

                # 从转换后的列表中获取哈希值
                items2 = {}
                for item_str in hashList_strings:
                    parts = item_str.split(": ")
                    if len(parts) == 2:
                        key = parts[0].lower()
                        value = parts[1].strip()
                        items2[key] = value

                # 输出比对的过程
                # print(f"选中的算法: {selected_algorithm}")
                # print(f"输入的哈希值: {input_hash}")
                # print(f"文件2的哈希项: {items2}")

                if selected_algorithm in items2 and input_hash == items2[selected_algorithm]:
                    self.file2Circle.setStyleSheet(f"background-color: {self.getColor('green')}")
                    self.addToLog("文件2的哈希值与输入值匹配！")
                    #print("匹配结果: 文件2的哈希值与输入值匹配！")
                else:
                    self.file2Circle.setStyleSheet(f"background-color: {self.getColor('red')}")
                    self.addToLog("文件2的哈希值与输入值不匹配！")
                    #print("匹配结果: 文件2的哈希值与输入值不匹配！")
        else:
            # print("111")
            # 没有勾选校验框，对比两个文件
            if self.file1 and file1_go!=1:
                self.calculateHashesAndAddToModel(self.file1, 1)

            if self.file2 and file2_go!=1:
                self.calculateHashesAndAddToModel(self.file2, 2)

            # 检查两个文件的哈希值
            if self.calculators.get(self.file1) and self.calculators.get(self.file2):
                self.compareHashes()

    def showAbout(self):
        about_text = "哈希校验工具\n\n"
        about_text += "本工具可以对文件进行多种哈希算法的校验，支持 MD5、SHA1、SHA256、SHA384、SHA512、RIPEMD160、MACTripleDES 和 CRC32 等算法。\n"
        about_text += "用户可以选择两个文件进行对比校验，也可以输入已知的哈希值进行校验。\n"
        QMessageBox.about(self, "关于", about_text)

    def getColor(self, color_name):
        if color_name == 'green':
            return '#7CFC00'
        elif color_name == 'red':
            return '#FF0000'

    def addToLog(self, message):
        self.logModel.appendRow(QStandardItem(message))

    def clearLists(self):
        # self.model1.clear()
        # self.model2.clear()
        self.logModel.clear()

if __name__ == "__main__":
    app = QApplication([])
    icon = QIcon('app_icon.ico')
    window = MD5Checker()
    window.show()
    sys.exit(app.exec())
