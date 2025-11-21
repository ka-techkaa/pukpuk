#TODO:
#ДОБАВИТЬ ВЫБОР КОЛИЧЕСТВА ПАКЕТОВ. СМОТРИ ИНТЕРФЕЙС КОМБО
#поменять дизайн приложения этого виуал
#исправиьь слова грамматика


from PyQt6.QtWidgets import (
    QMainWindow, 
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QApplication,
    QSplitter,
    QTextEdit,
    QTableView,
    QHeaderView,
    QComboBox,
    QFileDialog,
    QMessageBox

)
from core.NetworkSniffer import NetworkSniffer
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, pyqtSignal, QSortFilterProxyModel
from PyQt6.QtGui import QColor
from core.fileOOOOOOOOO import export_packets_to_csv
import pyqtgraph as pg

class PacketTable(QAbstractTableModel):
   def __init__(self, data):
      super().__init__()
      self._data = data
      self._headers = [
         '№',
         'source',
         'destination',
         'protokol',
         'length',
         'time'
      ]

   def add_packet(self, packet):
      self.beginInsertRows(QModelIndex(), len(self._data), len(self._data))
      self._data.append(packet)
      self.endInsertRows()

   def clear(self):
      self.beginResetModel()
      self._data = []
      self.endResetModel()


   def rowCount(self, parent = QModelIndex()):
      return len(self._data)
   
   def columnCount(self, parent = QModelIndex()):
      return len(self._headers)

   def data(self, index, role = Qt.ItemDataRole.DisplayRole):
      if not index.isValid():
         return None
      row = index.row()
      column = index.column()

      if role == Qt.ItemDataRole.DisplayRole:
         packet = self._data[row]
         match column:
            case 0:
               return packet.get('no', '')
            case 1:
               return str(packet.get('source', ""))
            case 2:
               return str(packet.get('destination', ""))
            case 3:
               return str(packet.get('protocol', ""))
            case 4:
               return packet.get('length', "")
            case 5:
               return str(packet.get('time', ""))
            case _: 
               return ""
         #keys = list(packet.keys())
         #return str(packet[keys[column]])
      
      elif role == Qt.ItemDataRole.BackgroundRole:
         packet = self._data[row]

         if packet ['protocol'] == 'TCP':
            return QColor(241,156,187)
         elif packet ['protocol'] == 'UDP':
            return QColor(251,206,177)
         
      return None
   
   def headerData(self, section, orientation, role = Qt.ItemDataRole.DisplayRole):
      if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
         return self._headers[section]
      return None
   


class MainWindow(QMainWindow):

   update_signal = pyqtSignal(dict)

   def __init__(self):
      super().__init__()
      self.sniffer = NetworkSniffer()
      self.max_packets = None  #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
      self.init_ui()
      self.setup_connections()

   def init_ui(self):
      self.setWindowTitle("приЛОжуХа")
      self.setGeometry(100, 100, 1200, 800)

      central_widget = QWidget()
      self.setCentralWidget(central_widget)

      layout = QVBoxLayout(central_widget)

      control_layout = QHBoxLayout()

      self.interface_combo = QComboBox()
      self.interface_combo.addItems(["Все интерфейсы"] + [iface for iface in self.sniffer.get_available_interface() if iface != 'lo'])

      self.packet_count_combo = QComboBox()
      self.packet_count_combo.addItems(["Бесконечно", "10", "50", "100", "500", "1000"]) #====================================================

      self.packet_count_combo.currentTextChanged.connect(self.on_packet_count_changed) #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

      self.start_btn = QPushButton("Старт")
      self.stop_btn = QPushButton("Стоп")
      self.stop_btn.setEnabled(False)
      self.clear_btn = QPushButton("Очистка")
      self.export_btn = QPushButton("CSV")

      control_layout.addWidget(self.packet_count_combo)
      control_layout.addWidget(self.interface_combo)
      control_layout.addWidget(self.start_btn)
      control_layout.addWidget(self.stop_btn)
      control_layout.addWidget(self.export_btn)
      control_layout.addWidget(self.clear_btn)
      

      self.packet_table = QTableView()
      self.table_model = PacketTable([])
      self.proxy_table_model = QSortFilterProxyModel()
      self.proxy_table_model.setSourceModel(self.table_model)
      self.proxy_table_model.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

      self.packet_table.setModel(self.proxy_table_model)
      self.packet_table.setSortingEnabled(True)
      header = self.packet_table.horizontalHeader()
      header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
      header.setStretchLastSection(True)



      self.packet_details = QTextEdit()
      self.packet_details.setReadOnly(True)

      splitter = QSplitter(Qt.Orientation.Vertical)
      splitter.addWidget(self.packet_table)
      splitter.addWidget(self.packet_details)
      

      layout.addLayout(control_layout)
      layout.addWidget(splitter)

      self.stats_plot = pg.PlotWidget(title = "Распределение по протоколам")
      self.stats_plot.setBackground((250,218,221))
      layout.addWidget(self.stats_plot)

   def setup_connections(self):
      self.start_btn.clicked.connect(self.start_sniffer)
      self.stop_btn.clicked.connect(self.stop_sniffer)

      self.clear_btn.clicked.connect(self.clear_capture)

      self.packet_table.clicked.connect(self.show_packet_details)

      self.export_btn.clicked.connect(self.export_csv)

      self.update_signal.connect(self.add_packet_to_table)
      self.sniffer.set_new_packet_callback(lambda pkt: self.update_signal.emit(pkt))

   def on_packet_count_changed(self, text): #===============================================================
    if text == "Бесконечно":
        self.max_packets = None
    else:
        try:
            self.max_packets = int(text)
        except ValueError:
            self.max_packets = None

   def add_packet_to_table(self, packet_info):
      self.table_model.add_packet(packet_info)
      if self.max_packets is not None and len(self.table_model._data) >= self.max_packets: #=====================================================
         self.stop_sniffer()
        # QMessageBox.information(self, "Захват завершен", f"Захвачено заданное количество пакетов: {self.max_packets}")
        
   def show_packet_details(self, index):
      if not index.isValid():
         return
      
      row = index.row()
      packet = self.table_model._data[row]
      details = f"""
      Packet #{packet['no']}
      Time: {packet['time']}
      Source: {packet['source']}
      Destination: {packet['destination']}
      Protocol: {packet['protocol']}
      Length: {packet['length']} bytes
      """

      self.packet_details.setText(details)

   def start_sniffer(self):
            
      selected_interface = self.interface_combo.currentText()
      if selected_interface == "Все интерфейсы":
         selected_interface = None

      self.on_packet_count_changed(self.packet_count_combo.currentText()) #====================================================

      self.sniffer.start(interface=selected_interface)
      self.start_btn.setEnabled(False)
      self.stop_btn.setEnabled(True)
        
   def stop_sniffer(self):
      self.sniffer.stop()
      self.start_btn.setEnabled(True)
      self.stop_btn.setEnabled(False)

      self.update_statistics()

   def clear_capture(self):
      self.sniffer.clear_capture()
      self.table_model.clear()
      self.packet_details.clear()
      self.update_statistics()


   def update_statistics(self):
      stats = self.sniffer.get_statistics()

      self.stats_plot.clear()

      protocols = list(stats['protocols'].keys())
      counts = list(stats['protocols'].values())

      if counts:
         bg = pg.BarGraphItem(x=range(len(protocols)), height = counts, width = 0.6, brush = (204,204,255))
         self.stats_plot.addItem(bg)

         self.stats_plot.getAxis('bottom').setTicks(
            [[(i, protocol) for i, protocol in enumerate(protocols)]]
         )
         self.stats_plot.setLabel('left', 'Количсетво пакетов')
         self.stats_plot.setLabel('bottom', 'Протоколы')

   def export_csv(self):
      if not self.sniffer.packets:
         QMessageBox.warning(self, "Нет данных", "Нет пакетов для экспорта")
         return
      
      path, _ = QFileDialog.getSaveFileName(
         self,
         "Сохранить csv"
         "csv Files (*.csv)",
         "packets.csv"
      )

      if path:
         try: 
            export_packets_to_csv(self.sniffer.packets, path)
            QMessageBox.information(self, "готова", "экспорт успешно выполнен")
         except Exception as e:
            QMessageBox.critical(self, "ошибка" , f"Не скачалось /n{e}")


if __name__ == "__main__":
   app = QApplication([])
   window = MainWindow()
   window.show()
   app.exec()
