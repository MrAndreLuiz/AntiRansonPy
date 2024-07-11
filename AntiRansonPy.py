import logging
import os
import psutil
import time
from typing import List, Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constantes
CPU_THRESHOLD = 90
DISK_THRESHOLD = 90
FILE_MOD_THRESHOLD = 10
MONITOR_DURATION = 60
DATABASE_FILE = 'ia_malicious.bd'
LOG_FILE = 'logs.txt'
KEY_FILE = 'chave.key'  # Arquivo para armazenar a chave (File to store the key)

# Configuração de logging
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class DiskMonitor:
    @staticmethod
    def get_all_units() -> List[str]:
        """Retorna uma lista de todas as unidades de disco disponíveis. (Returns a list of all available disk units.)"""
        try:
            return [part.device for part in psutil.disk_partitions(all=True)]
        except Exception as e:
            logging.error(f"Erro ao obter informações das unidades de disco: {e}")
            return []

    @staticmethod
    def monitor_units(units: List[str], file_monitor: 'FileMonitor') -> None:
        """Monitora o uso de disco para cada unidade especificada e modificações de arquivos. (Monitors disk usage for each specified unit and file modifications.)"""
        for unit in units:
            try:
                disk_usage = psutil.disk_usage(unit)
                logging.info(f"Unidade {unit}: {disk_usage.percent}% de uso")
                file_monitor.monitor_modifications(unit)
            except Exception as e:
                logging.error(f"Erro ao obter informações da unidade {unit}: {e}")

class FileMonitor:
    def __init__(self):
        self.file_modifications: Dict[str, int] = {}
        self.event_handler = FileSystemEventHandler()
        self.observer = Observer()

    def monitor_modifications(self, unit: str) -> None:
        """Monitora modificações de arquivos em uma unidade de disco especificada. (Monitors file modifications on a specified disk unit.)"""
        try:
            self.observer.schedule(self.event_handler, unit, recursive=True)
            self.observer.start()
        except OSError as e:
            logging.error(f"Erro ao monitorar modificações em {unit}: {e}")
        except Exception as e:
            logging.error(f"Erro inesperado ao monitorar modificações em {unit}: {e}")

    def stop(self):
        """Para o observador de arquivos. (Stops the file observer.)"""
        try:
            self.observer.stop()
            self.observer.join()
            logging.info("Monitoramento de arquivos parado.")
        except Exception as e:
            logging.error(f"Erro ao parar o monitoramento de arquivos: {e}")

    def on_modified(self, event) -> None:
        """Callback quando um arquivo é modificado. (Callback when a file is modified.)"""
        try:
            if event.is_directory:
                return
            file_path = event.src_path
            process_pids = self.get_process_pid_by_file(file_path)
            if process_pids:
                for pid in process_pids:
                    self.file_modifications[pid] = self.file_modifications.get(pid, 0) + 1
        except psutil.NoSuchProcess as e:
            logging.error(f"Processo não encontrado ao lidar com modificação de arquivo: {e}")
        except psutil.AccessDenied as e:
            logging.error(f"Acesso negado ao lidar com modificação de arquivo: {e}")
        except Exception as e:
            logging.error(f"Erro inesperado ao lidar com modificação de arquivo: {e}")

    def get_process_pid_by_file(self, file_path: str) -> List[int]:
        """Retorna o PID do processo que modificou o arquivo. (Returns the PID of the process that modified the file.)"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if any(file_path in file.path for file in proc.open_files()):
                        processes.append(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as e:
                    logging.error(f"Erro ao obter informações do processo {proc.pid}: {e}")
            return processes
        except Exception as e:
            logging.error(f"Erro ao obter PID do processo que modificou o arquivo {file_path}: {e}")
            return []

    def get_file_modifications_count(self, pid: int) -> int:
        """Retorna o número de modificações de arquivo para um PID específico. (Returns the number of file modifications for a specific PID.)"""
        return self.file_modifications.get(pid, 0)

class ProcessMonitor:
    @staticmethod
    def get_all_processes() -> List[Dict]:
        """Retorna uma lista de todos os processos em execução no sistema. (Returns a list of all processes running on the system.)"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logging.error(f"Erro ao obter informações do processo {proc.pid}: {e}")
            except Exception as e:
                logging.error(f"Erro inesperado ao obter informações do processo {proc.pid}: {e}")
        return processes

    @staticmethod
    def monitor_processes(processes: List[Dict], behavior_analyzer: 'ProcessBehaviorAnalyzer') -> None:
        """Monitora os processos em execução e registra suas informações. (Monitors running processes and logs their information.)"""
        for proc in processes:
            try:
                process_info = proc['name']
                pid = proc['pid']
                logging.info(f"Processo {pid}: {process_info}")
                behavior_analyzer.analyze_process(pid, process_info)
            except KeyError:
                logging.error("Chave inválida no dicionário do processo (Invalid key in process dictionary).")
            except Exception as e:
                logging.error(f"Erro ao monitorar o processo {pid}: {e}")

class ProcessBehaviorAnalyzer:
    def __init__(self):
        self.processes_behavior: Dict[int, Dict] = {}
        self.cpu_threshold = CPU_THRESHOLD
        self.disk_threshold = DISK_THRESHOLD
        self.file_mod_threshold = FILE_MOD_THRESHOLD
        self.monitor_duration = MONITOR_DURATION
        self.file_monitor = FileMonitor()
        self.malicious_processes = MaliciousProcessDatabase(DATABASE_FILE)

    def analyze_process(self, pid: int, process_name: str) -> None:
        """Analisa o comportamento do processo e decide se deve ser finalizado. (Analyzes process behavior and decides whether it should be terminated.)"""
        try:
            if pid not in self.processes_behavior:
                self.processes_behavior[pid] = {
                    'cpu_percent': [],
                    'disk_percent': [],
                    'file_modifications': 0,
                    'start_time': time.time()
                }

            process = psutil.Process(pid)
            cpu_percent = process.cpu_percent(interval=1)
            disk_percent = (process.io_counters().read_bytes + process.io_counters().write_bytes) / psutil.disk_usage('/').total * 100

            self.processes_behavior[pid]['cpu_percent'].append(cpu_percent)
            self.processes_behavior[pid]['disk_percent'].append(disk_percent)
            self.processes_behavior[pid]['file_modifications'] = self.file_monitor.get_file_modifications_count(pid)

            if self.is_malicious_behavior(pid):
                self.terminate_process(pid, process_name)
        except psutil.NoSuchProcess as e:
            logging.error(f"Processo não encontrado ao analisar comportamento: {e}")
            self.processes_behavior.pop(pid, None)
        except psutil.AccessDenied as e:
            logging.error(f"Acesso negado ao analisar comportamento do processo {pid}: {e}")
        except Exception as e:
            logging.error(f"Erro inesperado ao analisar processo {pid}: {e}")

    def is_malicious_behavior(self, pid: int) -> bool:
        """Verifica se o comportamento do processo é considerado malicioso. (Checks if the process behavior is considered malicious.)"""
        try:
            process_data = self.processes_behavior[pid]
            if (any(cpu > self.cpu_threshold for cpu in process_data['cpu_percent']) or
                any(disk > self.disk_threshold for disk in process_data['disk_percent']) or
                process_data['file_modifications'] > self.file_mod_threshold or
                self.detect_anomalous_behavior(process_data)):
                return True
            return False
        except KeyError:
            logging.error(f"Dados do processo {pid} não encontrados.")
            return False
        except Exception as e:
            logging.error(f"Erro ao verificar comportamento malicioso do processo {pid}: {e}")
            return False

    def detect_anomalous_behavior(self, process_data: Dict) -> bool:
        """Detecta padrões de comportamento anômalos que podem indicar atividade maliciosa. (Detects anomalous behavior patterns that may indicate malicious activity.)"""
        # Exemplo: Verificar padrões específicos de comportamento além dos thresholds
        return False

    def terminate_process(self, pid: int, process_name: str) -> None:
        """Finaliza o processo e adiciona ao banco de dados de processos maliciosos. (Terminates the process and adds it to the malicious processes database.)"""
        try:
            logging.warning(f"Processo malicioso detectado e finalizado: {process_name} (PID: {pid})")
            self.malicious_processes.add_malicious_process(process_name)
            process = psutil.Process(pid)
            process.terminate()
        except psutil.NoSuchProcess:
            logging.error(f"Processo {pid} não existe mais.")
            self.processes_behavior.pop(pid, None)
        except psutil.AccessDenied:
            logging.error(f"Permissão negada ao finalizar o processo {pid}.")
        except Exception as e:
            logging.error(f"Erro ao finalizar o processo {pid}: {e}")

    def cleanup(self):
        """Limpa recursos utilizados pelo analisador de comportamento de processo. (Cleans up resources used by the process behavior analyzer.)"""
        try:
            self.file_monitor.stop()
        except Exception as e:
            logging.error(f"Erro ao parar o monitoramento de arquivos: {e}")

class MaliciousProcessDatabase:
    def __init__(self, filename: str):
        self.filename = filename
        self.key_manager = KeyManager()

    def add_malicious_process(self, process_name: str) -> None:
        """Adiciona um processo malicioso ao banco de dados. (Adds a malicious process to the database.)"""
        try:
            encrypted_name = self.key_manager.encrypt(process_name.encode())
            with open(self.filename, 'ab') as f:
                f.write(encrypted_name)
        except Exception as e:
            logging.error(f"Erro ao adicionar processo malicioso ao banco de dados: {e}")

    def list_malicious_processes(self) -> List[str]:
        """Lista todos os processos maliciosos no banco de dados. (Lists all malicious processes in the database.)"""
        malicious_processes = []
        try:
            with open(self.filename, 'rb') as f:
                encrypted_data = f.read()
                decrypted_data = self.key_manager.decrypt(encrypted_data)
                malicious_processes = decrypted_data.decode().splitlines()
        except Exception as e:
            logging.error(f"Erro ao listar processos maliciosos do banco de dados: {e}")
        return malicious_processes

class KeyManager:
    def __init__(self):
        self.key = self.load_key()

    def load_key(self) -> bytes:
        """Carrega a chave criptográfica do arquivo ou gera uma nova se não existir. (Loads the cryptographic key from file or generates a new one if it doesn't exist.)"""
        try:
            if os.path.exists(KEY_FILE):
                with open(KEY_FILE, 'rb') as f:
                    return f.read()
            else:
                key = self.generate_key()
                with open(KEY_FILE, 'wb') as f:
                    f.write(key)
                return key
        except Exception as e:
            logging.error(f"Erro ao carregar ou gerar a chave criptográfica: {e}")
            raise

    def generate_key(self) -> bytes:
        """Gera uma nova chave criptográfica. (Generates a new cryptographic key.)"""
        return os.urandom(32)

    def encrypt(self, data: bytes) -> bytes:
        """Criptografa os dados usando AES-256. (Encrypts data using AES-256.)"""
        try:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(bytes.fromhex('51FE$%125ALOFODJ&1452')), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            return encryptor.update(padded_data) + encryptor.finalize()
        except Exception as e:
            logging.error(f"Erro ao criptografar os dados: {e}")
            raise

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Descriptografa os dados usando AES-256. (Decrypts data using AES-256.)"""
        try:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(bytes.fromhex('51FE$%125ALOFODJ&1452')), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            return unpadder.update(decrypted_data) + unpadder.finalize()
        except Exception as e:
            logging.error(f"Erro ao descriptografar os dados: {e}")
            raise

def main():
    try:
        disk_monitor = DiskMonitor()
        file_monitor = FileMonitor()
        process_analyzer = ProcessBehaviorAnalyzer()

        units = disk_monitor.get_all_units()
        disk_monitor.monitor_units(units, file_monitor)

        while True:
            processes = ProcessMonitor.get_all_processes()
            ProcessMonitor.monitor_processes(processes, process_analyzer)

            # Monitoramento contínuo - reiniciar se o serviço for interrompido
            time.sleep(MONITOR_DURATION)

    except KeyboardInterrupt:
        logging.info("Monitoramento encerrado pelo usuário. (Monitoring ended by user.)")
    except Exception as e:
        logging.error(f"Erro inesperado no monitoramento: {e}")
    finally:
        process_analyzer.cleanup()

if __name__ == "__main__":
    main()