import os
import random
import string
import time
import multiprocessing

def create_test_files(directory, num_files):
    try:
        os.makedirs(directory, exist_ok=True)
        for i in range(1, num_files + 1):
            file_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + ".test"
            file_path = os.path.join(directory, file_name)
            with open(file_path, 'w') as f:
                f.write("Conteúdo do arquivo de teste.")
        print(f"{num_files} arquivos criados com sucesso no diretório: {directory}")
    except Exception as e:
        print(f"Erro ao criar arquivos de teste: {e}")

def delete_test_files(directory):
    try:
        for file_name in os.listdir(directory):
            if file_name.endswith(".test"):
                file_path = os.path.join(directory, file_name)
                os.remove(file_path)
        print(f"Arquivos deletados com sucesso do diretório: {directory}")
    except Exception as e:
        print(f"Erro ao deletar arquivos de teste: {e}")

def simulate_malicious_behavior():
    try:
        while True:
            # Simulação de comportamento malicioso que consome CPU
            for i in range(1000000):
                pass
            time.sleep(1)
    except KeyboardInterrupt:
        print("Simulação de comportamento malicioso interrompida pelo usuário.")

if __name__ == "__main__":
    try:
        directory = "Teste"
        
        # Inicia processo para criar os arquivos de teste
        create_process = multiprocessing.Process(target=create_test_files, args=(directory, 2000))
        create_process.start()
        
        # Inicia processo para deletar os arquivos de teste enquanto simula comportamento malicioso
        delete_process = multiprocessing.Process(target=delete_test_files, args=(directory,))
        delete_process.start()
        
        # Simula comportamento malicioso que consome CPU
        simulate_malicious_behavior()
        
        # Aguarda até que ambos os processos terminem
        create_process.join()
        delete_process.join()
        
    except Exception as e:
        print(f"Erro durante a execução: {e}")
