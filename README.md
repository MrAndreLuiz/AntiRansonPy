![logo][] AntiRansonPy: Projeto de Sistema de Monitoramento e Prevenção de Ransomware
===============

Conteúdo
* [Introdução][lk-introducao]
* [Funcionalidades][lk-funcionalidades]
* [Instalação e Configuração][lk-instalacao-configuracao]
* [Personalização e Utilização][lk-personalizacao-utilizacao]
* [Futuras Atualizações][lk-atualizacoes]
* [Licença][lk-licen]
* [Problemas e Sugestões][lk-problemas]

[lk-introducao]: #introdução
[lk-funcionalidades]: #funcionalidades
[lk-instalacao-configuracao]: #instalação-e-configuração
[lk-personalizacao-utilizacao]: #personalização-e-utilização
[lk-atualizacoes]: #futuras-atualizações
[lk-licen]: #licença
[lk-problemas]: #problemas-e-sugestões

[logo]: https://github.com/MrAndreLuiz/AntiRansonPy/blob/main/AntiRansonPy.png?raw=true "Logo"

[Introdução][lk-introducao]
----------

O **AntiRansonPy** é uma solução open source projetada em Python para monitorar processos e arquivos, utilizando técnicas avançadas de detecção e prevenção de atividades maliciosas em sistemas operacionais Windows. Desenvolvido com o propósito de proteger dados principalmente contra ações de ransomware, mas também efetivo contra outras ameaças cibernéticas com comportamentos semelhantes, utilizando a combinação de monitoramento de processos, análise comportamental e criptografia AES-256 assegura a integridade e segurança dos dados da solução.

**Por que utilizar o AntiRansonPy ao invés de outras soluções disponíveis?**

**AntiRansonPy** é:

- **Open source**: Você pode ver e controlar o código-fonte que está sendo executado em seu sistema operacional.
- **Otimizado**: A solução não consome muitos recursos do sistema operacional.
- **Efetivo**: É efetivo em detectar o comportamente de vários tipos de ransomwares.
- **Gratuito**: Não há cobranças de licença para uso da solução.

[Funcionalidades][lk-funcionalidades]
----------

- **Monitoramento de Processos**: Monitora todos os processos em execução, analisando seu comportamento e consumo de recursos.
- **Análise de Comportamento**: Detecta padrões suspeitos que podem indicar atividades maliciosas.
- **Criptografia Avançada**: Utiliza criptografia AES-256 para proteger informações críticas.
- **Banco de Dados de Processos Maliciosos**: Armazena informações para identificação e prevenção de futuras ameaças.
- **Log Detalhado**: Registra eventos e análises em um log para rastreamento e solução de problemas.

**`Atenção:` Certifique-se de ler a Seção de [Problemas e Sugestões][lk-problemas] antes de utilizar a solução.**

[Instalação e Configuração][lk-instalacao-configuracao]
----------

### Requisitos

- **Sistema Operacional**: Windows 10 ou superior.
- **Git**: Disponível em [git-scm.com](https://git-scm.com/downloads).
- **Python**: 3.x (Disponível em [python.org](https://www.python.org/downloads/)).
- **Dependências**: psutil, watchdog, cryptography.

### Execute os seguintes comandos no Terminal do Windows:

#### Download do Projeto
```bash
git clone https://github.com/MrAndreLuiz/AntiRansonPy.git
```
#### Instalação de Dependências do Python
```bash
pip install psutil watchdog cryptography
```

#### Execução

```bash
python AntiRansonPy.py
```

#### Execução de Testes

```bash
python Test.py
```
> O código-fonte do arquivo `Test.py` força um comportamento semelhante a um ransomware criando 2.000 pastas, aumentado o uso de CPU e deletando 2.000 pastas. Esse comportamente pode ser utilizado para testar a efetividade da solução **AntiRansonPy** sem ser nocivo ao sistema operacional. **Não é recomendável executar um ransomware real para testar a solução.**


### Download do Executável

Baixe uma versão do **AntiRansonPy** que inclui um arquivo executável `.exe` para facilitar o uso inicial em ambientes Windows sem a necessidade de instalar o Python ou executar comandos no Terminal: 

| Versão                       | Download                 | Data de lançamento |
|------------------------------|--------------------------|--------------------|
| Alfa                         | [v0.0.1-alpha](https://github.com/MrAndreLuiz/AntiRansonPy/releases/tag/v0.0.1-alpha)     | 11/07/2024         |

**Reporte os problemas encontrados durante a execução na Seção de [Problemas e Sugestões][lk-problemas].**

[Personalização e Utilização][lk-personalizacao-utilizacao]
----------

### Arquivo de Configuração

O arquivo `AntiRansonPy.py` permite ajustes como:

- `CPU_THRESHOLD`: Limite de uso de CPU para detecção de processos maliciosos.
- `DISK_THRESHOLD`: Limite de uso de disco para identificação de atividades suspeitas.
- `FILE_MOD_THRESHOLD`: Número máximo de modificações de arquivo consideradas seguras.
- `MONITOR_DURATION`: Duração do monitoramento (em segundos).

### Banco de Dados e Logs de Análise Geral

- **Banco de Dados**: Armazenado em `ia_malicious.bd`.
- **Logs de Análise Geral**: Registrado em `logs.txt`.

[Futuras Atualizações][lk-atualizacoes]
----------

- **Interface Gráfica**: Interface para facilitar a interação e configuração da solução.
- **Integração com Nuvem**: Banco de dados em nuvem para compartilhamento de informações entre clientes.
- **Aprimoramento Criptográfico**: Melhorias na aplicação da chave criptográfica para maior segurança.
- **Heurística Avançada**: Melhoria na detecção de comportamentos maliciosos utlizando Inteligência Artificial.
- **Otimização de Desempenho**: Código otimizado para melhor eficiência e menor taxa de erros.

[Licença][lk-licen]
----------

O **AntiRansonPy** é distribuído sob a licença [MIT](https://opensource.org/licenses/MIT), o que significa que você é livre para usar, modificar e distribuir o código-fonte do projeto, desde que inclua o aviso de direito autoral, um link para o [Projeto no GitHub](https://github.com/MrAndreLuiz/AntiRansonPy) e essa permissão em todas as cópias ou partes substanciais do código-fonte do projeto. A utilização deste pacote de software, de forma completa ou em partes individuais, em trabalhos acadêmicos em âmbito nacional ou internacional deve respeitar a legislação brasileira e a [lei nº 9.610][lk-lei] sobre direitos autorais.

[Problemas e Sugestões][lk-problemas]
----------

Se você encontrar erros, bugs, problemas de segurança ou tiver sugestões para melhorias, por favor, abra uma [Issue](https://github.com/MrAndreLuiz/AntiRansonPy/issues) no GitHub. Faremos o possível para abordar e resolver esses problemas o mais rápido possível.

**`Atenção:` A solução AntiRansonPy ainda está em estágios iniciais de desenvolvimento, portanto pode apresentar problemas diversos, não garantindo ser totalmente efetiva em proteger ambientes de produção ou que tenham dados sensíveis.**
> Este pacote de software é fornecido "como está", sem garania de qualquer tipo, expressa ou implícita, incluindo, sem limitação, as garantias de comercialização e adequação a um determinado fim. Em nenhum caso os autores ou dententores de direitos de autor são responsáveis por qualquer reclamação, danos ou outra responsabilidade, seja em uma ação de contrato, delito ou de outra forma, decorrentes de, ou em conexão com este pacote de software, seu uso, ou outra aplicação do código fonte, imagens, sons e outros aqui distribuídos.

[lk-lei]: http://www.planalto.gov.br/ccivil_03/leis/L9610.htm