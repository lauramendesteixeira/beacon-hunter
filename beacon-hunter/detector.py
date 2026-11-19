#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detector.py - BEACON HUNTER
Detector de conexoes periodicas (beaconing) - Pos-exploracao em sistemas
Autora: Laura Mendes Teixeira

Como funciona
-------------
Captura os pacotes TCP da maquina e registra cada NOVA conexao (pacote SYN).
As conexoes sao agrupadas por (IP de origem, IP de destino, porta de destino),
ja que a porta de origem muda a cada conexao. Quando um mesmo destino recebe
conexoes em intervalos quase iguais (ex.: a cada 30 s), o fluxo e marcado como
SUSPEITO - esse e o comportamento de um backdoor "ligando para casa".
Os dados trocados nas conexoes suspeitas sao listados no terminal, gravados em
deteccoes.csv e exibidos no painel visual (painel.html, em http://127.0.0.1:8765).

Uso
---
  python detector.py                          captura ao vivo (scapy + Npcap)
  python detector.py --pcap 18-11.pcapng      analisa uma captura do Wireshark
  python detector.py --demo                   trafego simulado (teste do painel)

Opcoes uteis
  --iface NOME         interface de captura (padrao: loopback + interface principal)
  --listar-interfaces  mostra as interfaces disponiveis e sai
  --min-conexoes N     conexoes minimas para avaliar o padrao (padrao 4)
  --tolerancia X       variacao maxima do intervalo, 0.15 = 15% (padrao 0.15)
  --intervalo-min S    ignora repeticoes mais rapidas que S segundos (padrao 5)
  --porta-web N        porta do painel (padrao 8765)
  --sem-painel         nao abre o painel visual
  -v                   mostra todas as conexoes, nao so as suspeitas
  --mysql              grava fluxos, conexoes, dados e alertas no MySQL (banco beacon_hunter)
                       a senha e pedida ao iniciar (ou variavel de ambiente MYSQL_SENHA)

Requisitos (captura ao vivo): pip install scapy  +  Npcap (vem com o Wireshark).
Requisito (--mysql): pip install mysql-connector-python
"""

import argparse
import csv
import getpass
import queue
import json
import math
import os
import random
import statistics
import struct
import sys
import threading
import time
import webbrowser
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ----------------------------------------------------------------- terminal --
os.system('')  # habilita cores ANSI no terminal do Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

AZ, CI, VD, AM, VM, CZ, NG, RS = ('\033[94m', '\033[96m', '\033[92m', '\033[93m',
                                  '\033[91m', '\033[90m', '\033[1m', '\033[0m')
_print_lock = threading.Lock()


def out(msg=''):
    with _print_lock:
        print(msg, flush=True)


def hora(ts):
    return datetime.fromtimestamp(ts).strftime('%H:%M:%S')


def hora_ms(ts):
    return datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]


# ------------------------------------------------------------------ modelo --
@dataclass
class Pacote:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    flags: int
    payload: bytes


SYN, ACK = 0x02, 0x10


def analisar_conteudo(dados: bytes):
    """Retorna (eh_texto, entropia, texto_exibicao)."""
    if not dados:
        return True, 0.0, ''
    cont = [0] * 256
    for b in dados:
        cont[b] += 1
    n = len(dados)
    entropia = -sum(c / n * math.log2(c / n) for c in cont if c)
    imprimiveis = sum(1 for b in dados if 32 <= b < 127 or b in (9, 10, 13))
    eh_texto = imprimiveis / n >= 0.9
    if eh_texto:
        texto = dados.decode('utf-8', 'replace').replace('\r', ' ').replace('\n', ' ').strip()
    else:
        texto = dados[:48].hex(' ') + (' ...' if n > 48 else '')
    return eh_texto, entropia, texto


class Fluxo:
    def __init__(self, src, dst, dport):
        self.id = f'{src}>{dst}:{dport}'
        self.src, self.dst, self.dport = src, dst, dport
        self.inicios = []            # horario de cada nova conexao (SYN)
        self.portas = []             # porta de origem de cada conexao
        self.dados = []              # (ts, sentido, bytes, eh_texto, entropia, texto)
        self.bytes = 0
        self.pacotes = 0
        self.status = 'OBSERVANDO'
        self.score = 0
        self.motivos = []
        self.alertado = False
        self.db_id = None

    def intervalos(self):
        ult = self.inicios[-21:]
        return [b - a for a, b in zip(ult, ult[1:])]

    def estatisticas(self):
        iv = self.intervalos()
        if not iv:
            return None, None, None
        media = statistics.fmean(iv)
        desvio = statistics.pstdev(iv) if len(iv) > 1 else 0.0
        cv = desvio / media if media > 0 else 1.0
        return media, desvio, cv

    def criptografia(self):
        if not self.dados:
            return '—'
        binarios = [d for d in self.dados if not d[3]]
        if not binarios:
            return 'NÃO (texto puro)'
        # entropia normalizada: perto do maximo possivel => dados embaralhados (cifrados)
        cifrados = [d for d in binarios if d[2] >= 16 and d[4] / min(8, math.log2(d[2])) > 0.85]
        if cifrados:
            return f'PROVÁVEL (entropia {statistics.fmean(d[4] for d in cifrados):.1f})'
        return 'INDEFINIDO (binário)'


# ------------------------------------------------------------------ mysql --
SQL_TABELAS = [
    """CREATE TABLE IF NOT EXISTS fluxos (
        id INT AUTO_INCREMENT PRIMARY KEY,
        origem VARCHAR(45) NOT NULL,
        destino VARCHAR(45) NOT NULL,
        porta_destino INT NOT NULL,
        primeira_conexao DATETIME(3),
        ultima_conexao DATETIME(3),
        total_conexoes INT DEFAULT 0,
        intervalo_medio_s DECIMAL(10,3),
        variacao_pct DECIMAL(8,3),
        score INT DEFAULT 0,
        status ENUM('OBSERVANDO','SUSPEITO') DEFAULT 'OBSERVANDO',
        criptografia VARCHAR(40),
        UNIQUE KEY uk_fluxo (origem, destino, porta_destino))""",
    """CREATE TABLE IF NOT EXISTS conexoes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fluxo_id INT NOT NULL,
        data_hora DATETIME(3) NOT NULL,
        porta_origem INT NOT NULL,
        intervalo_s DECIMAL(10,3) NULL,
        FOREIGN KEY (fluxo_id) REFERENCES fluxos(id))""",
    """CREATE TABLE IF NOT EXISTS dados_trocados (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fluxo_id INT NOT NULL,
        data_hora DATETIME(3) NOT NULL,
        sentido ENUM('ida','volta'),
        bytes INT,
        criptografado BOOLEAN,
        entropia DECIMAL(5,2),
        conteudo TEXT,
        FOREIGN KEY (fluxo_id) REFERENCES fluxos(id))""",
    """CREATE TABLE IF NOT EXISTS alertas (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fluxo_id INT NOT NULL,
        data_hora DATETIME(3) NOT NULL,
        intervalo_medio_s DECIMAL(10,3),
        score INT,
        mensagem VARCHAR(255),
        FOREIGN KEY (fluxo_id) REFERENCES fluxos(id))""",
]


def dt(ts):
    return datetime.fromtimestamp(ts)


class BancoMySQL:
    """Grava as informacoes coletadas no MySQL. As gravacoes vao para uma fila e
    sao feitas por uma thread separada, para nao atrasar a captura de pacotes."""

    def __init__(self, host, porta, usuario, senha, banco):
        import mysql.connector
        self.con = mysql.connector.connect(host=host, port=porta, user=usuario, password=senha,
                                           autocommit=True, charset='utf8mb4')
        cur = self.con.cursor()
        cur.execute(f'CREATE DATABASE IF NOT EXISTS `{banco}` CHARACTER SET utf8mb4 '
                    f'COLLATE utf8mb4_unicode_ci')
        cur.execute(f'USE `{banco}`')
        for sql in SQL_TABELAS:
            cur.execute(sql)
        cur.close()
        self.fila = queue.Queue()
        self.gravados = {'fluxos': 0, 'conexoes': 0, 'dados_trocados': 0, 'alertas': 0}
        self.erros = 0
        threading.Thread(target=self._trabalhar, daemon=True).start()

    # chamadas pelo detector (so enfileiram)
    def fluxo(self, f):
        media, desvio, cv = f.estatisticas()
        self.fila.put(('fluxo', f, (f.src, f.dst, f.dport, dt(f.inicios[0]), dt(f.inicios[-1]),
                                    len(f.inicios), media, None if cv is None else cv * 100,
                                    f.score, f.status, f.criptografia()[:40])))

    def conexao(self, f, ts, porta, intervalo):
        self.fila.put(('conexao', f, (dt(ts), porta, intervalo)))

    def dados(self, f, item):
        ts, sentido, nbytes, eh_texto, ent, texto = item
        self.fila.put(('dados', f, (dt(ts), sentido, nbytes, not eh_texto, round(ent, 2), texto)))

    def alerta(self, f, msg):
        media = f.estatisticas()[0]
        self.fila.put(('alerta', f, (dt(f.inicios[-1]), media, f.score, msg[:255])))

    def aguardar(self):
        self.fila.join()

    # thread de gravacao
    def _trabalhar(self):
        cur = self.con.cursor()
        while True:
            tipo, f, v = self.fila.get()
            try:
                if tipo == 'fluxo':
                    cur.execute(
                        'INSERT INTO fluxos (origem, destino, porta_destino, primeira_conexao, '
                        'ultima_conexao, total_conexoes, intervalo_medio_s, variacao_pct, score, '
                        'status, criptografia) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) '
                        'ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), '
                        'ultima_conexao = VALUES(ultima_conexao), '
                        'total_conexoes = VALUES(total_conexoes), '
                        'intervalo_medio_s = VALUES(intervalo_medio_s), '
                        'variacao_pct = VALUES(variacao_pct), score = VALUES(score), '
                        'status = VALUES(status), criptografia = VALUES(criptografia)', v)
                    if f.db_id is None:
                        self.gravados['fluxos'] += 1
                    f.db_id = cur.lastrowid
                elif tipo == 'conexao':
                    cur.execute('INSERT INTO conexoes (fluxo_id, data_hora, porta_origem, intervalo_s) '
                                'VALUES (%s,%s,%s,%s)', (f.db_id,) + v)
                    self.gravados['conexoes'] += 1
                elif tipo == 'dados':
                    cur.execute('INSERT INTO dados_trocados (fluxo_id, data_hora, sentido, bytes, '
                                'criptografado, entropia, conteudo) VALUES (%s,%s,%s,%s,%s,%s,%s)',
                                (f.db_id,) + v)
                    self.gravados['dados_trocados'] += 1
                elif tipo == 'alerta':
                    cur.execute('INSERT INTO alertas (fluxo_id, data_hora, intervalo_medio_s, score, '
                                'mensagem) VALUES (%s,%s,%s,%s,%s)', (f.db_id,) + v)
                    self.gravados['alertas'] += 1
            except Exception as e:
                self.erros += 1
                if self.erros <= 5:
                    out(f'{VM}[MySQL] erro ao gravar {tipo}: {e}{RS}')
            finally:
                self.fila.task_done()


class Detector:
    PORTAS_COMUNS = {20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 8080, 8443}
    MARCAS_SENSIVEIS = ('host=', 'usuario=', 'user', 'pass', 'senha', 'sistema=', 'token', 'whoami')

    def __init__(self, args, modo, interfaces=''):
        self.args = args
        self.modo = modo
        self.interfaces = interfaces
        self.lock = threading.RLock()
        self.fluxos = {}
        self.conexoes = {}           # (src, sport, dst, dport) -> Fluxo
        self.eventos = deque(maxlen=600)
        self.alertas = deque(maxlen=50)
        self.ev_id = 0
        self.total_pacotes = 0
        self.total_bytes = 0
        self.total_conexoes = 0
        self.inicio = time.time()
        self.ultimo_ts = None
        self.csv_path = args.csv
        self._csv_cabecalho()
        self.banco = None

    # relogio: no modo pcap usa o horario dos pacotes; senao, o relogio real
    def agora(self):
        if self.modo == 'PCAP' and self.ultimo_ts:
            return self.ultimo_ts
        return time.time()

    # ------------------------------------------------------------ pacotes --
    def processar(self, p: Pacote):
        if p.sport in self.args.ignorar or p.dport in self.args.ignorar:
            return
        with self.lock:
            self.total_pacotes += 1
            self.total_bytes += len(p.payload)
            self.ultimo_ts = p.ts if self.ultimo_ts is None else max(self.ultimo_ts, p.ts)
            if self.modo == 'PCAP' and len(self.eventos) == 0 and self.total_pacotes == 1:
                self.inicio = p.ts

            if p.flags & SYN and not p.flags & ACK:
                self._nova_conexao(p)
                return

            fluxo, sentido = self.conexoes.get((p.src, p.sport, p.dst, p.dport)), 'ida'
            if fluxo is None:
                fluxo, sentido = self.conexoes.get((p.dst, p.dport, p.src, p.sport)), 'volta'
            if fluxo is None:
                return
            fluxo.pacotes += 1
            if p.payload:
                self._dados(fluxo, p, sentido)

    def _nova_conexao(self, p):
        chave = (p.src, p.dst, p.dport)
        fluxo = self.fluxos.get(chave)
        if fluxo is None:
            fluxo = self.fluxos[chave] = Fluxo(*chave)
        if fluxo.portas and fluxo.portas[-1] == p.sport and abs(fluxo.inicios[-1] - p.ts) < 15:
            return  # retransmissao do mesmo SYN (mesma porta de origem)
        self.conexoes[(p.src, p.sport, p.dst, p.dport)] = fluxo
        fluxo.inicios.append(p.ts)
        fluxo.portas.append(p.sport)
        fluxo.pacotes += 1
        self.total_conexoes += 1
        self._evento(fluxo, p.ts, 'conexao', 0, f'{p.src}:{p.sport} → {p.dst}:{p.dport}')
        self._avaliar(fluxo, p)
        if self.banco:
            iv = fluxo.inicios[-1] - fluxo.inicios[-2] if len(fluxo.inicios) > 1 else None
            self.banco.fluxo(fluxo)
            self.banco.conexao(fluxo, p.ts, p.sport, iv)

    def _dados(self, fluxo, p, sentido):
        eh_texto, ent, texto = analisar_conteudo(p.payload)
        item = (p.ts, sentido, len(p.payload), eh_texto, ent, texto)
        fluxo.dados.append(item)
        if len(fluxo.dados) > 200:
            del fluxo.dados[:50]
        fluxo.bytes += len(p.payload)
        self._evento(fluxo, p.ts, 'dados', len(p.payload), texto, sentido, eh_texto, ent, p.sport)
        if self.banco:
            self.banco.dados(fluxo, item)
        if fluxo.status == 'SUSPEITO':
            self._imprimir_dado(fluxo, item, p.sport if sentido == 'ida' else p.dport)
            self._csv([item], fluxo)
            self._recalcular_score(fluxo)
            if self.banco:
                self.banco.fluxo(fluxo)

    def _evento(self, fluxo, ts, tipo, nbytes, texto, sentido='ida', eh_texto=True, ent=0.0, porta=0):
        self.ev_id += 1
        self.eventos.append({'id': self.ev_id, 'ts': ts, 'fluxo': fluxo, 'tipo': tipo,
                             'bytes': nbytes, 'texto': texto[:400], 'sentido': sentido,
                             'cifrado': not eh_texto, 'entropia': round(ent, 2), 'porta': porta})

    # ----------------------------------------------------------- deteccao --
    def _recalcular_score(self, f):
        media, desvio, cv = f.estatisticas()
        motivos, score = [], 0
        n = len(f.inicios)
        periodico = (media is not None and n >= self.args.min_conexoes and
                     self.args.intervalo_min <= media <= self.args.intervalo_max and
                     cv <= self.args.tolerancia)
        if periodico:
            score = 55
            motivos.append(f'{n} conexões a cada ~{media:.1f}s')
            score += round(15 * (1 - cv / self.args.tolerancia))
            motivos.append(f'variação de apenas {cv * 100:.2f}%')
            score += min(15, (n - self.args.min_conexoes + 1) * 3)
        elif media is not None:
            score = max(0, round(30 * (1 - min(cv, 1))) * (n >= 3))
        if f.dport not in self.PORTAS_COMUNS:
            score += 5
            motivos.append(f'porta incomum ({f.dport})')
        texto = ' '.join(d[5].lower() for d in f.dados[-10:] if d[3])
        if any(m in texto for m in self.MARCAS_SENSIVEIS):
            score += 10
            motivos.append('dados do sistema em texto puro')
        f.score = min(100, score)
        f.motivos = motivos
        return periodico

    def _avaliar(self, f, p):
        periodico = self._recalcular_score(f)
        if periodico and not f.alertado:
            f.status, f.alertado = 'SUSPEITO', True
            self._alerta(f)
        elif f.status == 'SUSPEITO' and not periodico:
            f.status, f.alertado = 'OBSERVANDO', False
            if self.banco:
                self.banco.fluxo(f)
            m, _, cv = f.estatisticas()
            out(f'{CZ}[{hora(p.ts)}] padrão desfeito em {f.dst}:{f.dport} (variação {cv * 100:.0f}%) '
                f'— volta para observação{RS}')
        elif f.status == 'SUSPEITO':
            iv = f.inicios[-1] - f.inicios[-2]
            out(f'{CZ}[{hora(p.ts)}]{RS} {VM}{NG}BEACON  {RS} #{len(f.inicios):<3} '
                f'{f.src}:{p.sport} → {f.dst}:{f.dport}  {AM}+{iv:.3f}s{RS}')
        elif self.args.verbose:
            out(f'{CZ}[{hora(p.ts)}] conexão  {f.src}:{p.sport} → {f.dst}:{f.dport} '
                f'(#{len(f.inicios)}){RS}')

    def _alerta(self, f):
        media, desvio, cv = f.estatisticas()
        msg = f'Conexão periódica: {f.src} → {f.dst}:{f.dport} a cada {media:.2f}s'
        self.alertas.append({'ts': f.inicios[-1], 'fluxo': f.id, 'msg': msg, 'score': f.score})
        if self.banco:
            self.banco.fluxo(f)
            self.banco.alerta(f, msg)
        linha = '═' * 74
        out()
        out(f'{VM}{NG}{linha}{RS}')
        out(f'{VM}{NG}  ⚠  ALERTA — CONEXÃO PERIÓDICA DETECTADA (possível backdoor / beacon){RS}')
        out(f'{VM}{NG}{linha}{RS}')
        out(f'   Origem ............ {NG}{f.src}{RS}  (portas efêmeras: '
            f'{", ".join(map(str, f.portas[-5:]))}...)')
        out(f'   Destino ........... {NG}{f.dst}:{f.dport}{RS}')
        out(f'   Conexões .......... {len(f.inicios)}')
        out(f'   Intervalo médio ... {AM}{NG}{media:.3f} s{RS}   (desvio {desvio * 1000:.1f} ms, '
            f'variação {cv * 100:.3f}%)')
        out(f'   Criptografia ...... {f.criptografia()}')
        out(f'   Score de risco .... {VM}{NG}{f.score}/100{RS}  ({"; ".join(f.motivos)})')
        out(f'   {CI}Histórico de conexões e dados trocados:{RS}')
        anterior = None
        for i, (ini, porta) in enumerate(zip(f.inicios, f.portas), 1):
            delta = '' if anterior is None else f'  +{ini - anterior:.3f}s'
            anterior = ini
            out(f'     {CZ}#{i:<3}{RS} {hora_ms(ini)}  {f.src}:{porta} → {f.dst}:{f.dport}{AM}{delta}{RS}')
            for d in f.dados:
                if ini <= d[0] < ini + 5 and (i == len(f.inicios) or d[0] < f.inicios[i]):
                    self._imprimir_dado(f, d, porta, recuo=10, com_hora=False)
        out()
        self._csv(f.dados, f)

    def _imprimir_dado(self, f, d, porta, recuo=2, com_hora=True):
        ts, sentido, nbytes, eh_texto, ent, texto = d
        seta = '→' if sentido == 'ida' else '←'
        tag = f'{VD}texto puro{RS}' if eh_texto else f'{AM}cifrado? H={ent:.1f}{RS}'
        pre = f'{CZ}[{hora(ts)}]{RS} {CI}DADOS{RS}   ' if com_hora else ' ' * recuo
        out(f'{pre}{seta} {nbytes} B [{tag}] {NG}{texto}{RS}')

    # ---------------------------------------------------------------- csv --
    def _csv_cabecalho(self):
        if not self.csv_path:
            return
        novo = not os.path.exists(self.csv_path)
        with open(self.csv_path, 'a', newline='', encoding='utf-8') as fh:
            if novo:
                csv.writer(fh, delimiter=';').writerow(
                    ['data_hora', 'origem', 'destino', 'porta_destino', 'sentido', 'bytes',
                     'criptografado', 'entropia', 'intervalo_medio_s', 'score', 'conteudo'])

    def _csv(self, itens, f):
        if not self.csv_path or not itens:
            return
        media = f.estatisticas()[0] or 0
        with open(self.csv_path, 'a', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh, delimiter=';')
            for ts, sentido, nbytes, eh_texto, ent, texto in itens:
                w.writerow([datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                            f.src, f.dst, f.dport, sentido, nbytes, 'nao' if eh_texto else 'sim',
                            f'{ent:.2f}', f'{media:.3f}', f.score, texto])

    # ---------------------------------------------------------- snapshot --
    def snapshot(self):
        with self.lock:
            agora = self.agora()
            fl = []
            for f in self.fluxos.values():
                media, desvio, cv = f.estatisticas()
                fl.append({'id': f.id, 'src': f.src, 'dst': f.dst, 'dport': f.dport,
                           'n': len(f.inicios), 'media': media, 'desvio': desvio, 'cv': cv,
                           'score': f.score, 'status': f.status, 'ultimo': f.inicios[-1],
                           'bytes': f.bytes, 'cripto': f.criptografia(), 'motivos': f.motivos,
                           'inicios': f.inicios[-80:]})
            fl.sort(key=lambda x: (x['status'] != 'SUSPEITO', -x['score'], -x['n'], -x['ultimo']))
            evs = [{'id': e['id'], 'ts': e['ts'], 'fluxo': e['fluxo'].id, 'tipo': e['tipo'],
                    'bytes': e['bytes'], 'texto': e['texto'], 'sentido': e['sentido'],
                    'cifrado': e['cifrado'], 'entropia': e['entropia'], 'porta': e['porta'],
                    'suspeito': e['fluxo'].status == 'SUSPEITO'} for e in list(self.eventos)[-300:]]
            return {'agora': agora, 'inicio': self.inicio, 'modo': self.modo,
                    'interfaces': self.interfaces,
                    'criterio': {'min': self.args.min_conexoes, 'tol': self.args.tolerancia},
                    'stats': {'pacotes': self.total_pacotes, 'bytes': self.total_bytes,
                              'conexoes': self.total_conexoes, 'fluxos': len(self.fluxos),
                              'suspeitos': sum(1 for f in self.fluxos.values()
                                               if f.status == 'SUSPEITO')},
                    'fluxos': fl[:40], 'eventos': evs, 'alertas': list(self.alertas)[-10:]}

    def resumo(self):
        sus = [f for f in self.fluxos.values() if f.status == 'SUSPEITO']
        out(f'{AZ}{NG}── Resumo ─────────────────────────────────────────────────────────{RS}')
        out(f'   Pacotes analisados: {self.total_pacotes}   Conexões TCP: {self.total_conexoes}   '
            f'Fluxos: {len(self.fluxos)}   {VM if sus else VD}Suspeitos: {len(sus)}{RS}')
        for f in sus:
            m, d, cv = f.estatisticas()
            out(f'   {VM}●{RS} {f.src} → {f.dst}:{f.dport}  {len(f.inicios)} conexões, '
                f'{m:.3f}s ±{d * 1000:.1f}ms, score {f.score}, criptografia: {f.criptografia()}')
        if self.banco:
            self.banco.aguardar()
            g = self.banco.gravados
            out(f'   MySQL: {g["fluxos"]} fluxos novos, {g["conexoes"]} conexões, '
                f'{g["dados_trocados"]} dados trocados e {g["alertas"]} alertas gravados'
                + (f'  ({VM}{self.banco.erros} erros{RS})' if self.banco.erros else ''))


# --------------------------------------------------------------- captura --
def captura_ao_vivo(det, args):
    try:
        from scapy.all import sniff, conf, IP, IPv6, TCP
    except Exception:
        out(f'{VM}Scapy não encontrado.{RS} Instale com:  python -m pip install scapy')
        out('Para testar sem captura:  python detector.py --demo   ou   --pcap arquivo.pcapng')
        os._exit(1)

    if args.iface:
        ifaces = args.iface
    else:
        ifaces = []
        lb = getattr(conf, 'loopback_name', None)
        for i in (lb, conf.iface):
            nome = getattr(i, 'network_name', i)
            if nome and nome not in ifaces:
                ifaces.append(nome)
    det.interfaces = ', '.join(map(str, ifaces))

    def cb(pkt):
        if TCP not in pkt:
            return
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            return
        t = pkt[TCP]
        det.processar(Pacote(float(pkt.time), ip.src, int(t.sport), ip.dst, int(t.dport),
                             int(t.flags), bytes(t.payload)))

    try:
        sniff(iface=ifaces if len(ifaces) > 1 else ifaces[0], filter='tcp', prn=cb, store=False)
    except Exception as e:
        out(f'{VM}Falha ao iniciar a captura:{RS} {e}')
        out('Dicas: abra o terminal como Administrador; confira se o Npcap está instalado;')
        out('       veja as interfaces com --listar-interfaces e escolha com --iface.')
        os._exit(1)


def ler_pcap(caminho):
    """Leitor de .pcap/.pcapng sem dependencias (Ethernet, Loopback/NULL e IP cru)."""
    dados = open(caminho, 'rb').read()
    pacotes = []
    magic = dados[:4]
    if magic == b'\x0a\x0d\x0d\x0a':
        off, end, ifaces = 0, '<', []
        while off + 12 <= len(dados):
            tipo = struct.unpack_from(end + 'I', dados, off)[0]
            if tipo == 0x0A0D0D0A:
                end = '<' if dados[off + 8:off + 12] == b'\x4d\x3c\x2b\x1a' else '>'
                ifaces = []
            tam = struct.unpack_from(end + 'I', dados, off + 4)[0]
            if tam < 12:
                break
            corpo = dados[off + 8:off + tam - 4]
            if tipo == 1:
                link = struct.unpack_from(end + 'H', corpo, 0)[0]
                res, o = 6, 8
                while o + 4 <= len(corpo):
                    cod, ln = struct.unpack_from(end + 'HH', corpo, o)
                    if cod == 0:
                        break
                    if cod == 9:
                        res = corpo[o + 4]
                    o += 4 + ((ln + 3) & ~3)
                ifaces.append((link, res))
            elif tipo == 6:
                iid, th, tl, cap = struct.unpack_from(end + 'IIII', corpo, 0)
                link, res = ifaces[iid]
                bruto = (th << 32) | tl
                ts = bruto / (10 ** res) if res < 128 else bruto / (2 ** (res & 0x7F))
                pacotes.append((ts, link, corpo[20:20 + cap]))
            off += tam
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        end = '<' if magic[0] in (0xD4, 0x4D) else '>'
        nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
        link = struct.unpack_from(end + 'I', dados, 20)[0]
        off = 24
        while off + 16 <= len(dados):
            s, us, cap, _ = struct.unpack_from(end + 'IIII', dados, off)
            pacotes.append((s + us / (1e9 if nano else 1e6), link, dados[off + 16:off + 16 + cap]))
            off += 16 + cap
    else:
        raise ValueError('formato de captura não reconhecido')

    resultado = []
    for ts, link, raw in pacotes:
        p = decodificar(link, raw, ts)
        if p:
            resultado.append(p)
    return resultado


def decodificar(link, raw, ts):
    try:
        if link == 0:
            fam = struct.unpack_from('<I', raw, 0)[0]
            ip, ver = raw[4:], (4 if fam == 2 else 6)
        elif link == 1:
            et, ip = struct.unpack_from('>H', raw, 12)[0], raw[14:]
            if et == 0x8100:
                et, ip = struct.unpack_from('>H', raw, 16)[0], raw[18:]
            ver = {0x0800: 4, 0x86DD: 6}.get(et)
        elif link in (101, 228, 229):
            ip, ver = raw, raw[0] >> 4
        else:
            return None
        if ver == 4:
            ihl, proto = (ip[0] & 0xF) * 4, ip[9]
            src, dst = '.'.join(map(str, ip[12:16])), '.'.join(map(str, ip[16:20]))
            l4 = ip[ihl:struct.unpack_from('>H', ip, 2)[0]]
        elif ver == 6:
            import ipaddress
            proto = ip[6]
            src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
            l4 = ip[40:]
        else:
            return None
        if proto != 6:
            return None
        sp, dp, _, _, off, fl = struct.unpack_from('>HHIIBB', l4, 0)
        return Pacote(ts, src, sp, dst, dp, fl, bytes(l4[(off >> 4) * 4:]))
    except (struct.error, IndexError):
        return None


def reproduzir_pcap(det, args):
    pacotes = ler_pcap(args.pcap)
    out(f'{CZ}{len(pacotes)} pacotes TCP lidos de {args.pcap} — reproduzindo a '
        f'{args.velocidade:g}x{RS}' if args.velocidade else
        f'{CZ}{len(pacotes)} pacotes TCP lidos de {args.pcap}{RS}')
    anterior = None
    for p in pacotes:
        if args.velocidade and anterior is not None:
            time.sleep(min(2.0, max(0.0, (p.ts - anterior) / args.velocidade)))
        anterior = p.ts
        det.processar(p)
    out()
    det.resumo()
    if not args.sem_painel:
        out(f'{CZ}Captura reproduzida. O painel continua aberto — Ctrl+C para sair.{RS}')


def simular(det, args):
    """Gera trafego de exemplo: 2 beacons (um em texto puro e um cifrado) + ruido."""
    local = '192.168.0.10'
    rnd = random.Random(7)
    beacons = [
        {'dst': local, 'dport': 9000, 'periodo': 5.0, 'prox': time.time() + 1, 'cifrado': False},
        {'dst': '10.0.0.77', 'dport': 4444, 'periodo': 8.0, 'prox': time.time() + 3, 'cifrado': True},
    ]
    ruido_prox = time.time()
    while True:
        agora = time.time()
        for b in beacons:
            if agora >= b['prox']:
                sp = rnd.randint(49152, 65535)
                if b['cifrado']:
                    carga = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(60, 140)))
                else:
                    carga = (f'{datetime.now()} | Host=PC-LABORATORIO | Usuario=aluno | '
                             f'Sistema=Windows').encode()
                enviar_conexao(det, agora, local, sp, b['dst'], b['dport'], carga)
                b['prox'] = agora + b['periodo'] + rnd.uniform(-0.004, 0.004)
        if agora >= ruido_prox:
            dst = rnd.choice(['142.250.79.46', '20.190.159.4', '104.18.32.7', '13.107.42.14',
                              '151.101.1.140', '52.96.0.1'])
            enviar_conexao(det, agora, local, rnd.randint(49152, 65535), dst,
                           rnd.choice([443, 443, 443, 80]),
                           bytes(rnd.getrandbits(8) for _ in range(rnd.randint(200, 900))))
            ruido_prox = agora + rnd.expovariate(1 / 2.5)
        time.sleep(0.05)


def enviar_conexao(det, ts, src, sp, dst, dp, carga):
    det.processar(Pacote(ts, src, sp, dst, dp, SYN, b''))
    det.processar(Pacote(ts + 0.0005, dst, dp, src, sp, SYN | ACK, b''))
    det.processar(Pacote(ts + 0.0008, src, sp, dst, dp, ACK, b''))
    det.processar(Pacote(ts + 0.0019, src, sp, dst, dp, ACK | 0x08, carga))
    det.processar(Pacote(ts + 0.0021, dst, dp, src, sp, ACK, b''))


# ---------------------------------------------------------------- painel --
def iniciar_painel(det, porta, abrir):
    caminho = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'painel.html')
    if not os.path.exists(caminho):
        out(f'{AM}painel.html não encontrado ao lado do detector.py — painel desativado.{RS}')
        return None
    with open(caminho, encoding='utf-8') as fh:
        pagina = fh.read().encode('utf-8')

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith('/api/estado'):
                corpo = json.dumps(det.snapshot(), ensure_ascii=False).encode('utf-8')
                tipo = 'application/json; charset=utf-8'
            elif self.path in ('/', '/index.html'):
                corpo, tipo = pagina, 'text/html; charset=utf-8'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', tipo)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(('127.0.0.1', porta), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{porta}'
    if abrir:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    return url


# ------------------------------------------------------------------ main --
def main():
    ap = argparse.ArgumentParser(description='Detector de conexões periódicas (beaconing)')
    ap.add_argument('--pcap', help='analisar um arquivo .pcap/.pcapng em vez de capturar')
    ap.add_argument('--velocidade', type=float, default=10,
                    help='velocidade da reprodução do pcap (0 = instantâneo, padrão 10x)')
    ap.add_argument('--demo', action='store_true', help='tráfego simulado')
    ap.add_argument('--iface', action='append', help='interface de captura (pode repetir)')
    ap.add_argument('--listar-interfaces', action='store_true')
    ap.add_argument('--min-conexoes', type=int, default=4)
    ap.add_argument('--tolerancia', type=float, default=0.15)
    ap.add_argument('--intervalo-min', type=float, default=5.0)
    ap.add_argument('--intervalo-max', type=float, default=3600.0)
    ap.add_argument('--ignorar', type=int, nargs='*', default=[], metavar='PORTA')
    ap.add_argument('--csv', default='deteccoes.csv', help='arquivo de saída ("" desativa)')
    ap.add_argument('--porta-web', type=int, default=8765)
    ap.add_argument('--sem-painel', action='store_true')
    ap.add_argument('--sem-navegador', action='store_true')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--mysql', action='store_true', help='gravar no MySQL')
    ap.add_argument('--mysql-host', default='localhost')
    ap.add_argument('--mysql-porta', type=int, default=3306)
    ap.add_argument('--mysql-usuario', default='root')
    ap.add_argument('--mysql-banco', default='beacon_hunter')
    args = ap.parse_args()
    args.ignorar = set(args.ignorar)

    if args.listar_interfaces:
        from scapy.all import conf
        print(conf.ifaces)
        return

    # o detector nao deve analisar o proprio trafego (painel web e gravacoes no MySQL)
    if not args.sem_painel:
        args.ignorar.add(args.porta_web)
    if args.mysql:
        args.ignorar.add(args.mysql_porta)

    modo = 'PCAP' if args.pcap else 'DEMO' if args.demo else 'AO VIVO'
    det = Detector(args, modo)

    if args.mysql:
        try:
            import mysql.connector  # noqa: F401
        except ImportError:
            out(f'{VM}mysql-connector-python não instalado.{RS} Instale com:  '
                f'python -m pip install mysql-connector-python')
            return
        senha = os.environ.get('MYSQL_SENHA') or getpass.getpass(
            f'Senha do MySQL ({args.mysql_usuario}@{args.mysql_host}): ')
        try:
            det.banco = BancoMySQL(args.mysql_host, args.mysql_porta, args.mysql_usuario, senha,
                                   args.mysql_banco)
        except Exception as e:
            out(f'{VM}Não foi possível conectar ao MySQL:{RS} {e}')
            out('Confira se o serviço MySQL está rodando, o usuário e a senha.')
            return
        del senha

    out(f'{AZ}{NG}╔══════════════════════════════════════════════════════════════════════════╗{RS}')
    out(f'{AZ}{NG}║  BEACON HUNTER  ·  Detector de conexões periódicas                       ║{RS}')
    out(f'{AZ}{NG}╚══════════════════════════════════════════════════════════════════════════╝{RS}')
    out(f' Modo: {NG}{modo}{RS}    Critério: ≥{args.min_conexoes} conexões ao mesmo destino com '
        f'variação ≤{args.tolerancia * 100:.0f}% no intervalo')
    if not args.sem_painel:
        url = iniciar_painel(det, args.porta_web, not args.sem_navegador)
        if url:
            out(f' Painel visual: {CI}{url}{RS}')
    if args.csv:
        out(f' Registro: {os.path.abspath(args.csv)}')
    if det.banco:
        out(f' MySQL: {VD}conectado{RS} — {args.mysql_usuario}@{args.mysql_host}:{args.mysql_porta}'
            f' / banco {args.mysql_banco}')
    out(f'{CZ} Ctrl+C para encerrar.{RS}\n')

    alvo = reproduzir_pcap if args.pcap else simular if args.demo else captura_ao_vivo
    t = threading.Thread(target=alvo, args=(det, args), daemon=True)
    t.start()

    ultimo_status = time.time()
    try:
        while True:
            time.sleep(0.5)
            if modo != 'PCAP' and time.time() - ultimo_status >= 30:
                ultimo_status = time.time()
                with det.lock:
                    s = det.snapshot()['stats']
                out(f'{CZ}[{hora(time.time())}] monitorando… pacotes {s["pacotes"]} · conexões '
                    f'{s["conexoes"]} · fluxos {s["fluxos"]} · suspeitos {s["suspeitos"]}{RS}')
            if args.pcap and args.sem_painel and not t.is_alive():
                break
    except KeyboardInterrupt:
        out()
        det.resumo()


if __name__ == '__main__':
    main()
