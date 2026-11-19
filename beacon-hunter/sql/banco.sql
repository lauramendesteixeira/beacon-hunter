-- =====================================================================
--  Banco de dados do detector de conexões periódicas (beacon_hunter)
--  Atividade Extra - Pós-exploração em Sistemas - Laura Mendes Teixeira
-- =====================================================================
CREATE DATABASE IF NOT EXISTS beacon_hunter
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE beacon_hunter;

-- cada destino monitorado (origem -> destino:porta)
CREATE TABLE IF NOT EXISTS fluxos (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  origem            VARCHAR(45) NOT NULL,
  destino           VARCHAR(45) NOT NULL,
  porta_destino     INT NOT NULL,
  primeira_conexao  DATETIME(3),
  ultima_conexao    DATETIME(3),
  total_conexoes    INT DEFAULT 0,
  intervalo_medio_s DECIMAL(10,3),
  variacao_pct      DECIMAL(8,3),
  score             INT DEFAULT 0,
  status            ENUM('OBSERVANDO','SUSPEITO') DEFAULT 'OBSERVANDO',
  criptografia      VARCHAR(40),
  UNIQUE KEY uk_fluxo (origem, destino, porta_destino)
);

-- cada nova conexão (SYN) feita para um fluxo
CREATE TABLE IF NOT EXISTS conexoes (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  fluxo_id      INT NOT NULL,
  data_hora     DATETIME(3) NOT NULL,
  porta_origem  INT NOT NULL,
  intervalo_s   DECIMAL(10,3) NULL,
  FOREIGN KEY (fluxo_id) REFERENCES fluxos(id)
);

-- conteúdo trocado nas conexões
CREATE TABLE IF NOT EXISTS dados_trocados (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  fluxo_id       INT NOT NULL,
  data_hora      DATETIME(3) NOT NULL,
  sentido        ENUM('ida','volta'),
  bytes          INT,
  criptografado  BOOLEAN,
  entropia       DECIMAL(5,2),
  conteudo       TEXT,
  FOREIGN KEY (fluxo_id) REFERENCES fluxos(id)
);

-- alertas de beacon gerados pelo detector
CREATE TABLE IF NOT EXISTS alertas (
  id                INT AUTO_INCREMENT PRIMARY KEY,
  fluxo_id          INT NOT NULL,
  data_hora         DATETIME(3) NOT NULL,
  intervalo_medio_s DECIMAL(10,3),
  score             INT,
  mensagem          VARCHAR(255),
  FOREIGN KEY (fluxo_id) REFERENCES fluxos(id)
);
