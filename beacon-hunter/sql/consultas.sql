-- =====================================================================
--  Consultas - banco beacon_hunter (dados gravados pelo detector.py)
--  Atividade Extra - Pós-exploração em Sistemas - Laura Mendes Teixeira
-- =====================================================================
USE beacon_hunter;

-- 1) COUNT + GROUP BY + ORDER BY
--    Quantas conexões cada fluxo recebeu (do mais acessado para o menos)
SELECT f.origem, f.destino, f.porta_destino, f.status,
       COUNT(c.id) AS total_conexoes
FROM fluxos f
JOIN conexoes c ON c.fluxo_id = f.id
GROUP BY f.id, f.origem, f.destino, f.porta_destino, f.status
ORDER BY total_conexoes DESC;

-- 2) WHERE
--    Fluxos classificados como SUSPEITOS (possíveis backdoors)
SELECT origem, destino, porta_destino, total_conexoes,
       intervalo_medio_s, variacao_pct, score, criptografia
FROM fluxos
WHERE status = 'SUSPEITO';

-- 3) MIN + MAX + COUNT + WHERE
--    Primeira e última conexão do beacon na porta 9000 e quantas ocorreram
SELECT MIN(c.data_hora) AS primeira_conexao,
       MAX(c.data_hora) AS ultima_conexao,
       COUNT(*)         AS conexoes,
       TIMESTAMPDIFF(SECOND, MIN(c.data_hora), MAX(c.data_hora)) AS duracao_s
FROM conexoes c
JOIN fluxos f ON f.id = c.fluxo_id
WHERE f.porta_destino = 9000;

-- 4) MIN + MAX + AVG + WHERE
--    Regularidade do beacon: menor, maior e média do intervalo entre conexões
SELECT MIN(c.intervalo_s) AS menor_intervalo_s,
       MAX(c.intervalo_s) AS maior_intervalo_s,
       ROUND(AVG(c.intervalo_s), 3) AS media_intervalo_s,
       ROUND(MAX(c.intervalo_s) - MIN(c.intervalo_s), 3) AS diferenca_s
FROM conexoes c
JOIN fluxos f ON f.id = c.fluxo_id
WHERE f.porta_destino = 9000 AND c.intervalo_s IS NOT NULL;

-- 5) SUM + COUNT + GROUP BY + ORDER BY
--    Volume de dados trocados por fluxo
SELECT f.destino, f.porta_destino,
       COUNT(d.id)  AS mensagens,
       SUM(d.bytes) AS total_bytes
FROM dados_trocados d
JOIN fluxos f ON f.id = d.fluxo_id
GROUP BY f.id, f.destino, f.porta_destino
ORDER BY total_bytes DESC;

-- 6) WHERE + LIKE + ORDER BY
--    Mensagens que vazaram usuário e nome da máquina em texto puro
SELECT d.data_hora, f.destino, f.porta_destino, d.bytes, d.conteudo
FROM dados_trocados d
JOIN fluxos f ON f.id = d.fluxo_id
WHERE d.criptografado = FALSE
  AND d.conteudo LIKE '%Usuario=%'
ORDER BY d.data_hora;

-- 7) COUNT + SUM + GROUP BY
--    Quanto do tráfego registrado estava em texto puro x cifrado
SELECT CASE WHEN criptografado THEN 'cifrado/binário' ELSE 'texto puro' END AS tipo,
       COUNT(*)   AS mensagens,
       SUM(bytes) AS total_bytes
FROM dados_trocados
GROUP BY criptografado;

-- 8) SUBQUERY (escalar) + MAX
--    Fluxo com o maior score de risco registrado
SELECT origem, destino, porta_destino, score, status
FROM fluxos
WHERE score = (SELECT MAX(score) FROM fluxos);

-- 9) SUBQUERY (IN) + ORDER BY
--    Todo o conteúdo trocado pelos fluxos que geraram alerta
SELECT d.data_hora, d.sentido, d.bytes, d.conteudo
FROM dados_trocados d
WHERE d.fluxo_id IN (SELECT fluxo_id FROM alertas)
ORDER BY d.data_hora;

-- 10) SUBQUERY (correlacionada) + WHERE
--     Conexões do beacon que demoraram mais que a média do próprio fluxo
SELECT c.data_hora, c.porta_origem, c.intervalo_s
FROM conexoes c
WHERE c.intervalo_s > (SELECT AVG(c2.intervalo_s)
                       FROM conexoes c2
                       WHERE c2.fluxo_id = c.fluxo_id)
  AND c.fluxo_id IN (SELECT id FROM fluxos WHERE status = 'SUSPEITO')
ORDER BY c.data_hora;

-- 11) COUNT + GROUP BY + HAVING + SUBQUERY
--     Destinos que receberam mais conexões que a média de todos os fluxos
SELECT f.destino, f.porta_destino, COUNT(c.id) AS conexoes
FROM fluxos f
JOIN conexoes c ON c.fluxo_id = f.id
GROUP BY f.id, f.destino, f.porta_destino
HAVING COUNT(c.id) > (SELECT AVG(total_conexoes) FROM fluxos)
ORDER BY conexoes DESC;

-- 12) COUNT + GROUP BY + ORDER BY
--     Conexões por minuto (mostra o ritmo constante do beacon: 2 por minuto)
SELECT DATE_FORMAT(c.data_hora, '%H:%i') AS minuto,
       COUNT(*) AS conexoes
FROM conexoes c
JOIN fluxos f ON f.id = c.fluxo_id
WHERE f.porta_destino = 9000
GROUP BY minuto
ORDER BY minuto;

-- 13) MIN + MAX + COUNT + GROUP BY
--     Tamanho das mensagens por sentido (ida = vítima -> servidor)
SELECT sentido,
       COUNT(*)   AS mensagens,
       MIN(bytes) AS menor_bytes,
       MAX(bytes) AS maior_bytes,
       SUM(bytes) AS total_bytes
FROM dados_trocados
GROUP BY sentido;

-- 14) JOIN + ORDER BY
--     Histórico de alertas gerados pelo detector
SELECT a.data_hora, f.origem, f.destino, f.porta_destino,
       a.intervalo_medio_s, a.score, a.mensagem
FROM alertas a
JOIN fluxos f ON f.id = a.fluxo_id
ORDER BY a.score DESC, a.data_hora;
