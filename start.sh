#!/bin/bash
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "  ${YELLOW}[..]${NC}   $1"; }
head() { echo -e "\n${CYAN}$1${NC}"; }

BASE=~/thesis-rag
VENV=$BASE/venv

echo ""
echo "============================================"
echo "  RAG Threat Detector — Full Auto Start"
echo "============================================"

# ── 0. RESET simulation state ──────────────────────────────
head "[ 0/7 ] Resetting simulation state"
> $BASE/logs/linux.log
rm -rf $BASE/filebeat/registry
pkill -f llm_watcher 2>/dev/null
ok "Log file cleared, registry reset, old watchers stopped"

# ── 1. KERNEL param ────────────────────────────────────────
head "[ 1/7 ] System"
sudo sysctl -w vm.max_map_count=262144 > /dev/null 2>&1 \
    && ok "vm.max_map_count set" \
    || ok "vm.max_map_count (skipped — no sudo)"

# ── 2. ELASTICSEARCH ───────────────────────────────────────
head "[ 2/7 ] Elasticsearch"
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    ok "Already running"
else
    info "Starting Elasticsearch..."
    $BASE/elasticsearch/bin/elasticsearch \
        -d -p $BASE/elasticsearch/elasticsearch.pid \
        > $BASE/elasticsearch/logs/es-startup.log 2>&1
    for i in {1..20}; do
        curl -s http://localhost:9200 > /dev/null 2>&1 && break
        sleep 2
    done
    curl -s http://localhost:9200 > /dev/null 2>&1 \
        && ok "Elasticsearch :9200" \
        || fail "Elasticsearch failed to start"
fi

# ── 3. KIBANA ──────────────────────────────────────────────
head "[ 3/7 ] Kibana"
if curl -s http://localhost:5601 > /dev/null 2>&1; then
    ok "Already running"
else
    info "Starting Kibana (takes ~30s to be ready)..."
    nohup $BASE/kibana/bin/kibana > $BASE/kibana/logs/kibana.log 2>&1 &
    echo $! > $BASE/kibana/kibana.pid
    ok "Kibana starting on :5601"
fi

# ── 4. LOGSTASH ────────────────────────────────────────────
head "[ 4/7 ] Logstash"
if pgrep -f logstash > /dev/null; then
    info "Logstash running — restarting to pick up fresh config..."
    pkill -f logstash
    sleep 6
fi
info "Starting Logstash (JVM needs ~45s)..."
nohup $BASE/logstash/bin/logstash \
    --path.settings $BASE/logstash/config \
    -f $BASE/logstash/config/conf.d/thesis-pipeline.conf \
    > $BASE/logstash/logs/logstash.log 2>&1 &
echo $! > $BASE/logstash/logstash.pid

for i in {1..30}; do
    sleep 3
    if curl -s http://localhost:9600/_node/pipelines > /dev/null 2>&1; then
        ok "Logstash running :5044"
        break
    fi
    if [ $i -eq 30 ]; then
        fail "Logstash failed — check logstash/logs/logstash.log"
    fi
done

# ── 5. FILEBEAT ────────────────────────────────────────────
head "[ 5/7 ] Filebeat"
pkill -f filebeat 2>/dev/null
sleep 2
nohup $BASE/filebeat/filebeat \
    -c $BASE/filebeat/filebeat.yml \
    --path.home $BASE/filebeat \
    --path.logs $BASE/filebeat/logs \
    > $BASE/filebeat/logs/filebeat-startup.log 2>&1 &
echo $! > $BASE/filebeat/filebeat.pid
sleep 3
pgrep -f filebeat > /dev/null \
    && ok "Filebeat running" \
    || fail "Filebeat failed to start"

# ── 6. OLLAMA ──────────────────────────────────────────────
head "[ 6/7 ] Ollama + Qwen3:14B"
if curl -s http://localhost:11434 > /dev/null 2>&1; then
    ok "Ollama already running"
else
    info "Starting Ollama..."
    nohup ollama serve > $BASE/ollama.log 2>&1 &
    echo $! > $BASE/ollama.pid
    sleep 5
    curl -s http://localhost:11434 > /dev/null 2>&1 \
        && ok "Ollama :11434" \
        || fail "Ollama failed to start"
fi

if ollama list 2>/dev/null | grep -q "qwen3:14b"; then
    ok "qwen3:14b model ready"
else
    fail "qwen3:14b not found — run: ollama pull qwen3:14b"
fi

# ── 7. START LLM WATCHER ───────────────────────────────────
head "[ 7/7 ] LLM Watcher"
sleep 3

source $VENV/bin/activate

info "Starting LLM watcher (RAG + Qwen3:14B + baseline normality)..."
nohup python3 $BASE/llm_watcher.py \
    > $BASE/logs/llm_watcher.log 2>&1 &
echo $! > $BASE/llm_watcher.pid
ok "LLM watcher started (PID: $!)"

# ── DONE ───────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Pipeline is fully running"
echo ""
echo "  Kibana     : http://localhost:5601"
echo "  ES health  : http://localhost:9200/_cat/health"
echo "  Log count  : http://localhost:9200/thesis-simulation-*/_count"
echo ""
echo "  Inject logs: python inject_fresh.py <dataset.csv>"
echo "  Watch LLM  : tail -f $BASE/logs/llm_watcher.log"
echo "  Evaluate   : python evaluate.py <dataset.csv>"
echo ""
echo "  Stop all   : ./stop.sh"
echo "============================================"
echo ""
