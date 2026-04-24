#!/bin/bash
mkdir -p /data/grcx-audit
ln -sfn /data/grcx-audit /app/grcx-audit

(while true; do
    grcx watch --poll 900 >> /data/grcx-audit/watch.log 2>&1
    echo "[$(date -u)] grcx watch exited ($?), restarting in 60s" >> /data/grcx-audit/watch.log
    sleep 60
done) &

python -m flask --app dashboard.app run --host 0.0.0.0 --port 5001
