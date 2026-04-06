#!/bin/bash
mkdir -p /data/grcx-audit
ln -sfn /data/grcx-audit /app/grcx-audit
grcx watch --poll 900 &
python -m flask --app dashboard.app run --host 0.0.0.0 --port 5001
