#!/bin/bash
# Start the sentinel watcher in the background
grcx watch --poll 900 &

# Start Flask in the foreground
python -m flask --app dashboard.app run --host 0.0.0.0 --port 5001
