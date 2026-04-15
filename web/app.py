from flask import Flask, render_template, jsonify
import csv
import json
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

app = Flask(__name__)


def safe_json(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def read_csv_rows(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


@app.route('/')
def index():
    rules = safe_json(os.path.join(LOG_DIR, 'rules.json'), [])
    stats = safe_json(os.path.join(LOG_DIR, 'flow_stats.json'), [])
    blocked = read_csv_rows(os.path.join(LOG_DIR, 'blocked_packets.log'))
    events = []
    events_path = os.path.join(LOG_DIR, 'events.log')
    if os.path.exists(events_path):
        with open(events_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()[1:] if line.strip()]
            events = list(reversed(lines[-10:]))

    metrics = {
        'rules': len(rules),
        'blocked_packets': len(blocked),
        'active_flows': len(stats),
        'hosts': 4,
    }
    return render_template('index.html', rules=rules, stats=stats[:12], blocked=list(reversed(blocked[-12:])), events=events, metrics=metrics)


@app.route('/api/overview')
def api_overview():
    return jsonify({
        'rules': safe_json(os.path.join(LOG_DIR, 'rules.json'), []),
        'stats': safe_json(os.path.join(LOG_DIR, 'flow_stats.json'), []),
        'blocked': read_csv_rows(os.path.join(LOG_DIR, 'blocked_packets.log')),
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
