"""
HTML report export for IOCSweep analysis results.

Generates beautiful, interactive HTML reports with:
- Executive summary
- Threat indicators
- Network visualization
- Detailed findings
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Template

from iocsweep.models import AnalysisResult, Severity


class HTMLExporter:
    """
    Export analysis results to interactive HTML report.
    """

    TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IOCSweep Analysis Report</title>
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --danger: #f85149;
            --warning: #d29922;
            --success: #3fb950;
            --info: #58a6ff;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #238636 0%, #1f6feb 100%);
            padding: 40px 20px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 8px;
        }
        header h1 { font-size: 2.5em; margin-bottom: 10px; color: white; }
        header p { color: rgba(255,255,255,0.8); font-size: 1.1em; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: var(--accent);
        }
        .stat-card .label { color: var(--text-muted); }
        .stat-card.critical .value { color: var(--danger); }
        .stat-card.warning .value { color: var(--warning); }
        .stat-card.success .value { color: var(--success); }
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .section h2 {
            color: var(--text);
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .section h2 .icon { font-size: 1.2em; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { background: rgba(255,255,255,0.05); color: var(--text-muted); }
        tr:hover { background: rgba(255,255,255,0.03); }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .badge-critical { background: var(--danger); color: white; }
        .badge-high { background: #da3633; color: white; }
        .badge-medium { background: var(--warning); color: black; }
        .badge-low { background: #388bfd; color: white; }
        .badge-info { background: var(--info); color: white; }
        .ioc-value {
            font-family: 'Consolas', 'Monaco', monospace;
            background: rgba(255,255,255,0.1);
            padding: 2px 6px;
            border-radius: 4px;
            word-break: break-all;
        }
        .threat-card {
            background: rgba(248,81,73,0.1);
            border-left: 4px solid var(--danger);
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
        }
        .threat-card.medium {
            background: rgba(210,153,34,0.1);
            border-left-color: var(--warning);
        }
        .threat-card h4 { margin-bottom: 8px; }
        .threat-card .details { color: var(--text-muted); font-size: 0.9em; }
        .mitre-tag {
            display: inline-block;
            background: #1f6feb;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            margin: 2px;
        }
        .progress-bar {
            height: 8px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-bar .fill {
            height: 100%;
            border-radius: 4px;
        }
        .protocol-chart { display: flex; flex-wrap: wrap; gap: 10px; }
        .protocol-item {
            background: rgba(255,255,255,0.05);
            padding: 10px 15px;
            border-radius: 6px;
        }
        .protocol-item .name { color: var(--text-muted); font-size: 0.9em; }
        .protocol-item .count { font-size: 1.2em; font-weight: bold; }
        .footer {
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
            font-size: 0.9em;
        }
        .collapsible { cursor: pointer; user-select: none; }
        .collapsible:after { content: ' [+]'; color: var(--accent); }
        .collapsible.active:after { content: ' [-]'; }
        .content { display: none; padding-top: 15px; }
        .content.show { display: block; }
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr 1fr; }
            header h1 { font-size: 1.8em; }
            table { font-size: 0.8em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>IOCSweep Analysis Report</h1>
            <p>{{ pcap_file }} | {{ analysis_time }}</p>
        </header>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{{ "{:,}".format(total_packets) }}</div>
                <div class="label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="value">{{ format_bytes(total_bytes) }}</div>
                <div class="label">Total Traffic</div>
            </div>
            <div class="stat-card">
                <div class="value">{{ unique_ips }}</div>
                <div class="label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="value">{{ unique_domains }}</div>
                <div class="label">Unique Domains</div>
            </div>
            <div class="stat-card {{ 'critical' if ioc_matches > 0 else 'success' }}">
                <div class="value">{{ ioc_matches }}</div>
                <div class="label">IOC Matches</div>
            </div>
            <div class="stat-card {{ 'warning' if suspicious_count > 0 else 'success' }}">
                <div class="value">{{ suspicious_count }}</div>
                <div class="label">Suspicious Activities</div>
            </div>
            <div class="stat-card {{ 'critical' if beacon_count > 0 else 'success' }}">
                <div class="value">{{ beacon_count }}</div>
                <div class="label">Beacon Patterns</div>
            </div>
            <div class="stat-card">
                <div class="value">{{ extracted_files }}</div>
                <div class="label">Extracted Files</div>
            </div>
        </div>

        <!-- Critical Findings -->
        {% if critical_findings %}
        <div class="section">
            <h2><span class="icon">&#x26A0;</span> Critical Findings</h2>
            {% for finding in critical_findings %}
            <div class="threat-card">
                <h4>
                    <span class="badge badge-{{ finding.severity }}">{{ finding.severity|upper }}</span>
                    {{ finding.type }}
                </h4>
                <p>{{ finding.description }}</p>
                <div class="details">
                    {% if finding.src_ip %}Source: {{ finding.src_ip }}{% endif %}
                    {% if finding.dst_ip %} → Destination: {{ finding.dst_ip }}{% endif %}
                    {% if finding.mitre %}
                    <br>
                    {% for technique in finding.mitre %}
                    <span class="mitre-tag">{{ technique }}</span>
                    {% endfor %}
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- IOC Matches -->
        {% if ioc_match_list %}
        <div class="section">
            <h2><span class="icon">&#x1F6A8;</span> IOC Matches ({{ ioc_match_list|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Severity</th>
                        <th>Found In</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ioc in ioc_match_list %}
                    <tr>
                        <td>{{ ioc.type }}</td>
                        <td><span class="ioc-value">{{ ioc.value }}</span></td>
                        <td><span class="badge badge-{{ ioc.severity }}">{{ ioc.severity|upper }}</span></td>
                        <td>{{ ioc.found_in }}</td>
                        <td>{{ ioc.timestamp }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Beacon Patterns -->
        {% if beacon_list %}
        <div class="section">
            <h2><span class="icon">&#x1F4E1;</span> Potential C2 Beacons ({{ beacon_list|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Destination</th>
                        <th>Port</th>
                        <th>Interval</th>
                        <th>Jitter</th>
                        <th>Connections</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {% for beacon in beacon_list %}
                    <tr>
                        <td><span class="ioc-value">{{ beacon.dst_ip }}</span></td>
                        <td>{{ beacon.dst_port }}</td>
                        <td>{{ beacon.interval }}</td>
                        <td>{{ beacon.jitter }}%</td>
                        <td>{{ beacon.connections }}</td>
                        <td>
                            <div class="progress-bar" style="width: 100px;">
                                <div class="fill" style="width: {{ beacon.confidence }}%; background: {{ '#3fb950' if beacon.confidence >= 80 else '#d29922' if beacon.confidence >= 50 else '#f85149' }};"></div>
                            </div>
                            {{ beacon.confidence }}%
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Suspicious DNS -->
        {% if suspicious_dns %}
        <div class="section">
            <h2 class="collapsible"><span class="icon">&#x1F310;</span> Suspicious DNS Queries ({{ suspicious_dns|length }})</h2>
            <div class="content">
                <table>
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Type</th>
                            <th>Entropy</th>
                            <th>Reasons</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for dns in suspicious_dns %}
                        <tr>
                            <td><span class="ioc-value">{{ dns.query_name }}</span></td>
                            <td>{{ dns.query_type }}</td>
                            <td>{{ "%.2f"|format(dns.entropy) if dns.entropy else 'N/A' }}</td>
                            <td>{{ dns.reasons|join(', ') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Suspicious HTTP -->
        {% if suspicious_http %}
        <div class="section">
            <h2 class="collapsible"><span class="icon">&#x1F4BB;</span> Suspicious HTTP Transactions ({{ suspicious_http|length }})</h2>
            <div class="content">
                <table>
                    <thead>
                        <tr>
                            <th>Method</th>
                            <th>URL</th>
                            <th>User-Agent</th>
                            <th>Reasons</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for http in suspicious_http %}
                        <tr>
                            <td>{{ http.method }}</td>
                            <td><span class="ioc-value">{{ http.url[:80] }}{% if http.url|length > 80 %}...{% endif %}</span></td>
                            <td>{{ http.user_agent[:50] if http.user_agent else 'N/A' }}{% if http.user_agent and http.user_agent|length > 50 %}...{% endif %}</td>
                            <td>{{ http.reasons|join(', ') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Extracted Files -->
        {% if files_list %}
        <div class="section">
            <h2 class="collapsible"><span class="icon">&#x1F4C1;</span> Extracted Files ({{ files_list|length }})</h2>
            <div class="content">
                <table>
                    <thead>
                        <tr>
                            <th>Filename</th>
                            <th>Type</th>
                            <th>Size</th>
                            <th>SHA256</th>
                            <th>Entropy</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in files_list %}
                        <tr>
                            <td>{{ file.filename or 'Unknown' }}</td>
                            <td>{{ file.magic_type or file.content_type or 'Unknown' }}</td>
                            <td>{{ format_bytes(file.size) }}</td>
                            <td><span class="ioc-value">{{ file.sha256[:16] }}...</span></td>
                            <td>{{ "%.2f"|format(file.entropy) if file.entropy else 'N/A' }}</td>
                            <td>
                                {% if file.is_suspicious %}
                                <span class="badge badge-high">Suspicious</span>
                                {% elif file.is_executable %}
                                <span class="badge badge-medium">Executable</span>
                                {% else %}
                                <span class="badge badge-info">Clean</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}

        <!-- Protocol Distribution -->
        <div class="section">
            <h2><span class="icon">&#x1F4CA;</span> Protocol Distribution</h2>
            <div class="protocol-chart">
                {% for proto, count in protocol_dist.items() %}
                <div class="protocol-item">
                    <div class="name">{{ proto }}</div>
                    <div class="count">{{ "{:,}".format(count) }}</div>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Top Talkers -->
        <div class="section">
            <h2 class="collapsible"><span class="icon">&#x1F4AC;</span> Top Talkers</h2>
            <div class="content">
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Traffic Volume</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ip, bytes in top_talkers %}
                        <tr>
                            <td><span class="ioc-value">{{ ip }}</span></td>
                            <td>{{ format_bytes(bytes) }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Geolocation -->
        {% if geo_summary %}
        <div class="section">
            <h2><span class="icon">&#x1F30D;</span> Geographic Distribution</h2>
            <div class="protocol-chart">
                {% for country, count in geo_summary.items() %}
                <div class="protocol-item">
                    <div class="name">{{ country }}</div>
                    <div class="count">{{ "{:,}".format(count) }}</div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <footer>
            <p>Generated by IOCSweep v2.0.0 | {{ generation_time }}</p>
            <p>Analysis Duration: {{ "%.2f"|format(duration) }} seconds</p>
        </footer>
    </div>

    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(el => {
            el.addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                content.classList.toggle('show');
            });
        });
    </script>
</body>
</html>
'''

    def __init__(self):
        """Initialize HTML exporter."""
        self.template = Template(self.TEMPLATE)

    def export(self, result: AnalysisResult, output_path: Path | str) -> None:
        """
        Export analysis result to HTML report.

        Args:
            result: Analysis result to export
            output_path: Path to output file
        """
        context = self._build_context(result)
        html = self.template.render(**context)

        with open(output_path, 'w') as f:
            f.write(html)

    def _build_context(self, result: AnalysisResult) -> dict:
        """Build template context from analysis result."""
        # Critical findings
        critical_findings = []
        for activity in result.suspicious_activities:
            if activity.severity in (Severity.HIGH, Severity.CRITICAL):
                critical_findings.append({
                    'type': activity.activity_type,
                    'severity': activity.severity.value,
                    'description': activity.description,
                    'src_ip': activity.src_ip,
                    'dst_ip': activity.dst_ip,
                    'mitre': activity.mitre_techniques,
                })

        for ioc in result.ioc_matches:
            if ioc.severity in (Severity.HIGH, Severity.CRITICAL):
                critical_findings.append({
                    'type': f'IOC Match: {ioc.ioc_type.value}',
                    'severity': ioc.severity.value,
                    'description': f'Matched {ioc.ioc_value}',
                    'src_ip': ioc.src_ip,
                    'dst_ip': ioc.dst_ip,
                    'mitre': [],
                })

        # IOC matches
        ioc_match_list = [
            {
                'type': m.ioc_type.value,
                'value': m.ioc_value,
                'severity': m.severity.value,
                'found_in': m.matched_in,
                'timestamp': m.timestamp.strftime('%H:%M:%S') if m.timestamp else 'N/A',
            }
            for m in result.ioc_matches
        ]

        # Beacons
        beacon_list = [
            {
                'dst_ip': b.dst_ip,
                'dst_port': b.dst_port,
                'interval': f'{b.interval_mean:.1f}s',
                'jitter': f'{b.jitter_percent:.1f}',
                'connections': b.connection_count,
                'confidence': int(b.confidence * 100),
            }
            for b in result.beacon_patterns if b.is_likely_beacon
        ]

        # Suspicious DNS
        suspicious_dns = [
            {
                'query_name': d.query_name,
                'query_type': d.query_type,
                'entropy': d.entropy,
                'reasons': d.suspicion_reasons,
            }
            for d in result.dns_records if d.is_suspicious
        ][:50]

        # Suspicious HTTP
        suspicious_http = [
            {
                'method': h.method,
                'url': h.full_url,
                'user_agent': h.user_agent,
                'reasons': h.suspicion_reasons,
            }
            for h in result.http_transactions if h.is_suspicious
        ][:50]

        # Files
        files_list = [
            {
                'filename': f.filename,
                'content_type': f.content_type,
                'magic_type': f.magic_type,
                'size': f.size,
                'sha256': f.sha256,
                'entropy': f.entropy,
                'is_suspicious': f.is_suspicious,
                'is_executable': f.is_executable,
            }
            for f in result.files
        ]

        return {
            'pcap_file': Path(result.pcap_file).name,
            'analysis_time': result.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'duration': result.analysis_duration_seconds,
            'total_packets': result.total_packets,
            'total_bytes': result.total_bytes,
            'unique_ips': len(result.unique_src_ips | result.unique_dst_ips),
            'unique_domains': len(result.unique_domains),
            'ioc_matches': len(result.ioc_matches),
            'suspicious_count': len(result.suspicious_activities),
            'beacon_count': len([b for b in result.beacon_patterns if b.is_likely_beacon]),
            'extracted_files': len(result.files),
            'critical_findings': critical_findings[:20],
            'ioc_match_list': ioc_match_list,
            'beacon_list': beacon_list,
            'suspicious_dns': suspicious_dns,
            'suspicious_http': suspicious_http,
            'files_list': files_list,
            'protocol_dist': dict(sorted(
                result.protocol_distribution.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'top_talkers': result.top_talkers[:15],
            'geo_summary': dict(sorted(
                result.geolocation_summary.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'format_bytes': self._format_bytes,
        }

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes in human-readable form."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f'{bytes_val:.1f} {unit}'
            bytes_val /= 1024
        return f'{bytes_val:.1f} PB'
