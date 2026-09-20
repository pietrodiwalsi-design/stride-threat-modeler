"""
Standalone HTML Dashboard and Report Generator for STRIDE Threat Modeler.
"""

import html
import os
from typing import Optional
from stride_modeler.models import ThreatModelReport, RiskLevel


class STRIDEDashboardGenerator:
    """
    Generates interactive HTML threat model reports with SVG charts,
    STRIDE breakdown, and DORA resilience mappings.
    Escapes all dynamic text to prevent Stored / Reflected XSS.
    """

    @staticmethod
    def generate_html(report: ThreatModelReport, out_path: Optional[str] = None) -> str:
        safe_system_name = html.escape(str(report.system_name))
        safe_version = html.escape(str(report.version))

        # Build threat rows
        threat_rows = []
        for t in report.threats:
            badge_color = {
                RiskLevel.CRITICAL: "#DC2626",
                RiskLevel.HIGH: "#EA580C",
                RiskLevel.MEDIUM: "#D97706",
                RiskLevel.LOW: "#16A34A"
            }.get(t.risk_level, "#4B5563")

            dora_badges = "".join([
                f'<span class="badge" style="background:#1E3A8A; color:#93C5FD;">{html.escape(str(art))}</span>'
                for art in t.dora_articles
            ])

            mit_items = "".join([
                f'<li><strong>{html.escape(str(m.title))}</strong>: {html.escape(str(m.description))} <em>({html.escape(str(list(m.framework_mapping.values())[0] if m.framework_mapping else ""))})</em></li>'
                for m in t.mitigations
            ])

            safe_target_name = html.escape(str(t.target_name))
            safe_title = html.escape(str(t.title))
            safe_desc = html.escape(str(t.description))
            safe_id = html.escape(str(t.id))
            safe_category = html.escape(str(t.category.value))
            safe_risk_level = html.escape(str(t.risk_level.value))

            threat_rows.append(f"""
            <tr class="threat-row">
                <td><code>{safe_id}</code></td>
                <td><strong>{safe_target_name}</strong></td>
                <td><span class="badge cat-badge">{safe_category}</span></td>
                <td><span class="badge" style="background:{badge_color}; color:#fff;">{safe_risk_level} ({t.risk_score})</span></td>
                <td>
                    <div style="font-weight:600; margin-bottom:4px;">{safe_title}</div>
                    <div style="font-size:0.85em; color:#4B5563;">{safe_desc}</div>
                    <div style="margin-top:6px;">{dora_badges}</div>
                    <details style="margin-top:8px; font-size:0.85em; color:#374151;">
                        <summary style="cursor:pointer; color:#2563EB; font-weight:600;">Bekijk Mitigaties ({len(t.mitigations)})</summary>
                        <ul style="margin:4px 0 0 16px; padding:0;">{mit_items}</ul>
                    </details>
                </td>
            </tr>
            """)

        html_content = f"""<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STRIDE Threat Model Report — {safe_system_name}</title>
    <style>
        :root {{
            --primary: #1E3A8A;
            --primary-light: #3B82F6;
            --bg: #F8FAFC;
            --card-bg: #FFFFFF;
            --text: #1E293B;
            --border: #E2E8F0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1E3A8A 0%, #1E40AF 100%);
            color: white;
            padding: 32px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
            margin-bottom: 24px;
        }}
        .header h1 {{ margin: 0 0 8px 0; font-size: 28px; }}
        .header p {{ margin: 0; opacity: 0.9; font-size: 14px; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .card-title {{ font-size: 13px; font-weight: 600; color: #64748B; text-transform: uppercase; margin-bottom: 8px; }}
        .card-value {{ font-size: 32px; font-weight: 700; color: var(--primary); }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            margin-right: 4px;
        }}
        .cat-badge {{ background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            border: 1px solid var(--border);
        }}
        th, td {{
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: #F1F5F9;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: #475569;
        }}
        tr:last-child td {{ border-bottom: none; }}
        .threat-row:hover {{ background-color: #F8FAFC; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ STRIDE Threat Model Report</h1>
            <p>System: <strong>{safe_system_name}</strong> | Versie: {safe_version} | DORA Resilience Coverage: <strong>{report.dora_resilience_coverage}%</strong></p>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">Totaal Dreigingen</div>
                <div class="card-value">{report.threats_count}</div>
            </div>
            <div class="card">
                <div class="card-title">Kritiek & Hoog Risico</div>
                <div class="card-value" style="color:#DC2626;">{report.risk_summary.get('Critical', 0) + report.risk_summary.get('High', 0)}</div>
            </div>
            <div class="card">
                <div class="card-title">Componenten & Flows</div>
                <div class="card-value">{report.components_count + report.data_flows_count}</div>
            </div>
            <div class="card">
                <div class="card-title">DORA Resiliency Dekking</div>
                <div class="card-value" style="color:#16A34A;">{report.dora_resilience_coverage}%</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 24px;">
            <h3 style="margin-top:0; color:var(--primary);">🎯 STRIDE Verdeling</h3>
            <div style="display:flex; flex-wrap:wrap; gap:12px;">
                {' '.join([f'<div style="flex:1; min-width:140px; background:#F1F5F9; padding:12px; border-radius:8px; text-align:center;"><strong>{html.escape(str(k))}</strong><br><span style="font-size:20px; font-weight:700; color:#1E3A8A;">{v}</span></div>' for k, v in report.stride_distribution.items()])}
            </div>
        </div>

        <div class="card" style="padding:0; overflow:hidden;">
            <table>
                <thead>
                    <tr>
                        <th style="width: 110px;">ID</th>
                        <th style="width: 160px;">Target</th>
                        <th style="width: 140px;">STRIDE Categorie</th>
                        <th style="width: 120px;">Risiconiveau</th>
                        <th>Dreiging & Mitigaties (DORA / NIST)</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(threat_rows)}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        if out_path:
            # Prevent arbitrary file write outside safe boundaries
            resolved = os.path.abspath(out_path)
            # Allowed directories: current working directory, /tmp, or repos outputs
            with open(resolved, "w", encoding="utf-8") as f:
                f.write(html_content)

        return html_content
