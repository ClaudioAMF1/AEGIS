"""Report generation. The JSON document is the source of truth (stored in ``reports``); the PDF
is rendered from it on demand so both formats always agree."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fpdf import FPDF
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis import __version__
from aegis.db import utcnow
from aegis.models import Alert, Event, Incident, IncidentEvent, Investigation, Report
from aegis.routers.common import scope_clause
from aegis.schemas import Scope
from aegis.services import analytics


def build_overview(db: Session, scope: Scope, start: datetime, end: datetime) -> dict[str, Any]:
    data = analytics.analytics(db, scope, start, end)
    overview = analytics.overview(db, scope, start, end)
    incidents = db.scalars(
        select(Incident)
        .where(Incident.detected_at.between(start, end), scope_clause(Incident.is_synthetic, scope))
        .order_by(Incident.detected_at)
    ).all()
    return {
        "kind": "overview",
        "scope": scope.value,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "metrics": overview["metrics"],
        "analytics": data,
        "incidents": [
            {
                "number": i.number,
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "detected_at": i.detected_at.isoformat(),
                "techniques": i.attack_techniques,
            }
            for i in incidents
        ],
    }


def build_incident(db: Session, incident_id: uuid.UUID) -> dict[str, Any]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise KeyError("incident")
    alerts = db.scalars(
        select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.first_event_at)
    ).all()
    events = db.scalars(
        select(Event)
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(Event.occurred_at)
        .limit(500)
    ).all()
    journal = db.scalars(
        select(Investigation)
        .where(Investigation.incident_id == incident_id)
        .order_by(Investigation.created_at)
    ).all()
    return {
        "kind": "incident",
        "scope": "demo" if incident.is_synthetic else "live",
        "period": {
            "start": incident.started_at.isoformat(),
            "end": (incident.ended_at or utcnow()).isoformat(),
        },
        "incident": {
            "id": str(incident.id),
            "number": incident.number,
            "title": incident.title,
            "description": incident.description,
            "status": incident.status,
            "severity": incident.severity,
            "started_at": incident.started_at.isoformat(),
            "ended_at": incident.ended_at.isoformat() if incident.ended_at else None,
            "detected_at": incident.detected_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "techniques": incident.attack_techniques,
            "tactics": incident.attack_tactics,
        },
        "alerts": [
            {
                "title": a.title,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "status": a.status,
                "disposition": a.disposition,
                "hits": a.hit_count,
                "first_event_at": a.first_event_at.isoformat(),
            }
            for a in alerts
        ],
        "timeline": [
            {
                "event_id": str(e.id),
                "occurred_at": e.occurred_at.isoformat(),
                "host": e.hostname,
                "type": f"{e.category}.{e.action}",
                "summary": e.summary,
            }
            for e in events
        ],
        "journal": [
            {
                "at": j.created_at.isoformat(),
                "author": j.author_name,
                "type": j.entry_type,
                "body": j.body,
            }
            for j in journal
        ],
    }


def create(
    db: Session,
    *,
    title: str,
    content: dict[str, Any],
    user_id: uuid.UUID,
    incident_id: uuid.UUID | None = None,
) -> Report:
    report = Report(
        title=title,
        kind=content["kind"],
        period_start=datetime.fromisoformat(content["period"]["start"]),
        period_end=datetime.fromisoformat(content["period"]["end"]),
        incident_id=incident_id,
        include_synthetic=content["scope"] != "live",
        content={
            **content,
            "generated_at": utcnow().isoformat(),
            "generator": f"AEGIS {__version__}",
        },
        created_by=user_id,
    )
    db.add(report)
    db.flush()
    return report


# --- PDF ------------------------------------------------------------------------------------

_REPLACEMENTS = {
    "\u2192": "->",
    "\u2212": "-",
    "\u2014": "-",
    "\u2013": "-",
    "\u2026": "...",
    "\u00b7": "-",
    "\u2265": ">=",
    "\u2264": "<=",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u25c6": "*",
}


def _latin1(text: object) -> str:
    value = str(text)
    for src, dst in _REPLACEMENTS.items():
        value = value.replace(src, dst)
    return value.encode("latin-1", "replace").decode("latin-1")


class _Pdf(FPDF):
    def __init__(self, title: str, scope: str) -> None:
        super().__init__(format="A4")
        self.report_title = title
        self.scope = scope
        self.set_auto_page_break(auto=True, margin=16)
        self.set_margins(16, 16, 16)

    def header(self) -> None:
        self.set_font("Courier", "B", 9)
        self.set_text_color(60, 66, 54)
        self.cell(0, 5, _latin1(f"AEGIS / {self.report_title}"), new_x="LMARGIN", new_y="NEXT")
        if self.scope != "live":
            self.set_text_color(110, 79, 140)
            self.cell(0, 5, "DADOS SINTETICOS (MODO DEMO)", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(187, 189, 169)
        self.line(16, self.get_y() + 1, 194, self.get_y() + 1)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Courier", "", 7)
        self.set_text_color(120, 120, 110)
        self.cell(0, 5, _latin1(f"pagina {self.page_no()}"), align="R")

    def h2(self, text: str) -> None:
        self.ln(2)
        self.set_font("Courier", "B", 10)
        self.set_text_color(51, 58, 46)
        self.cell(0, 6, _latin1(text.upper()), new_x="LMARGIN", new_y="NEXT")

    def para(self, text: str, size: int = 8) -> None:
        self.set_font("Courier", "", size)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 4, _latin1(text), new_x="LMARGIN", new_y="NEXT")

    def kv(self, key: str, value: object) -> None:
        self.set_font("Courier", "", 8)
        self.set_text_color(99, 105, 88)
        self.cell(52, 4.5, _latin1(key))
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 4.5, _latin1(value), new_x="LMARGIN", new_y="NEXT")


def render_pdf(report: Report) -> bytes:
    c = report.content
    pdf = _Pdf(report.title, c.get("scope", "live"))
    pdf.add_page()
    pdf.set_font("Courier", "B", 14)
    pdf.multi_cell(0, 7, _latin1(report.title), new_x="LMARGIN", new_y="NEXT")
    pdf.kv("periodo", f"{c['period']['start']} -> {c['period']['end']}")
    pdf.kv("gerado em", c.get("generated_at", ""))
    pdf.kv("escopo", c.get("scope"))
    if c["kind"] == "overview":
        pdf.h2("indicadores")
        for m in c["metrics"]:
            pdf.kv(m["label"], f"{m['value']} {m['unit'] if m['unit'] != 'count' else ''}")
            pdf.para(f"  definicao: {m['definition']} fonte: {m['source']}", size=7)
        a = c["analytics"]
        pdf.h2("alertas por severidade")
        for sev, n in sorted(a["alerts_by_severity"].items()):
            pdf.kv(sev, n)
        pdf.h2("regras mais acionadas")
        for r in a["top_rules"]:
            pdf.kv(str(r["alerts"]), f"{r['title']} ({r['rule_id']})")
        pdf.h2("qualidade da deteccao")
        fp = a["false_positive_rate"]
        pdf.kv(
            "falsos positivos",
            f"{fp['value']}% de {fp['labelled']} alertas rotulados"
            if fp["value"] is not None
            else "sem alertas rotulados",
        )
        pdf.kv(
            "tempo ate deteccao",
            f"mediana {a['time_to_detect_seconds']['median']} s "
            f"({a['time_to_detect_seconds']['samples']} amostras)",
        )
        pdf.kv(
            "tempo ate triagem",
            f"mediana {a['time_to_triage_seconds']['median']} s "
            f"({a['time_to_triage_seconds']['samples']} amostras)",
        )
        pdf.kv(
            "cobertura ATT&CK",
            f"{len(a['coverage']['techniques'])} tecnicas em "
            f"{a['coverage']['rules_enabled']} regras ativas",
        )
        pdf.para(a["definitions"]["coverage"], size=7)
        pdf.h2("incidentes")
        for i in c["incidents"]:
            pdf.kv(f"INC-{i['number']:04d}", f"[{i['severity']}/{i['status']}] {i['title']}")
    else:
        inc = c["incident"]
        pdf.h2(f"INC-{inc['number']:04d}")
        for key in ("status", "severity", "started_at", "ended_at", "detected_at", "resolved_at"):
            pdf.kv(key, inc[key] or "-")
        pdf.kv("ATT&CK", ", ".join(inc["techniques"]) or "-")
        if inc["description"]:
            pdf.para(inc["description"])
        pdf.h2("alertas")
        for a in c["alerts"]:
            pdf.kv(
                a["severity"],
                f"{a['title']} ({a['rule_id']}, {a['hits']} ocorrencias, {a['disposition']})",
            )
        pdf.h2("linha do tempo (evidencias)")
        for e in c["timeline"]:
            pdf.para(f"{e['occurred_at']}  {e['host']}  {e['type']}  {e['summary']}", size=7)
            pdf.para(f"    event_id {e['event_id']}", size=6)
        pdf.h2("diario")
        for j in c["journal"]:
            pdf.para(f"{j['at']} {j['author']} [{j['type']}] {j['body']}", size=7)
    return bytes(pdf.output())
