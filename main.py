import flet as ft
import pyperclip
import csv
import io

from cvss import calculate_base_score, METRIC_FIELDS, vector_string
from parser import parse_csv_text, parse_json_text
from storage import Store
from ui_components import pill, section_title, info_card, toast_bar


METRIC_OPTIONS = {
    "AV": [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")],
    "AC": [("L", "Low"), ("H", "High")],
    "PR": [("N", "None"), ("L", "Low"), ("H", "High")],
    "UI": [("N", "None"), ("R", "Required")],
    "S":  [("U", "Unchanged"), ("C", "Changed")],
    "C":  [("H", "High"), ("L", "Low"), ("N", "None")],
    "I":  [("H", "High"), ("L", "Low"), ("N", "None")],
    "A":  [("H", "High"), ("L", "Low"), ("N", "None")],
}

METRIC_LABELS = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}


def split_csv_field(s: str):
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def main(page: ft.Page):
    page.title = "RiskMapper (Flet) — CVSS + Attack Surface"
    page.theme_mode = ft.ThemeMode.DARK
    page.window.width = 1100
    page.window.height = 760
    page.padding = 18

    page.theme = ft.Theme(color_scheme_seed=ft.colors.BLUE, use_material3=True)
    page.dark_theme = ft.Theme(color_scheme_seed=ft.colors.BLUE, use_material3=True)

    theme_btn = ft.IconButton(icon=ft.icons.LIGHT_MODE, tooltip="Passer en mode clair")

    def toggle_theme(e):
        page.theme_mode = (
            ft.ThemeMode.LIGHT if page.theme_mode == ft.ThemeMode.DARK else ft.ThemeMode.DARK
        )
        if page.theme_mode == ft.ThemeMode.LIGHT:
            theme_btn.icon = ft.icons.DARK_MODE
            theme_btn.tooltip = "Passer en mode sombre"
        else:
            theme_btn.icon = ft.icons.LIGHT_MODE
            theme_btn.tooltip = "Passer en mode clair"
        page.update()

    theme_btn.on_click = toggle_theme
    page.appbar = ft.AppBar(
        title=ft.Text("RiskMapper"),
        center_title=False,
        actions=[theme_btn],
    )

    store = Store()
    store.load_from_db()

    def notify(msg: str, kind: str = "info"):
        sb = toast_bar(msg, kind)
        page.overlay.append(sb)
        sb.open = True
        page.update()

    def copy_text(text: str):
        try:
            if hasattr(page, "set_clipboard"):
                page.set_clipboard(text)
                notify("Copied to clipboard ✅", "success")
                return
        except Exception:
            pass

        try:
            pyperclip.copy(text)
            notify("Copied to clipboard ✅", "success")
        except Exception as ex:
            notify(f"Clipboard copy failed: {ex}", "error")

    export_picker = ft.FilePicker()
    page.overlay.append(export_picker)

    assets_export_picker = ft.FilePicker()
    page.overlay.append(assets_export_picker)

    assets_export_ctx = {"asset_names": []}

    def build_findings_csv() -> str:
        output = io.StringIO()
        w = csv.writer(output, delimiter=';')
        w.writerow(["id", "asset", "title", "score", "severity", "vector", "AV", "AC", "PR", "UI", "S", "C", "I", "A"])

        sorted_findings = sorted(store.findings.values(), key=lambda x: x.score, reverse=True)
        for f in sorted_findings:
            m = f.metrics
            w.writerow([
                f.id, f.asset_name, f.title, f"{f.score:.1f}", f.severity, getattr(f, "vector", ""),
                m["AV"], m["AC"], m["PR"], m["UI"], m["S"], m["C"], m["I"], m["A"]
            ])
        return output.getvalue()

    def build_findings_csv_for_assets(asset_names: list[str]) -> str:
        output = io.StringIO()
        w = csv.writer(output, delimiter=';')
        w.writerow(["id", "asset", "title", "score", "severity", "vector", "AV", "AC", "PR", "UI", "S", "C", "I", "A"])

        selected_set = {a.strip().lower() for a in asset_names if a and a.strip()}
        findings = [
            f for f in store.findings.values()
            if f.asset_name.strip().lower() in selected_set
        ]
        findings.sort(key=lambda x: x.score, reverse=True)

        for f in findings:
            m = f.metrics
            w.writerow([
                f.id, f.asset_name, f.title, f"{f.score:.1f}", f.severity, getattr(f, "vector", ""),
                m["AV"], m["AC"], m["PR"], m["UI"], m["S"], m["C"], m["I"], m["A"]
            ])

        return output.getvalue()

    def on_export_result(e: ft.FilePickerResultEvent):
        if not e.path:
            return
        try:
            csv_text = build_findings_csv()
            with open(e.path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_text)
            notify(f"CSV exported ✅\n{e.path}", "success")
        except Exception as ex:
            notify(f"Export failed: {ex}", "error")

    export_picker.on_result = on_export_result

    def on_assets_export_result(e: ft.FilePickerResultEvent):
        if not e.path:
            return
        try:
            names = assets_export_ctx["asset_names"]
            if not names:
                notify("No assets selected.", "warning")
                return

            csv_text = build_findings_csv_for_assets(names)
            with open(e.path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_text)

            notify(f"Selected assets CSV exported ✅\n{e.path}", "success")
        except Exception as ex:
            notify(f"Export failed: {ex}", "error")

    assets_export_picker.on_result = on_assets_export_result


    dash_counts = ft.Column(spacing=6)
    dash_latest = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO, height=270)

    def go_tab(i: int):
        tabs.selected_index = i
        tabs.update()

    def rebuild_dashboard():
        dash_counts.controls.clear()
        c = store.severity_counts()
        dash_counts.controls.extend([
            ft.Row([ft.Text("Critical", width=90), ft.Text(str(c["Critical"]))]),
            ft.Row([ft.Text("High", width=90), ft.Text(str(c["High"]))]),
            ft.Row([ft.Text("Medium", width=90), ft.Text(str(c["Medium"]))]),
            ft.Row([ft.Text("Low", width=90), ft.Text(str(c["Low"]))]),
            ft.Row([ft.Text("None", width=90), ft.Text(str(c["None"]))]),
        ])

        dash_latest.controls.clear()
        findings = list(store.findings.values())[-10:]
        if not findings:
            dash_latest.controls.append(ft.Text("No findings yet. Use Calculator or Import.", opacity=0.8))
        else:
            for f in reversed(findings):
                try:
                    res = calculate_base_score(f.metrics)
                    impact_txt = f"I:{res.impact:.1f}"
                    explo_txt = f"E:{res.exploitability:.1f}"
                except Exception:
                    impact_txt = "I:—"
                    explo_txt = "E:—"

                dash_latest.controls.append(
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Text(f.asset_name, width=200),
                                ft.Text(f.title, expand=True),
                                ft.Text(impact_txt, width=70, text_align=ft.TextAlign.RIGHT, opacity=0.85),
                                ft.Text(explo_txt, width=70, text_align=ft.TextAlign.RIGHT, opacity=0.85),
                                ft.Container(content=pill(f.severity, f.score), margin=ft.margin.only(left=8)),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        on_click=lambda e, an=f.asset_name: (
                            (last_selected_asset.__setitem__("id", store.get_asset_by_name(an).id) # type: ignore
                             if store.get_asset_by_name(an) is not None
                             else last_selected_asset.__setitem__("id", None)),
                            go_tab(3),
                            rebuild_assets_list(),
                            rebuild_asset_detail(),
                            page.update()
                        ),
                        ink=True,
                        padding=10,
                        border=ft.border.all(1, ft.colors.with_opacity(0.12, ft.colors.WHITE)),
                        border_radius=14,
                    )
                )
        page.update()

    dashboard_view = ft.Column(
        [
            section_title("Dashboard"),
            ft.ResponsiveRow(
                [
                    ft.ResponsiveRow(
                        col=6,
                        controls=[info_card("Findings by Severity", dash_counts)],
                    ),
                    ft.ResponsiveRow(
                        col=6,
                        controls=[
                            info_card(
                                "Quick Actions",
                                ft.Column(
                                    [
                                        ft.ElevatedButton("Open CVSS Calculator", on_click=lambda e: go_tab(1)),
                                        ft.ElevatedButton("Import Findings", on_click=lambda e: go_tab(2)),
                                        ft.ElevatedButton("Manage Assets", on_click=lambda e: go_tab(3)),
                                        ft.ElevatedButton(
                                            "Export Findings to CSV",
                                            icon=ft.icons.DOWNLOAD,
                                            on_click=lambda e: export_picker.save_file(
                                                file_name="riskmapper_findings.csv",
                                                allowed_extensions=["csv"],
                                            ),
                                        ),
                                    ],
                                    spacing=10,
                                ),
                            )
                        ],
                    ),
                ]
            ),
            info_card("Latest Findings", dash_latest),
        ],
        spacing=16,
    )

    calc_asset_dropdown = ft.Dropdown(label="Select existing asset (optional)", options=[])
    calc_asset_custom = ft.TextField(label="Or enter custom asset name (optional)", hint_text="e.g., web-portal-01")
    calc_title = ft.TextField(label="Finding title (optional)", hint_text="e.g., SQL Injection in /login")

    metric_dropdowns = {}
    for k in METRIC_FIELDS:
        opts = [ft.dropdown.Option(code, text=f"{code} — {label}") for code, label in METRIC_OPTIONS[k]]
        label_text = f"{k}: {METRIC_LABELS.get(k, '')}"
        metric_dropdowns[k] = ft.Dropdown(label=label_text, options=opts)

    calc_result_line = ft.Row([], spacing=10)
    calc_details = ft.Column([], spacing=6)

    def do_calculate(save: bool):
        try:
            metrics = {k: metric_dropdowns[k].value for k in METRIC_FIELDS}
            res = calculate_base_score(metrics)
            vec = vector_string(metrics)

            calc_result_line.controls = [
                ft.Text(f"Base Score: {res.score:.1f}", size=20, weight=ft.FontWeight.BOLD),
                pill(res.severity, res.score),
            ]

            calc_details.controls = [
                ft.Text(f"Impact: {res.impact:.1f}"),
                ft.Text(f"Exploitability: {res.exploitability:.1f}"),
                ft.Row(
                    [
                        ft.Text(f"Vector: {vec}", selectable=True, expand=True, opacity=0.85),
                        ft.IconButton(
                            icon=ft.icons.CONTENT_COPY,
                            tooltip="Copy CVSS vector",
                            on_click=lambda e, v=vec: copy_text(v),
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
            ]

            if save:
                chosen_asset = None
                if calc_asset_dropdown.value:
                    chosen_asset = calc_asset_dropdown.value
                elif (calc_asset_custom.value or "").strip():
                    chosen_asset = calc_asset_custom.value.strip() # type: ignore
                else:
                    chosen_asset = "Unassigned"

                store.add_finding(
                    asset_name=chosen_asset,
                    title=calc_title.value or "Manual Finding",
                    metrics={k: metrics[k] for k in METRIC_FIELDS},
                    score=res.score,
                    severity=res.severity,
                    vector=vec,
                )
                rebuild_all()
                notify("Finding saved.", "success")

            page.update()

        except Exception as ex:
            notify(str(ex), "error")

    calculator_view = ft.Column(
        [
            section_title("CVSS v3.1 Calculator"),
            info_card("Finding Info", ft.Column([calc_asset_dropdown, calc_asset_custom, calc_title], spacing=10)),
            info_card(
                "Base Metrics",
                ft.Row(
                    controls=list(metric_dropdowns.values()),
                    wrap=True,
                    spacing=12,
                    run_spacing=12,
                ),
            ),
            ft.Row(
                [
                    ft.ElevatedButton("Calculate", on_click=lambda e: do_calculate(save=False)),
                    ft.OutlinedButton("Calculate & Save", on_click=lambda e: do_calculate(save=True)),
                ],
                spacing=12,
            ),
            info_card("Result", ft.Column([calc_result_line, calc_details], spacing=10)),
            ft.Text(
                "Tip: Link findings to assets by using the exact same asset name in Assets tab.",
                opacity=0.7,
            ),
        ],
        spacing=16,
        scroll=ft.ScrollMode.AUTO,
    )

    import_format = ft.RadioGroup(
        content=ft.Row(
            [
                ft.Radio(value="csv", label="CSV"),
                ft.Radio(value="json", label="JSON"),
            ],
            spacing=20,
        ),
        value="csv",
    )

    import_text = ft.TextField(
        label="Paste CSV/JSON here (or load from file)",
        multiline=True,
        min_lines=10,
        max_lines=18,
    )
    import_summary = ft.Column(spacing=6)

    file_picker = ft.FilePicker()
    page.overlay.append(file_picker)

    def on_file_result(e: ft.FilePickerResultEvent):
        if not e.files:
            return
        try:
            path = e.files[0].path
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                import_text.value = f.read()
            notify(f"Loaded: {path}", "success")
            page.update()
        except Exception as ex:
            notify(f"Failed reading file: {ex}", "error")

    file_picker.on_result = on_file_result

    def do_import():
        txt = import_text.value or ""
        mode = import_format.value
        if not txt.strip():
            notify("Paste some CSV/JSON first (or Load from file).", "warning")
            return

        try:
            parsed = parse_csv_text(txt) if mode == "csv" else parse_json_text(txt)
            valid = 0
            skipped = 0

            for item in parsed:
                metrics = {k: item[k] for k in METRIC_FIELDS}
                try:
                    res = calculate_base_score(metrics)
                    vec = vector_string(metrics)
                except Exception:
                    skipped += 1
                    continue

                asset_name = (item.get("asset") or "").strip()
                if asset_name:
                    if store.get_asset_by_name(asset_name) is None:
                        store.add_asset(name=asset_name, tags=[], services=[])

                store.add_finding(
                    asset_name=asset_name or "Unassigned",
                    title=item["title"],
                    metrics=metrics,
                    score=res.score,
                    severity=res.severity,
                    vector=vec,
                )
                valid += 1

            rebuild_all()
            import_summary.controls = [
                ft.Text(f"Imported: {valid}", weight=ft.FontWeight.BOLD),
                ft.Text(f"Skipped invalid rows: {skipped}"),
            ]
            notify(f"Import complete: {valid} added, {skipped} skipped.", "success")
            page.update()

        except Exception as ex:
            notify(f"Import failed: {ex}", "error")

    import_view = ft.Column(
        [
            section_title("Import Findings"),
            info_card(
                "How to import",
                ft.Column(
                    [
                        ft.Text("CSV header: asset,title,AV,AC,PR,UI,S,C,I,A", selectable=True),
                        ft.Text('Example row: web-01,"XSS in search",N,L,N,R,U,L,L,N', selectable=True),
                        ft.Text("JSON must be a list of objects with the same keys.", selectable=True),
                    ],
                    spacing=8,
                ),
            ),
            info_card(
                "Import Input",
                ft.Column(
                    [
                        import_format,
                        import_text,
                        ft.Row(
                            [
                                ft.ElevatedButton(
                                    "Load from file",
                                    on_click=lambda e: file_picker.pick_files(
                                        allow_multiple=False,
                                        allowed_extensions=["csv", "json"],
                                    ),
                                ),
                                ft.ElevatedButton("Import", on_click=lambda e: do_import()),
                            ],
                            spacing=12,
                        ),
                        import_summary,
                    ],
                    spacing=10,
                ),
            ),
        ],
        spacing=16,
        scroll=ft.ScrollMode.AUTO,
    )

    asset_name = ft.TextField(label="Asset name", hint_text="e.g., api.example.com or 10.0.0.12")
    asset_tags = ft.TextField(label="Tags (comma-separated)", hint_text="internet-facing, prod, pci")
    asset_services = ft.TextField(label="Services (comma-separated)", hint_text="80/http, 443/https, 22/ssh")

    assets_list = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO, height=420)
    asset_detail_title = ft.Text("Select assets to view details.", size=16, weight=ft.FontWeight.BOLD)
    asset_detail_body = ft.Column(spacing=8)

    selected_assets = set()
    last_selected_asset = {"id": None}

    def export_selected_assets():
        if not selected_assets:
            notify("Select at least one asset first.", "warning")
            return

        names = []
        for aid in selected_assets:
            if aid in store.assets:
                names.append(store.assets[aid].name)

        if not names:
            notify("Selection contains no valid assets.", "warning")
            return

        assets_export_ctx["asset_names"] = names

        assets_export_picker.save_file(
            file_name="riskmapper_selected_assets_findings.csv",
            allowed_extensions=["csv"],
        )

    def rebuild_assets_list():
        assets_list.controls.clear()

        if not store.assets:
            assets_list.controls.append(ft.Text("No assets yet. Add one using the form.", opacity=0.75))
            page.update()
            return

        def mk_row(aid: str):
            a = store.assets[aid]
            findings = store.findings_for_asset_name(a.name)
            if findings:
                max_score = max(f.score for f in findings)
                avg_score = sum(f.score for f in findings) / len(findings)
            else:
                max_score = 0.0
                avg_score = 0.0

            def on_toggle(e):
                if aid in selected_assets:
                    selected_assets.remove(aid)
                    if last_selected_asset["id"] == aid:
                        last_selected_asset["id"] = None
                else:
                    selected_assets.add(aid)
                    last_selected_asset["id"] = aid # type: ignore

                rebuild_assets_list()
                rebuild_asset_detail()
                page.update()

            is_selected = (aid in selected_assets)

            return ft.Container(
                content=ft.Row(
                    [
                        ft.Text(a.name, width=260, weight=ft.FontWeight.BOLD),
                        ft.Text(f"Findings: {len(findings)}", width=110),
                        ft.Text(f"Max: {max_score:.1f}", width=90),
                        ft.Text(f"Avg: {avg_score:.1f}", width=90),
                        ft.IconButton(icon=ft.icons.CHEVRON_RIGHT, on_click=on_toggle),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                on_click=on_toggle,
                ink=True,
                bgcolor=ft.colors.with_opacity(0.14, ft.colors.BLUE) if is_selected else None,
                padding=10,
                border=ft.border.all(1, ft.colors.with_opacity(0.12, ft.colors.WHITE)),
                border_radius=14,
            )

        for aid in list(store.assets.keys())[::-1]:
            assets_list.controls.append(mk_row(aid))

        update_asset_dropdown()
        page.update()

    def clear_selection(e):
        selected_assets.clear()
        last_selected_asset["id"] = None
        rebuild_assets_list()
        rebuild_asset_detail()
        page.update()

    def rebuild_asset_detail():
        aid = last_selected_asset["id"]
        asset_detail_body.controls.clear()

        if not aid or aid not in store.assets:
            asset_detail_title.value = (
                "Select assets (multi-select is allowed). "
                "Details shows the last clicked asset."
            )
            page.update()
            return

        a = store.assets[aid]
        asset_detail_title.value = f"Asset (last selected): {a.name}"

        findings = store.findings_for_asset_name(a.name)
        if findings:
            max_score = max(f.score for f in findings)
            avg_score = sum(f.score for f in findings) / len(findings)
        else:
            max_score = 0.0
            avg_score = 0.0

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        finding_cards = ft.Column(spacing=8)
        if not findings:
            finding_cards.controls.append(ft.Text("No findings mapped to this asset yet.", opacity=0.75))
        else:
            for f in sorted(findings, key=lambda x: x.score, reverse=True):
                try:
                    res = calculate_base_score(f.metrics)
                    impact_txt = f"I:{res.impact:.1f}"
                    explo_txt = f"E:{res.exploitability:.1f}"
                except Exception:
                    impact_txt = "I:—"
                    explo_txt = "E:—"

                finding_cards.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Text(f.title, expand=True),
                                        ft.Text(impact_txt, width=60, text_align=ft.TextAlign.RIGHT, opacity=0.85),
                                        ft.Text(explo_txt, width=60, text_align=ft.TextAlign.RIGHT, opacity=0.85),
                                        ft.Container(content=pill(f.severity, f.score), margin=ft.margin.only(left=8)),
                                        ft.IconButton(
                                            icon=ft.icons.DELETE_OUTLINE,
                                            tooltip="Delete finding",
                                            on_click=lambda e, fid=f.id: (store.delete_finding(fid), rebuild_all()),
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                ),
                                ft.Row(
                                    [
                                        ft.Text(getattr(f, "vector", ""), size=12, opacity=0.75, expand=True, selectable=True),
                                        ft.IconButton(
                                            icon=ft.icons.CONTENT_COPY,
                                            tooltip="Copy vector",
                                            on_click=lambda e, v=getattr(f, "vector", ""): copy_text(v),
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                ),
                            ],
                            spacing=6,
                        ),
                        padding=10,
                        border=ft.border.all(1, ft.colors.with_opacity(0.12, ft.colors.WHITE)),
                        border_radius=14,
                    )
                )

        def delete_asset():
            if aid in selected_assets:
                selected_assets.remove(aid)
            last_selected_asset["id"] = None

            store.delete_asset(aid)
            rebuild_all()
            notify("Asset deleted.", "success")

        asset_detail_body.controls.extend(
            [
                info_card(
                    "Attack Surface",
                    ft.Column(
                        [
                            ft.Text(f"Tags: {', '.join(a.tags) if a.tags else '—'}"),
                            ft.Text(f"Services: {', '.join(a.services) if a.services else '—'}"),
                        ],
                        spacing=6,
                    ),
                ),
                info_card(
                    "Risk Summary",
                    ft.Column(
                        [
                            ft.Text(f"Findings: {len(findings)}"),
                            ft.Text(f"Max score: {max_score:.1f}"),
                            ft.Text(f"Avg score: {avg_score:.1f}"),
                            ft.Row(
                                [
                                    ft.Column([ft.Text("Critical"), ft.Text(str(counts["Critical"]))]),
                                    ft.Column([ft.Text("High"), ft.Text(str(counts["High"]))]),
                                    ft.Column([ft.Text("Medium"), ft.Text(str(counts["Medium"]))]),
                                    ft.Column([ft.Text("Low"), ft.Text(str(counts["Low"]))]),
                                    ft.Column([ft.Text("None"), ft.Text(str(counts["None"]))]),
                                ],
                                wrap=True,
                                spacing=18,
                            ),
                            ft.Row(
                                [
                                    ft.ElevatedButton(
                                        "Export selected assets to CSV",
                                        icon=ft.icons.DOWNLOAD,
                                        on_click=lambda e: export_selected_assets(),
                                    ),
                                    ft.OutlinedButton(
                                        "Clear selection",
                                        icon=ft.icons.CLEAR,
                                        on_click=clear_selection,
                                    ),
                                    ft.OutlinedButton(
                                        "Delete this asset",
                                        icon=ft.icons.DELETE,
                                        on_click=lambda e: delete_asset(),
                                    ),
                                ],
                                wrap=True,
                                spacing=10,
                            ),
                        ],
                        spacing=8,
                    ),
                ),
                info_card("Findings (sorted by score)", finding_cards),
            ]
        )
        page.update()


    def update_asset_dropdown():
        current = getattr(calc_asset_dropdown, "value", None)
        opts = [ft.dropdown.Option(a.name, text=a.name) for a in store.assets.values()]
        calc_asset_dropdown.options = opts
        names = [a.name for a in store.assets.values()]
        if current and current in names:
            calc_asset_dropdown.value = current
        else:
            calc_asset_dropdown.value = None

    def add_asset_action(e):
        name = (asset_name.value or "").strip()
        if not name:
            notify("Asset name is required.", "error")
            return

        tags = split_csv_field(asset_tags.value) # type: ignore
        services = split_csv_field(asset_services.value) # type: ignore
        store.add_asset(name=name, tags=tags, services=services)

        asset_name.value = ""
        asset_tags.value = ""
        asset_services.value = ""

        rebuild_assets_list()
        notify("Asset added.", "success")
        page.update()

    assets_view = ft.Column(
        [
            section_title("Attack Surface / Assets"),
            ft.ResponsiveRow(
                [
                    ft.Container(
                        col=5,
                        content=info_card(
                            "Add Asset",
                            ft.Column(
                                [
                                    asset_name,
                                    asset_tags,
                                    asset_services,
                                    ft.ElevatedButton("Add Asset", on_click=add_asset_action),
                                    ft.Row(
                                        [
                                            ft.ElevatedButton(
                                                "Export selected assets to CSV",
                                                icon=ft.icons.DOWNLOAD,
                                                on_click=lambda e: export_selected_assets(),
                                            ),
                                            ft.OutlinedButton(
                                                "Clear selection",
                                                icon=ft.icons.CLEAR,
                                                on_click=clear_selection,
                                            ),
                                        ],
                                        wrap=True,
                                        spacing=10,
                                    ),
                                ],
                                spacing=10,
                            ),
                        ),
                    ),
                    ft.Container(col=7, content=info_card("Assets (click row to toggle select)", assets_list)),
                ]
            ),
            info_card("Asset Details (last selected)", ft.Column([asset_detail_title, asset_detail_body], spacing=12)),
        ],
        spacing=16,
        scroll=ft.ScrollMode.AUTO,
    )

    def rebuild_all():
        rebuild_dashboard()
        rebuild_assets_list()
        rebuild_asset_detail()

    tabs = ft.Tabs(
        selected_index=0,
        animation_duration=250,
        tabs=[
            ft.Tab(text="Dashboard", content=dashboard_view),
            ft.Tab(text="Calculator", content=calculator_view),
            ft.Tab(text="Import", content=import_view),
            ft.Tab(text="Assets", content=assets_view),
        ],
        expand=1,
    )

    page.add(tabs)
    rebuild_all()


ft.app(target=main)
