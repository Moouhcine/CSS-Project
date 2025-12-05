import flet as ft

from cvss import calculate_base_score, METRIC_FIELDS
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

def split_csv_field(s: str):
    return [x.strip() for x in (s or "").split(",") if x.strip()]

def main(page: ft.Page):
    page.title = "RiskMapper (Flet) — CVSS + Attack Surface"
    page.theme_mode = ft.ThemeMode.DARK
    page.window.width = 1100
    page.window.height = 760
    page.padding = 18

    store = Store()

    # ----------------------------
    # Shared toasts
    # ----------------------------
    def notify(msg: str, kind: str = "info"):
        page.snack_bar = toast_bar(msg, kind)
        page.snack_bar.open = True
        page.update()
    
    # ----------------------------
    # DASHBOARD
    # ----------------------------
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
                dash_latest.controls.append(
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Text(f.asset_name, width=200),
                                ft.Text(f.title, expand=True),
                                ft.Text(f"{f.score:.1f}", width=70, text_align=ft.TextAlign.RIGHT),
                                pill(f.severity),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
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
                        controls=[
                            info_card("Findings by Severity", dash_counts),
                        ],
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

    # ----------------------------
    # CALCULATOR
    # ----------------------------
    calc_asset = ft.TextField(label="Asset name (optional)", hint_text="e.g., web-portal-01")
    calc_title = ft.TextField(label="Finding title (optional)", hint_text="e.g., SQL Injection in /login")

    metric_dropdowns = {}
    for k in METRIC_FIELDS:
        opts = [ft.dropdown.Option(code, text=f"{code} — {label}") for code, label in METRIC_OPTIONS[k]]
        metric_dropdowns[k] = ft.Dropdown(label=k, options=opts)


    calc_result_line = ft.Row([], spacing=10)
    calc_details = ft.Column([], spacing=6)

    last_result = {"score": None, "severity": None, "impact": None, "exploitability": None}

    def do_calculate(save: bool):
        try:
            metrics = {k: metric_dropdowns[k].value for k in METRIC_FIELDS}
            res = calculate_base_score(metrics)

            last_result["score"] = res.score
            last_result["severity"] = res.severity
            last_result["impact"] = res.impact
            last_result["exploitability"] = res.exploitability

            calc_result_line.controls = [
                ft.Text(f"Base Score: {res.score:.1f}", size=20, weight=ft.FontWeight.BOLD),
                pill(res.severity),
            ]
            calc_details.controls = [
                ft.Text(f"Impact: {res.impact:.1f}"),
                ft.Text(f"Exploitability: {res.exploitability:.1f}"),
            ]

            if save:
                store.add_finding(
                    asset_name=calc_asset.value or "Unassigned",
                    title=calc_title.value or "Manual Finding",
                    metrics={k: metrics[k] for k in METRIC_FIELDS},
                    score=res.score,
                    severity=res.severity,
                )
                rebuild_all()
                notify("Finding saved.", "success")
            page.update()

        except Exception as ex:
            notify(str(ex), "error")

    calculator_view = ft.Column(
        [
            section_title("CVSS v3.1 Calculator"),
            info_card(
                "Finding Info",
                ft.Column([calc_asset, calc_title], spacing=10),
            ),
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
            info_card(
                "Result",
                ft.Column([calc_result_line, calc_details], spacing=10),
            ),
            ft.Text(
                "Tip: Link findings to assets by using the exact same asset name in Assets tab.",
                opacity=0.7,
            ),
        ],
        spacing=16,
        scroll=ft.ScrollMode.AUTO,
    )

    # ----------------------------
    # IMPORT
    # ----------------------------
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
        # Flet gives a path; read locally
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
                except Exception:
                    skipped += 1
                    continue

                store.add_finding(
                    asset_name=item["asset"],
                    title=item["title"],
                    metrics=metrics,
                    score=res.score,
                    severity=res.severity,
                )
                valid += 1

            rebuild_dashboard()
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

    # ----------------------------
    # ASSETS (attack surface mapper)
    # ----------------------------
    asset_name = ft.TextField(label="Asset name", hint_text="e.g., api.example.com or 10.0.0.12")
    asset_tags = ft.TextField(label="Tags (comma-separated)", hint_text="internet-facing, prod, pci")
    asset_services = ft.TextField(label="Services (comma-separated)", hint_text="80/http, 443/https, 22/ssh")

    assets_list = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO, height=420)

    asset_detail_title = ft.Text("Select an asset to view risk details.", size=16, weight=ft.FontWeight.BOLD)
    asset_detail_body = ft.Column(spacing=8)

    selected_asset_id = {"id": None}

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

            def on_select(e):
                selected_asset_id["id"] = aid
                rebuild_asset_detail()
                page.update()

            return ft.Container(
                content=ft.Row(
                    [
                        ft.Text(a.name, width=260, weight=ft.FontWeight.BOLD),
                        ft.Text(f"Findings: {len(findings)}", width=110),
                        ft.Text(f"Max: {max_score:.1f}", width=90),
                        ft.Text(f"Avg: {avg_score:.1f}", width=90),
                        ft.IconButton(icon=ft.icons.CHEVRON_RIGHT, on_click=on_select),
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                padding=10,
                border=ft.border.all(1, ft.colors.with_opacity(0.12, ft.colors.WHITE)),
                border_radius=14,
            )

        for aid in list(store.assets.keys())[::-1]:
            assets_list.controls.append(mk_row(aid))

        page.update()

    def rebuild_asset_detail():
        aid = selected_asset_id["id"]
        asset_detail_body.controls.clear()

        if not aid or aid not in store.assets:
            asset_detail_title.value = "Select an asset to view risk details."
            page.update()
            return

        a = store.assets[aid]
        asset_detail_title.value = f"Asset: {a.name}"

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

        # Findings table blocks
        finding_cards = ft.Column(spacing=8)
        if not findings:
            finding_cards.controls.append(ft.Text("No findings mapped to this asset yet.", opacity=0.75))
        else:
            # Sort by score desc
            for f in sorted(findings, key=lambda x: x.score, reverse=True):
                vector_short = " ".join([f"{k}:{f.metrics[k]}" for k in METRIC_FIELDS])
                finding_cards.controls.append(
                    ft.Container(
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Text(f.title, expand=True),
                                        ft.Text(f"{f.score:.1f}", width=70, text_align=ft.TextAlign.RIGHT),
                                        pill(f.severity),
                                        ft.IconButton(
                                            icon=ft.icons.DELETE_OUTLINE,
                                            tooltip="Delete finding",
                                            on_click=lambda e, fid=f.id: (store.delete_finding(fid), rebuild_all()),
                                        ),
                                    ],
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                ),
                                ft.Text(vector_short, size=12, opacity=0.75),
                            ],
                            spacing=6,
                        ),
                        padding=10,
                        border=ft.border.all(1, ft.colors.with_opacity(0.12, ft.colors.WHITE)),
                        border_radius=14,
                    )
                )

        def delete_asset():
            store.delete_asset(aid)
            selected_asset_id["id"] = None
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
                                    ft.OutlinedButton("Delete Asset", icon=ft.icons.DELETE, on_click=lambda e: delete_asset()),
                                ],
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

    def add_asset_action(e):
        name = (asset_name.value or "").strip()
        if not name:
            notify("Asset name is required.", "error")
            return
        tags = split_csv_field(asset_tags.value)
        services = split_csv_field(asset_services.value)
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
                                ],
                                spacing=10,
                            ),
                        ),
                    ),
                    ft.Container(
                        col=7,
                        content=info_card("Assets", assets_list),
                    ),
                ]
            ),
            info_card("Asset Details", ft.Column([asset_detail_title, asset_detail_body], spacing=12)),
        ],
        spacing=16,
        scroll=ft.ScrollMode.AUTO,
    )

    # ----------------------------
    # Utility: rebuild everything
    # ----------------------------
    def rebuild_all():
        rebuild_dashboard()
        rebuild_assets_list()
        rebuild_asset_detail()

    # ----------------------------
    # Tabs
    # ----------------------------
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

    # Initial build
    rebuild_all()

ft.app(target=main)
