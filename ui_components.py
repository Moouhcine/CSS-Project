import flet as ft

def pill(text: str) -> ft.Container:
    key = text.lower()
    # Flet comes with theme colors; keep it simple and readable.
    bg_map = {
        "critical": ft.colors.RED_400,
        "high": ft.colors.DEEP_ORANGE_300,
        "medium": ft.colors.AMBER_300,
        "low": ft.colors.BLUE_300,
        "none": ft.colors.GREY_400,
    }
    return ft.Container(
        content=ft.Text(text, weight=ft.FontWeight.W_600, size=12),
        bgcolor=bg_map.get(key, ft.colors.GREY_400),
        padding=ft.padding.symmetric(horizontal=10, vertical=4),
        border_radius=999,
    )

def section_title(text: str) -> ft.Row:
    return ft.Row(
        [ft.Text(text, size=18, weight=ft.FontWeight.BOLD)],
        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
    )

def info_card(title: str, content: ft.Control) -> ft.Container:
    return ft.Container(
        content=ft.Column([ft.Text(title, weight=ft.FontWeight.BOLD), content], spacing=10),
        padding=16,
        border=ft.border.all(1, ft.colors.with_opacity(0.15, ft.colors.WHITE)),
        border_radius=16,
        bgcolor=ft.colors.with_opacity(0.04, ft.colors.WHITE),
    )

def toast_bar(msg: str, kind: str = "info") -> ft.SnackBar:
    color = {
        "info": ft.colors.BLUE_300,
        "success": ft.colors.GREEN_300,
        "error": ft.colors.RED_300,
        "warning": ft.colors.AMBER_300,
    }.get(kind, ft.colors.BLUE_300)

    return ft.SnackBar(
        content=ft.Text(msg),
        bgcolor=ft.colors.with_opacity(0.15, color),
        show_close_icon=True,
    )
