import flet as ft

def pill(severity: str, score: float | None = None) -> ft.Container:
    """
    Badge pour la sévérité. Affiche un style plus doux et lisible.
    Si `score` est fourni, le texte devient "{score:.1f} {severity}".
    """
    key = (severity or "").strip().lower()

    # Couleurs adoucies (fonds pâles) + bordure légère pour le contraste
    bg_map = {
        "critical": ft.colors.RED_200,
        "high": ft.colors.DEEP_ORANGE_200,
        "medium": ft.colors.AMBER_200,
        "low": ft.colors.BLUE_200,
        "none": ft.colors.GREY_300,
    }
    border_map = {
        "critical": ft.colors.RED_400,
        "high": ft.colors.DEEP_ORANGE_400,
        "medium": ft.colors.AMBER_400,
        "low": ft.colors.BLUE_400,
        "none": ft.colors.GREY_500,
    }

    label = f"{score:.1f} {severity}" if score is not None else severity

    return ft.Container(
        content=ft.Text(label, weight=ft.FontWeight.W_600, size=12, color=ft.colors.BLACK87),
        bgcolor=bg_map.get(key, ft.colors.GREY_300),
        padding=ft.padding.symmetric(horizontal=12, vertical=5),
        border_radius=999,
        border=ft.border.all(1, ft.colors.with_opacity(0.5, border_map.get(key, ft.colors.GREY_500))),
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
        # Mini bordure grise + coins arrondis pour mieux distinguer les cartes
        border=ft.border.all(1, ft.colors.with_opacity(0.35, ft.colors.GREY_500)),
        border_radius=14,
        # Remplacer le blanc pur par un gris très léger (lisible en light/dark)
        bgcolor=ft.colors.with_opacity(0.07, ft.colors.GREY_300),
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
