"""Design tokens. Dark is primary; light is for report export."""
DARK = {
    "bg_base":     "#070B14",
    "bg_surface":  "#0E1626",
    "bg_elevated": "#162034",
    "border":      "#243352",
    "text":        "#E6EDF7",
    "muted":       "#8FA3C4",
    "info":        "#3B82F6",
    "low":         "#22D3EE",
    "medium":      "#F5B301",
    "high":        "#FF7A45",
    "critical":    "#FF3B5C",
    "nominal":     "#7CF29A",
    "brand":       "#8B5CF6",
    "brand_2":     "#22D3EE",
}

LIGHT = {
    "bg_base":     "#FFFFFF",
    "bg_surface":  "#F7F9FC",
    "bg_elevated": "#EEF2F8",
    "border":      "#DCE3EF",
    "text":        "#0F172A",
    "muted":       "#5B6B84",
    "info":        "#2563EB",
    "low":         "#0891B2",
    "medium":      "#B45309",
    "high":        "#EA580C",
    "critical":    "#DC2626",
    "nominal":     "#16A34A",
    "brand":       "#7C3AED",
    "brand_2":     "#0891B2",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]