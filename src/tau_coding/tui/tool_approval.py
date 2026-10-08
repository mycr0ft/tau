"""Accessible Textual adapter for Tau-owned per-call approval requests."""

from __future__ import annotations

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Vertical
from textual.events import Key
from textual.screen import ModalScreen
from textual.widgets import Label, ListItem, ListView, Static

from tau_coding.tool_approval import ApprovalChoice, ApprovalRequest

_LABELS: tuple[tuple[ApprovalChoice, str], ...] = (
    ("allow-once", "Allow this call"),
    ("allow-run", "Allow this tool for this run"),
    ("allow-save", "Allow and save rule for this path"),
    ("deny-once", "Deny this call"),
    ("deny-save", "Deny and save rule for this path"),
)

_CLASS_WORDS: dict[str, str] = {
    "readonly": "read-only file access",
    "writes": "file write",
    "command": "shell command",
    "network": "network access",
    "device": "smart-card / security-token access",
    "exfil-capable": "outbound data transfer",
    "unknown": "unrecognized call",
}


def _choice_labels(request: ApprovalRequest) -> tuple[tuple[ApprovalChoice, str], ...]:
    wanted = set(request.choices)
    return tuple((choice, label) for choice, label in _LABELS if choice in wanted)


class ToolApprovalScreen(ModalScreen[ApprovalChoice | None]):
    """Tau-style modal picker rendering one policy-owned approval request."""

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel"),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
        Binding("enter", "select_cursor", "Select", show=False),
    ]
    DEFAULT_CSS = """
    ToolApprovalScreen {
        align: center middle;
        background: #000000 70%;
    }
    #tool-approval-dialog {
        width: 76;
        max-width: 92%;
        height: auto;
        max-height: 90%;
        padding: 1 2;
        background: #000000;
        color: #d8dee9;
        border: tall #141922;
    }
    #tool-approval-title {
        height: 1;
        text-style: bold;
        margin-bottom: 1;
    }
    #tool-approval-tool-label,
    #tool-approval-class-label,
    #tool-approval-summary-label {
        height: 1;
        color: #667085;
    }
    #tool-approval-tool,
    #tool-approval-summary,
    #tool-approval-reasons,
    #tool-approval-boundary {
        height: auto;
        margin-bottom: 1;
    }
    #tool-approval-reasons {
        color: #d08770;
    }
    #tool-approval-boundary {
        color: #667085;
    }
    #tool-approval-list {
        height: auto;
        max-height: 7;
        background: #000000;
        color: #d8dee9;
        border: tall #141922;
    }
    #tool-approval-list ListItem.-highlight,
    #tool-approval-list ListItem.-highlight Label {
        background: #a7f3f0;
        color: #061a1a;
    }
    #tool-approval-help {
        height: 1;
        margin-top: 1;
        color: #667085;
    }
    """

    def __init__(
        self, request: ApprovalRequest, *, cancel_action: str = "denies this call"
    ) -> None:
        super().__init__()
        self.request = request
        self.cancel_action = cancel_action

    def compose(self) -> ComposeResult:
        risk = self.request.risk
        reason_text = "\n".join(f"• {reason}" for reason in risk.reasons) or "—"
        choices = [
            ListItem(
                Label(label, markup=False),
                id=f"approval-{choice}".replace("_", "-"),
                name=choice,
                classes="tool-approval-choice",
            )
            for choice, label in _choice_labels(self.request)
        ]
        with Vertical(id="tool-approval-dialog"):
            yield Static("Tool call requires approval", id="tool-approval-title")
            yield Static("Tool", id="tool-approval-tool-label")
            yield Static(self.request.tool, id="tool-approval-tool", markup=False)
            yield Static("Assessment", id="tool-approval-class-label")
            yield Static(
                f"{_CLASS_WORDS.get(risk.classification, risk.classification)}"
                + (" — sensitive, never auto-allowed" if risk.sensitive else ""),
                id="tool-approval-summary",
                markup=False,
            )
            yield Static(
                f"{self.request.summary}\n{reason_text}",
                id="tool-approval-reasons",
                markup=False,
            )
            yield Static(
                "This gate asks before acting; it is not a sandbox.",
                id="tool-approval-boundary",
            )
            yield ListView(*choices, id="tool-approval-list")
            yield Static(
                f"↑/↓ choose · Enter selects · Escape {self.cancel_action}",
                id="tool-approval-help",
            )

    def on_mount(self) -> None:
        """Focus the first explicit action for keyboard users."""
        choices = self.query_one("#tool-approval-list", ListView)
        choices.index = 0
        choices.focus()

    def on_key(self, event: Key) -> None:
        """Keep navigation local when hosted by Tau's globally bound app."""
        if event.key == "up":
            event.stop()
            self.action_cursor_up()
        elif event.key == "down":
            event.stop()
            self.action_cursor_down()
        elif event.key == "enter":
            event.stop()
            self.action_select_cursor()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        choice = event.item.name
        if choice is not None:
            self.dismiss(choice)  # type: ignore[arg-type]

    def action_cursor_up(self) -> None:
        self.query_one("#tool-approval-list", ListView).action_cursor_up()

    def action_cursor_down(self) -> None:
        self.query_one("#tool-approval-list", ListView).action_cursor_down()

    def action_select_cursor(self) -> None:
        self.query_one("#tool-approval-list", ListView).action_select_cursor()

    def action_cancel(self) -> None:
        self.dismiss(None)


class _ToolApprovalApp(App[ApprovalChoice | None]):
    def __init__(self, request: ApprovalRequest) -> None:
        super().__init__()
        from tau_coding.tui.themes import TAU_DARK_THEME, textual_theme_for_tui_theme

        tau_dark = textual_theme_for_tui_theme(TAU_DARK_THEME.name)
        self.register_theme(tau_dark)
        self.theme = tau_dark.name
        self.request = request

    def on_mount(self) -> None:
        self.push_screen(
            ToolApprovalScreen(self.request, cancel_action="denies this call"),
            self.exit,
        )


async def prompt_tool_approval(request: ApprovalRequest) -> ApprovalChoice | None:
    """Run the frontend adapter and return the Tau approval choice."""
    return await _ToolApprovalApp(request).run_async()
