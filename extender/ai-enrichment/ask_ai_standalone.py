# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ZAP Script: Ask AI (Standalone)
Type: Standalone
Description: Interactive AI assistant tab in ZAP. Supports Ollama (local) and OpenRouter (cloud).
             Enter prompts, stream responses, multi-turn conversations, model/provider switching,
             and send extracted requests to ZAP tools.

Depends on: ai_common.py in same directory.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from ai_common import (
    chat, list_models, health_check, format_error, security_prompts,
    truncate, build_report_snippet, extract_http_requests,
    AiConfig, ChatResult, AiException,
    OLLAMA_BASE_URL, OPENROUTER_BASE_URL,
    DEFAULT_SERVICE, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)
from javax.swing import (
    JPanel, JFrame, JTextArea, JButton, JComboBox, JLabel, JScrollPane,
    JProgressBar, JTabbedPane, JCheckBox, JSplitPane, JOptionPane,
    SwingUtilities, BorderFactory, BoxLayout, KeyStroke, AbstractAction,
    JToolBar, JMenuItem, JPopupMenu
)
from javax.swing.border import EmptyBorder, TitledBorder, EtchedBorder, CompoundBorder
from java.awt import BorderLayout, FlowLayout, Dimension, Insets, Font, Toolkit, Color
from java.awt.datatransfer import StringSelection
from java.awt.event import KeyEvent, ActionListener
from java.lang import Runnable
from org.parosproxy.paros.view import View
from org.parosproxy.paros.extension import ExtensionAdaptor
from org.parosproxy.paros.model import Model
from org.zaproxy.zap.extension.httppanel import HttpPanelRequest
from org.zaproxy.zap import ZapAddOn
import threading

class AiPanel(JPanel):
    """Main panel for the Ask AI standalone tab."""

    def __init__(self):
        JPanel.__init__(self, BorderLayout())
        self._load_config()
        self._provider_config = AiConfig(
            service=self.service, base_url=self.base_url, api_key=self.api_key,
            model=self.model, timeout=self.timeout, num_ctx=self.num_ctx
        )
        self._conversation = []
        self._build_ui()
        self._refresh_models()

    def _load_config(self):
        from org.zaproxy.zap.extension.script import ScriptVars
        def cfg(key, default):
            try:
                val = ScriptVars.getGlobalVar("ai.{}".format(key))
                return val if val else default
            except:
                return default
        self.service = cfg("service", DEFAULT_SERVICE)
        self.base_url = cfg("base_url", OLLAMA_BASE_URL if self.service == "ollama" else OPENROUTER_BASE_URL)
        self.api_key = cfg("api_key", "")
        self.model = cfg("model", DEFAULT_MODEL)
        self.timeout = int(cfg("timeout", str(DEFAULT_TIMEOUT)))
        self.num_ctx = int(cfg("num_ctx", str(DEFAULT_NUM_CTX)))
        self.streaming = cfg("streaming", "true") == "true"
        self.system_prompt = cfg("system_prompt", security_prompts()["explain"])

    def _save_config(self, key, value):
        try:
            from org.zaproxy.zap.extension.script import ScriptVars
            ScriptVars.setGlobalVar("ai.{}".format(key), str(value))
        except:
            pass

    def _build_ui(self):
        self.setBorder(EmptyBorder(10, 10, 10, 10))

        # --- Input area ---
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Your message (Ctrl+Enter to send)"),
            EmptyBorder(8, 8, 8, 8)))

        self.prompt_area = JTextArea(4, 60)
        self.prompt_area.lineWrap = True
        self.prompt_area.wrapStyleWord = True
        self.prompt_area.margin = Insets(8, 8, 8, 8)
        input_panel.add(JScrollPane(self.prompt_area), BorderLayout.CENTER)

        # Toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))

        toolbar.add(JLabel("Service:"))
        self.service_combo = JComboBox(["ollama", "openrouter"])
        self.service_combo.setSelectedItem(self.service)
        self.service_combo.setPreferredSize(Dimension(110, 24))
        self.service_combo.addActionListener(lambda e: self._on_service_change())
        toolbar.add(self.service_combo)

        self.api_key_label = JLabel("Key:")
        self.api_key_field = JTextField(18)
        self.api_key_field.setText(self.api_key)
        toolbar.add(self.api_key_label)
        toolbar.add(self.api_key_field)

        toolbar.add(JLabel("Model:"))
        self.model_combo = JComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.addItem(self.model)
        self.model_combo.setPreferredSize(Dimension(200, 24))
        toolbar.add(self.model_combo)

        refresh_btn = JButton("Refresh")
        refresh_btn.addActionListener(lambda e: self._refresh_models())
        toolbar.add(refresh_btn)

        self.streaming_cb = JCheckBox("Stream", self.streaming)
        toolbar.add(self.streaming_cb)

        self.ask_btn = JButton("Ask AI")
        self.ask_btn.addActionListener(lambda e: self._on_ask())
        toolbar.add(self.ask_btn)

        input_panel.add(toolbar, BorderLayout.SOUTH)

        top = JPanel(BorderLayout())
        top.add(JLabel("Ask AI — AI-powered security assistant (Ollama or OpenRouter). Type a question or paste content."), BorderLayout.NORTH)
        top.add(input_panel, BorderLayout.CENTER)

        # --- Response area ---
        response_panel = JPanel(BorderLayout())
        response_panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Response"), EmptyBorder(6, 6, 6, 6)))

        self.loading_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.loading_panel.add(JProgressBar())
        self.loading_panel.add(JLabel("Querying AI..."))
        self.loading_panel.setVisible(False)
        response_panel.add(self.loading_panel, BorderLayout.NORTH)

        self.response_area = JTextArea(15, 60)
        self.response_area.setEditable(False)
        self.response_area.lineWrap = True
        self.response_area.wrapStyleWord = True
        self.response_area.margin = Insets(8, 8, 8, 8)
        response_panel.add(JScrollPane(self.response_area), BorderLayout.CENTER)

        # Action buttons
        actions = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        copy_btn = JButton("Copy")
        copy_btn.addActionListener(lambda e: self._on_copy())
        actions.add(copy_btn)

        copy_report_btn = JButton("Copy as report snippet")
        copy_report_btn.addActionListener(lambda e: self._on_copy_report())
        actions.add(copy_report_btn)

        send_repeater_btn = JButton("Send to Req Editor")
        send_repeater_btn.setToolTipText("Send detected HTTP requests to manual request editor")
        send_repeater_btn.addActionListener(lambda e: self._send_to_requester())
        actions.add(send_repeater_btn)

        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._on_clear())
        actions.add(clear_btn)
        response_panel.add(actions, BorderLayout.SOUTH)

        # Follow-up
        followup_panel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        followup_panel.add(JLabel("Follow-up:"))
        self.followup_field = JTextArea(1, 40)
        self.followup_field.lineWrap = True
        self.followup_field.wrapStyleWord = True
        self.followup_field.setPreferredSize(Dimension(400, 24))
        followup_panel.add(JScrollPane(self.followup_field))
        self.followup_btn = JButton("Send")
        self.followup_btn.addActionListener(lambda e: self._on_followup())
        followup_panel.add(self.followup_btn)
        response_panel.add(followup_panel, BorderLayout.SOUTH)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, response_panel)
        split.setResizeWeight(0.35)
        self.add(split, BorderLayout.CENTER)

        # Hotkeys
        self.prompt_area.getInputMap(JPanel.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_MASK), "ask")
        self.prompt_area.getActionMap().put("ask", AbstractAction(actionPerformed=lambda e: self._on_ask()))

        self.followup_field.getInputMap(JPanel.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_MASK), "followup")
        self.followup_field.getActionMap().put("followup", AbstractAction(actionPerformed=lambda e: self._on_followup()))

        self._update_api_key_visibility()

    def _on_service_change(self):
        svc = str(self.service_combo.getSelectedItem())
        self._update_api_key_visibility()
        if svc == "openrouter" and not self.api_key_field.text.strip():
            self.response_area.text = "OpenRouter requires an API key. Paste it in the 'Key' field above."
        self._refresh_models()

    def _update_api_key_visibility(self):
        svc = str(self.service_combo.getSelectedItem())
        self.api_key_label.setVisible(svc == "openrouter")
        self.api_key_field.setVisible(svc == "openrouter")

    def _build_config(self):
        svc = str(self.service_combo.getSelectedItem())
        key = self.api_key_field.text.strip()
        model = self._get_model()
        if svc == "openrouter" and not key:
            return None
        return AiConfig(
            service=svc,
            base_url=self.base_url if svc == self.service else None,
            api_key=key,
            model=model,
            timeout=self.timeout,
            num_ctx=self.num_ctx
        )

    def _refresh_models(self):
        def run():
            try:
                svc = str(self.service_combo.getSelectedItem())
                key = self.api_key_field.text.strip()
                if svc == "openrouter" and not key:
                    return
                cfg = self._build_config()
                if not cfg:
                    return
                models = list_models(config=cfg)
                SwingUtilities.invokeLater(lambda: self._update_model_combo(models))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.response_area.setText(
                    format_error(e, self._build_config() or AiConfig())))
        threading.Thread(target=run, daemon=True).start()

    def _update_model_combo(self, models):
        current = self.model_combo.getEditor().getItem() if self.model_combo.isEditable() else self.model_combo.getSelectedItem()
        self.model_combo.removeAllItems()
        if current and str(current).strip():
            self.model_combo.addItem(str(current).strip())
        for m in models:
            if m != str(current or '').strip():
                self.model_combo.addItem(m)

    def _get_model(self):
        return str(self.model_combo.getEditor().getItem()).strip() if self.model_combo.isEditable() else str(self.model_combo.getSelectedItem()).strip()

    def _on_ask(self):
        user_msg = self.prompt_area.text.strip()
        if not user_msg:
            return
        self._do_chat(user_msg)

    def _on_followup(self):
        user_msg = self.followup_field.text.strip()
        if not user_msg:
            return
        self._do_chat(user_msg, is_followup=True)

    def _do_chat(self, user_msg, is_followup=False):
        cfg = self._build_config()
        if not cfg:
            JOptionPane.showMessageDialog(self, "OpenRouter requires an API key.")
            return

        self._save_config("service", cfg.service)
        self._save_config("model", cfg.model)
        if cfg.api_key:
            self._save_config("api_key", cfg.api_key)

        self.ask_btn.setEnabled(False)
        self.followup_btn.setEnabled(False)
        self.loading_panel.setVisible(True)

        if not is_followup:
            self._conversation = []
            self.response_area.text = ""

        self._conversation.append(("user", user_msg))

        def run():
            try:
                if self.streaming_cb.isSelected():
                    buf = []
                    def on_chunk(chunk):
                        buf.append(chunk)
                        SwingUtilities.invokeLater(lambda: self.response_area.append(chunk))
                    chat(cfg.model, self.system_prompt, user_msg, config=cfg,
                         stream=True, on_chunk=on_chunk)
                    self._conversation.append(("assistant", ''.join(buf)))
                else:
                    result = chat(cfg.model, self.system_prompt, user_msg, config=cfg)
                    def update():
                        self.response_area.text = result.content
                    SwingUtilities.invokeLater(update)
                    self._conversation.append(("assistant", result.content))
                SwingUtilities.invokeLater(self._on_done)
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self._show_error(e, cfg))
        threading.Thread(target=run, daemon=True).start()

    def _on_done(self):
        self.loading_panel.setVisible(False)
        self.ask_btn.setEnabled(True)
        self.followup_btn.setEnabled(True)
        self.followup_field.text = ""

    def _show_error(self, error, cfg):
        self.loading_panel.setVisible(False)
        self.ask_btn.setEnabled(True)
        self.followup_btn.setEnabled(True)
        self.response_area.text = format_error(error, cfg)

    def _on_copy(self):
        text = self.response_area.text
        if text:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)

    def _on_copy_report(self):
        text = build_report_snippet(self.response_area.text)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)

    def _on_clear(self):
        self.response_area.text = ""
        self._conversation = []

    def _send_to_requester(self):
        requests = extract_http_requests(self.response_area.text)
        if not requests:
            JOptionPane.showMessageDialog(self, "No HTTP requests found in response.")
            return
        try:
            from org.zaproxy.zap.extension.httppanel import HttpPanelRequest
            from org.parosproxy.paros.network import HttpRequestHeader
            extScript = Model.getSingleton().getExtensionLoader().getExtension(
                org.zaproxy.zap.extension.httppanel.ExtensionHttpPanel)
            if extScript:
                for raw in requests:
                    try:
                        msg = org.parosproxy.paros.network.HttpMessage()
                        msg.setRequestHeader(HttpRequestHeader(raw))
                        extScript.addHttpMessage(msg)
                    except:
                        pass
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error: {}".format(str(e)))


# ---- ZAP Extension Entry Point ----
class AskAiExtension(ExtensionAdaptor):
    """ZAP extension that adds an 'Ask AI' tab."""

    def getName(self):
        return "AskAi"

    def getUIName(self):
        return "Ask AI"

    def getDescription(self):
        return "AI-powered security analysis using Ollama (local) or OpenRouter (cloud)"

    def init(self):
        ExtensionAdaptor.init(self)
        self.panel = AiPanel()

    def getMainPanel(self):
        return self.panel


def install():
    """Called by ZAP when loading this standalone script."""
    try:
        ext = AskAiExtension()
        from org.parosproxy.paros.model import Model
        Model.getSingleton().getExtensionLoader().addExtension(ext)
        print("[Ask AI] Extension loaded. Use the 'Ask AI' tab.")
    except Exception as e:
        print("[Ask AI] Failed to load: {}".format(str(e)))

def uninstall():
    print("[Ask AI] Extension unloaded.")
