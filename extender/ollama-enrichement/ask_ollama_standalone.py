"""
ZAP Script: Ask Ollama (Standalone)
Type: Standalone
Description: Interactive Ollama AI assistant tab in ZAP. Enter prompts, stream responses,
             multi-turn conversations, model switching, and send extracted requests to ZAP tools.

Place ollama_common.py in the same directory or ZAP's shared scripts folder.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from ollama_common import (
    chat, list_models, health_check, format_error, security_prompts,
    truncate, build_report_snippet, extract_http_requests,
    DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX, OllamaException
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

class AskOllamaPanel(JPanel):
    """Main panel for the Ask Ollama standalone tab."""

    def __init__(self):
        JPanel.__init__(self, BorderLayout())
        self.base_url = self._load_config("ollama.base_url", DEFAULT_BASE_URL)
        self.model = self._load_config("ollama.model", DEFAULT_MODEL)
        self.timeout = int(self._load_config("ollama.timeout", str(DEFAULT_TIMEOUT)))
        self.num_ctx = int(self._load_config("ollama.num_ctx", str(DEFAULT_NUM_CTX)))
        self.streaming = self._load_config("ollama.streaming", "true") == "true"
        self.system_prompt = self._load_config("ollama.system_prompt", security_prompts()["explain"])
        self._conversation = []  # list of (user, assistant) tuples

        self._build_ui()
        self._refresh_models()

    # ---- Config helpers ----
    def _load_config(self, key, default):
        try:
            from org.parosproxy.paros.model import Model
            opts = Model.getSingleton().getOptionsParam()
            # Use ScriptVars for simpler persistence
            from org.zaproxy.zap.extension.script import ScriptVars
            val = ScriptVars.getGlobalVar(key)
            return val if val else default
        except:
            return default

    def _save_config(self, key, value):
        try:
            from org.zaproxy.zap.extension.script import ScriptVars
            ScriptVars.setGlobalVar(key, str(value))
        except:
            pass

    # ---- UI ----
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
        toolbar.add(JLabel("Model:"))
        self.model_combo = JComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.addItem(self.model)
        self.model_combo.setPreferredSize(Dimension(200, 24))
        toolbar.add(self.model_combo)

        refresh_btn = JButton("Refresh models")
        refresh_btn.addActionListener(lambda e: self._refresh_models())
        toolbar.add(refresh_btn)

        self.streaming_cb = JCheckBox("Stream", self.streaming)
        self.streaming_cb.setToolTipText("Show tokens as they arrive")
        toolbar.add(self.streaming_cb)

        self.ask_btn = JButton("Ask Ollama")
        self.ask_btn.setToolTipText("Send to Ollama (Ctrl+Enter)")
        self.ask_btn.addActionListener(lambda e: self._on_ask())
        toolbar.add(self.ask_btn)

        input_panel.add(toolbar, BorderLayout.SOUTH)

        top = JPanel(BorderLayout())
        top.add(JLabel("Ask Ollama — AI security assistant. Type a question or paste content."), BorderLayout.NORTH)
        top.add(input_panel, BorderLayout.CENTER)

        # --- Response area ---
        response_panel = JPanel(BorderLayout())
        response_panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Response"), EmptyBorder(6, 6, 6, 6)))

        self.loading_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.loading_panel.add(JProgressBar())
        self.loading_panel.add(JLabel("Querying Ollama..."))
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
        self.copy_btn = JButton("Copy")
        self.copy_btn.addActionListener(lambda e: self._on_copy())
        self.copy_btn.setEnabled(False)
        actions.add(self.copy_btn)

        self.copy_report_btn = JButton("Copy as report snippet")
        self.copy_report_btn.addActionListener(lambda e: self._on_copy_report())
        self.copy_report_btn.setEnabled(False)
        actions.add(self.copy_report_btn)

        self.send_repeater_btn = JButton("Send to Req Editor")
        self.send_repeater_btn.setToolTipText("Send detected HTTP requests to manual request editor")
        self.send_repeater_btn.addActionListener(lambda e: self._send_to_requester())
        self.send_repeater_btn.setEnabled(False)
        actions.add(self.send_repeater_btn)

        self.clear_btn = JButton("Clear")
        self.clear_btn.addActionListener(lambda e: self._on_clear())
        actions.add(self.clear_btn)
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
        self.followup_btn.setEnabled(False)
        followup_panel.add(self.followup_btn)
        response_panel.add(followup_panel, BorderLayout.SOUTH)

        # Split
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, response_panel)
        split.setResizeWeight(0.35)
        self.add(split, BorderLayout.CENTER)

        # Keyboard shortcut: Ctrl+Enter
        self.prompt_area.getInputMap(JPanel.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_MASK), "ask")
        self.prompt_area.getActionMap().put("ask", AbstractAction(actionPerformed=lambda e: self._on_ask()))

        self.followup_field.getInputMap(JPanel.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_MASK), "followup")
        self.followup_field.getActionMap().put("followup", AbstractAction(actionPerformed=lambda e: self._on_followup()))

    # ---- Actions ----
    def _refresh_models(self):
        def run():
            try:
                models = list_models(self.base_url, self.timeout)
                SwingUtilities.invokeLater(lambda: self._update_model_combo(models))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.response_area.setText(
                    format_error(e, self.base_url, self.model)))
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
        editor = self.model_combo.getEditor()
        return str(editor.getItem()).strip() if self.model_combo.isEditable() else str(self.model_combo.getSelectedItem()).strip()

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
        model = self._get_model() or self.model
        self._save_config("ollama.model", model)
        self._model = model

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
                    self._do_streaming_chat(model, user_msg)
                else:
                    self._do_sync_chat(model, user_msg)
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self._show_error(e, model))

        threading.Thread(target=run, daemon=True).start()

    def _do_sync_chat(self, model, user_msg):
        result = chat(model, self.system_prompt, user_msg, self.base_url,
                      self.timeout, self.num_ctx, stream=False)
        def update():
            usage = ""
            if result.prompt_tokens is not None and result.eval_tokens is not None:
                usage = "\n\n---\nTokens: {} in, {} out".format(result.prompt_tokens, result.eval_tokens)
            self.response_area.text = result.content + usage
            self._conversation.append(("assistant", result.content))
            self._on_done()
        SwingUtilities.invokeLater(update)

    def _do_streaming_chat(self, model, user_msg):
        buf = []
        def on_chunk(chunk):
            buf.append(chunk)
            def update():
                self.response_area.append(chunk)
            SwingUtilities.invokeLater(update)

        chat(model, self.system_prompt, user_msg, self.base_url,
             self.timeout, self.num_ctx, stream=True, on_chunk=on_chunk)
        content = ''.join(buf)
        self._conversation.append(("assistant", content))
        SwingUtilities.invokeLater(self._on_done)

    def _on_done(self):
        self.loading_panel.setVisible(False)
        self.ask_btn.setEnabled(True)
        self.followup_btn.setEnabled(True)
        self.copy_btn.setEnabled(True)
        self.copy_report_btn.setEnabled(True)
        self._update_send_buttons()
        self.followup_field.text = ""

    def _show_error(self, error, model):
        self.loading_panel.setVisible(False)
        self.ask_btn.setEnabled(True)
        self.followup_btn.setEnabled(True)
        self.response_area.text = format_error(error, self.base_url, model)

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
        self.copy_btn.setEnabled(False)
        self.copy_report_btn.setEnabled(False)
        self.send_repeater_btn.setEnabled(False)

    def _update_send_buttons(self):
        requests = extract_http_requests(self.response_area.text)
        self.send_repeater_btn.setEnabled(len(requests) > 0)

    def _send_to_requester(self):
        requests = extract_http_requests(self.response_area.text)
        if not requests:
            return
        try:
            from org.zaproxy.zap.extension.httppanel import HttpPanelRequest
            from org.parosproxy.paros.network import HttpRequestHeader
            extScript = Model.getSingleton().getExtensionLoader().getExtension(
                org.zaproxy.zap.extension.httppanel.ExtensionHttpPanel)
            if extScript:
                for i, raw in enumerate(requests):
                    try:
                        # Build HttpMessage from raw request
                        msg = org.parosproxy.paros.network.HttpMessage()
                        req_header = HttpRequestHeader(raw)
                        msg.setRequestHeader(req_header)
                        extScript.addHttpMessage(msg)
                    except:
                        pass
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error sending to request editor: {}".format(str(e)))

# ---- ZAP Extension Entry Point ----
class AskOllamaExtension(ExtensionAdaptor):
    """ZAP extension that adds an 'Ask Ollama' tab."""

    def getName(self):
        return "AskOllama"

    def getUIName(self):
        return "Ask Ollama"

    def getDescription(self):
        return "AI-powered security analysis using local Ollama models"

    def init(self):
        ExtensionAdaptor.init(self)
        self.panel = AskOllamaPanel()

    def getMainPanel(self):
        return self.panel

# Standalone script entry: register the extension
def install():
    """Called by ZAP when loading this standalone script."""
    try:
        ext = AskOllamaExtension()
        from org.parosproxy.paros.model import Model
        Model.getSingleton().getExtensionLoader().addExtension(ext)
        print("[Ask Ollama] Extension loaded. Use the 'Ask Ollama' tab.")
    except Exception as e:
        print("[Ask Ollama] Failed to load: {}".format(str(e)))

def uninstall():
    print("[Ask Ollama] Extension unloaded.")
