# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ZAP Script: Ask AI Enhanced (Standalone)
Type: Standalone
Description: Enhanced AI assistant with provider selection (Ollama/OpenRouter), streaming,
             multi-model comparison, auto-triage, CWE mapping, report generation, and
             executive summaries.

Depends on: ai_common.py, ai_common_enhanced.py in same directory.
"""
import sys, os
sys.path.append(os.path.dirname(__file__))

from ai_common import (
    chat, list_models, health_check, format_error, truncate, extract_http_requests,
    AiConfig, ChatResult, AiException,
    OLLAMA_BASE_URL, OPENROUTER_BASE_URL, DEFAULT_SERVICE, DEFAULT_MODEL,
    DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)
from ai_common_enhanced import (
    MultiModelChat, ModelRegistry, PROMPT_TEMPLATES, list_templates,
    auto_triage, map_cwe, generate_report, executive_summary
)
from javax.swing import (
    JPanel, JFrame, JTextArea, JButton, JComboBox, JLabel, JScrollPane,
    JProgressBar, JTabbedPane, JCheckBox, JSplitPane, JOptionPane,
    SwingUtilities, BorderFactory, BoxLayout, KeyStroke, AbstractAction,
    JToolBar, JMenuItem, JPopupMenu, JList, DefaultListModel, ListSelectionModel,
    JTextField, JDialog
)
from javax.swing.border import EmptyBorder, TitledBorder, EtchedBorder, CompoundBorder
from java.awt import BorderLayout, FlowLayout, Dimension, Insets, Font, Toolkit, Color, GridBagLayout, GridBagConstraints
from java.awt.datatransfer import StringSelection
from java.awt.event import KeyEvent, ActionListener
from java.lang import Runnable
from org.parosproxy.paros.view import View
from org.parosproxy.paros.extension import ExtensionAdaptor
from org.parosproxy.paros.model import Model
from org.zaproxy.zap.extension.script import ScriptVars
import threading

# ---- Config helpers ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ai_enh.{}".format(key))
        return val if val else default
    except:
        return default

def _set_cfg(key, value):
    try:
        ScriptVars.setGlobalVar("ai_enh.{}".format(key), str(value))
    except:
        pass

# ---- Main Panel ----
class EnhancedAiPanel(JPanel):
    def __init__(self):
        JPanel.__init__(self, BorderLayout())
        svc = _cfg("service", DEFAULT_SERVICE)
        self.config = AiConfig(
            service=svc,
            base_url=_cfg("base_url", OLLAMA_BASE_URL if svc == "ollama" else OPENROUTER_BASE_URL),
            api_key=_cfg("api_key", ""),
            model=_cfg("model", DEFAULT_MODEL),
            timeout=int(_cfg("timeout", str(DEFAULT_TIMEOUT))),
            num_ctx=int(_cfg("num_ctx", str(DEFAULT_NUM_CTX))),
        )
        self.streaming = _cfg("streaming", "true") == "true"
        self.registry = ModelRegistry(self.config)
        self.multi_model = MultiModelChat(self.config)
        self._conversation = []
        self._collected_findings = []
        self._build_ui()
        self._refresh_models()

    def _build_ui(self):
        self.setBorder(EmptyBorder(10, 10, 10, 10))
        tabs = JTabbedPane()
        tabs.addTab("Chat", self._build_chat_tab())
        tabs.addTab("Compare Models", self._build_compare_tab())
        tabs.addTab("Auto-Triage", self._build_triage_tab())
        tabs.addTab("Report", self._build_report_tab())
        self.add(tabs, BorderLayout.CENTER)

    # ==== Config bar (shared across tabs) ====
    def _build_config_bar(self):
        bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        bar.add(JLabel("Service:"))
        self.service_combo = JComboBox(["ollama", "openrouter"])
        self.service_combo.setSelectedItem(self.config.service)
        self.service_combo.setPreferredSize(Dimension(100, 22))
        self.service_combo.addActionListener(lambda e: self._on_config_change())
        bar.add(self.service_combo)

        self.api_key_label = JLabel("Key:")
        self.api_key_field = JTextField(15)
        self.api_key_field.setText(self.config.api_key)
        bar.add(self.api_key_label)
        bar.add(self.api_key_field)
        return bar

    def _on_config_change(self):
        svc = str(self.service_combo.getSelectedItem())
        self.api_key_label.setVisible(svc == "openrouter")
        self.api_key_field.setVisible(svc == "openrouter")
        self._save_service_config()

    def _save_service_config(self):
        cfg = self._gather_config()
        if cfg:
            self.config = cfg
            self.registry.config = cfg
            self.multi_model.config = cfg
            _set_cfg("service", cfg.service)
            _set_cfg("base_url", cfg.base_url)
            if cfg.api_key:
                _set_cfg("api_key", cfg.api_key)

    def _gather_config(self):
        svc = str(self.service_combo.getSelectedItem())
        key = self.api_key_field.text.strip()
        model = self._get_model()
        if svc == "openrouter" and not key:
            return None
        return AiConfig(
            service=svc,
            api_key=key,
            model=model,
            timeout=self.config.timeout,
            num_ctx=self.config.num_ctx
        )

    # ==== Chat Tab ====
    def _build_chat_tab(self):
        panel = JPanel(BorderLayout())

        self.prompt_area = JTextArea(4, 60)
        self.prompt_area.lineWrap = True
        self.prompt_area.wrapStyleWord = True
        self.prompt_area.margin = Insets(8, 8, 8, 8)
        input_panel = JPanel(BorderLayout())
        input_panel.setBorder(CompoundBorder(
            TitledBorder(EtchedBorder(), "Your message (Ctrl+Enter)"),
            EmptyBorder(8, 8, 8, 8)))
        input_panel.add(JScrollPane(self.prompt_area), BorderLayout.CENTER)

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        toolbar.add(JLabel("Model:"))
        self.model_combo = JComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.addItem(self.config.model)
        self.model_combo.setPreferredSize(Dimension(200, 24))
        toolbar.add(self.model_combo)

        toolbar.add(JLabel("Template:"))
        self.template_combo = JComboBox()
        for name, tmpl in sorted(PROMPT_TEMPLATES.items()):
            self.template_combo.addItem("{} ({})".format(tmpl["name"], tmpl["category"]))
        self.template_combo.setPreferredSize(Dimension(200, 24))
        toolbar.add(self.template_combo)

        refresh_btn = JButton("Refresh")
        refresh_btn.addActionListener(lambda e: self._refresh_models())
        toolbar.add(refresh_btn)

        # Config bar
        config_bar = self._build_config_bar()
        self.streaming_cb = JCheckBox("Stream", self.streaming)
        config_bar.add(self.streaming_cb)

        self.ask_btn = JButton("Ask AI")
        self.ask_btn.addActionListener(lambda e: self._on_ask())
        config_bar.add(self.ask_btn)
        input_panel.add(config_bar, BorderLayout.SOUTH)
        input_panel.add(toolbar, BorderLayout.NORTH)

        # Response
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

        actions = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        copy_btn = JButton("Copy")
        copy_btn.addActionListener(lambda e: self._copy_response())
        actions.add(copy_btn)

        add_to_report_btn = JButton("Add to Report")
        add_to_report_btn.addActionListener(lambda e: self._add_to_report())
        actions.add(add_to_report_btn)

        send_btn = JButton("Send to Req Editor")
        send_btn.addActionListener(lambda e: self._send_to_requester())
        actions.add(send_btn)

        clear_btn = JButton("Clear")
        clear_btn.addActionListener(lambda e: self._clear())
        actions.add(clear_btn)
        response_panel.add(actions, BorderLayout.SOUTH)

        followup_p = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        followup_p.add(JLabel("Follow-up:"))
        self.followup_field = JTextArea(1, 40)
        self.followup_field.lineWrap = True
        self.followup_field.wrapStyleWord = True
        self.followup_field.setPreferredSize(Dimension(400, 24))
        followup_p.add(JScrollPane(self.followup_field))
        self.followup_btn = JButton("Send")
        self.followup_btn.addActionListener(lambda e: self._on_followup())
        followup_p.add(self.followup_btn)
        response_panel.add(followup_p, BorderLayout.SOUTH)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, input_panel, response_panel)
        split.setResizeWeight(0.35)
        panel.add(split, BorderLayout.CENTER)

        self.prompt_area.getInputMap(JPanel.WHEN_FOCUSED).put(
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_MASK), "ask")
        self.prompt_area.getActionMap().put("ask", AbstractAction(actionPerformed=lambda e: self._on_ask()))

        self._update_api_key_visibility()
        return panel

    def _update_api_key_visibility(self):
        svc = str(self.service_combo.getSelectedItem())
        self.api_key_label.setVisible(svc == "openrouter")
        self.api_key_field.setVisible(svc == "openrouter")

    # ==== Compare Tab ====
    def _build_compare_tab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(8, 8, 8, 8))

        top = JPanel(BorderLayout())
        top.setBorder(CompoundBorder(TitledBorder(EtchedBorder(), "Prompt"), EmptyBorder(6, 6, 6, 6)))

        self.compare_prompt = JTextArea(3, 50)
        self.compare_prompt.lineWrap = True
        self.compare_prompt.wrapStyleWord = True
        top.add(JScrollPane(self.compare_prompt), BorderLayout.CENTER)

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        toolbar.add(JLabel("Select 2+ models:"))
        self.compare_model_list = JList()
        self.compare_model_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.compare_model_list.setVisibleRowCount(4)
        toolbar.add(JScrollPane(self.compare_model_list))
        compare_btn = JButton("Compare")
        compare_btn.addActionListener(lambda e: self._do_compare())
        toolbar.add(compare_btn)
        top.add(toolbar, BorderLayout.SOUTH)

        self.compare_results = JTextArea(10, 50)
        self.compare_results.setEditable(False)
        self.compare_results.lineWrap = True
        self.compare_results.wrapStyleWord = True
        bot = JScrollPane(self.compare_results)
        bot.setBorder(CompoundBorder(TitledBorder(EtchedBorder(), "Results"), EmptyBorder(6, 6, 6, 6)))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bot)
        split.setResizeWeight(0.35)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # ==== Triage Tab ====
    def _build_triage_tab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(8, 8, 8, 8))

        top = JPanel(BorderLayout())
        top.setBorder(CompoundBorder(TitledBorder(EtchedBorder(), "Alert/Finding Text"), EmptyBorder(6, 6, 6, 6)))
        self.triage_text = JTextArea(8, 50)
        self.triage_text.lineWrap = True
        self.triage_text.wrapStyleWord = True
        top.add(JScrollPane(self.triage_text), BorderLayout.CENTER)

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        triage_btn = JButton("Auto-Triage")
        triage_btn.addActionListener(lambda e: self._do_triage())
        toolbar.add(triage_btn)
        cwe_btn = JButton("Map CWE")
        cwe_btn.addActionListener(lambda e: self._do_cwe())
        toolbar.add(cwe_btn)
        summary_btn = JButton("Executive Summary")
        summary_btn.addActionListener(lambda e: self._do_exec_summary())
        toolbar.add(summary_btn)
        top.add(toolbar, BorderLayout.SOUTH)

        self.triage_results = JTextArea(10, 50)
        self.triage_results.setEditable(False)
        self.triage_results.lineWrap = True
        self.triage_results.wrapStyleWord = True
        bot = JScrollPane(self.triage_results)
        bot.setBorder(CompoundBorder(TitledBorder(EtchedBorder(), "Results"), EmptyBorder(6, 6, 6, 6)))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bot)
        split.setResizeWeight(0.4)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # ==== Report Tab ====
    def _build_report_tab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(8, 8, 8, 8))

        top = JPanel(BorderLayout())
        top.setBorder(CompoundBorder(TitledBorder(EtchedBorder(), "Collected Findings"), EmptyBorder(6, 6, 6, 6)))
        self.report_findings_area = JTextArea(6, 50)
        self.report_findings_area.setEditable(False)
        self.report_findings_area.lineWrap = True
        self.report_findings_area.wrapStyleWord = True
        top.add(JScrollPane(self.report_findings_area), BorderLayout.CENTER)

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        toolbar.add(JLabel("Format:"))
        self.report_fmt = JComboBox(["markdown", "html"])
        toolbar.add(self.report_fmt)
        gen_btn = JButton("Generate Report")
        gen_btn.addActionListener(lambda e: self._do_report())
        toolbar.add(gen_btn)
        clear_findings_btn = JButton("Clear Findings")
        clear_findings_btn.addActionListener(lambda e: self._clear_findings())
        toolbar.add(clear_findings_btn)
        top.add(toolbar, BorderLayout.SOUTH)

        self.report_output = JTextArea(10, 50)
        self.report_output.setEditable(False)
        self.report_output.lineWrap = True
        self.report_output.wrapStyleWord = True
        bot = JScrollPane(self.report_output)
        bot.setBorder(CompoundBorder(TitledBorder(EtchedBorder(), "Generated Report"), EmptyBorder(6, 6, 6, 6)))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, bot)
        split.setResizeWeight(0.35)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # ---- Actions ----
    def _refresh_models(self):
        def run():
            try:
                cfg = self._gather_config()
                if not cfg:
                    return
                self.registry.config = cfg
                models = self.registry.refresh()
                SwingUtilities.invokeLater(lambda: self._update_model_ui(models))
            except Exception as e:
                SwingUtilities.invokeLater(lambda: self.response_area.setText(
                    format_error(e, self._gather_config() or self.config)))
        threading.Thread(target=run, daemon=True).start()

    def _update_model_ui(self, models):
        current = self.model_combo.getEditor().getItem() if self.model_combo.isEditable() else self.model_combo.getSelectedItem()
        self.model_combo.removeAllItems()
        if current and str(current).strip():
            self.model_combo.addItem(str(current).strip())
        for m in models:
            if m != str(current or '').strip():
                self.model_combo.addItem(m)
        list_model = DefaultListModel()
        for m in models:
            list_model.addElement(m)
        self.compare_model_list.setModel(list_model)

    def _get_model(self):
        return str(self.model_combo.getEditor().getItem()).strip() if self.model_combo.isEditable() else str(self.model_combo.getSelectedItem()).strip()

    def _get_template(self):
        idx = self.template_combo.getSelectedIndex()
        keys = sorted(PROMPT_TEMPLATES.keys())
        if 0 <= idx < len(keys):
            return PROMPT_TEMPLATES[keys[idx]]
        return PROMPT_TEMPLATES.get("explain")

    def _on_ask(self):
        msg = self.prompt_area.text.strip()
        if not msg:
            return
        self._do_chat(msg)

    def _on_followup(self):
        msg = self.followup_field.text.strip()
        if not msg:
            return
        self._do_chat(msg, is_followup=True)

    def _do_chat(self, user_msg, is_followup=False):
        self._save_service_config()
        cfg = self._gather_config()
        if not cfg:
            JOptionPane.showMessageDialog(self, "OpenRouter requires an API key.")
            return

        model = self._get_model() or cfg.model
        template = self._get_template()
        _set_cfg("model", model)

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
                    chat(model, template["system"], user_msg, config=cfg,
                         stream=True, on_chunk=on_chunk)
                    self._conversation.append(("assistant", ''.join(buf)))
                else:
                    result = chat(model, template["system"], user_msg, config=cfg)
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

    def _copy_response(self):
        text = self.response_area.text
        if text:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)

    def _add_to_report(self):
        text = self.response_area.text
        if text.strip():
            self._collected_findings.append(text.strip())
            self.report_findings_area.text = "\n\n---\n\n".join(self._collected_findings)

    def _clear(self):
        self.response_area.text = ""
        self._conversation = []

    def _send_to_requester(self):
        requests = extract_http_requests(self.response_area.text)
        if not requests:
            JOptionPane.showMessageDialog(self, "No HTTP requests found.")
            return
        try:
            from org.parosproxy.zap.extension.httppanel import HttpPanelRequest
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

    # ---- Compare ----
    def _do_compare(self):
        prompt = self.compare_prompt.text.strip()
        if not prompt:
            return
        selected = [str(self.compare_model_list.getModel().getElementAt(i))
                    for i in self.compare_model_list.getSelectedIndices()]
        if len(selected) < 2:
            JOptionPane.showMessageDialog(self, "Select at least 2 models.")
            return

        self.compare_results.text = "Comparing models...\n"
        def run():
            cfg = self._gather_config() or self.config
            results, errors = self.multi_model.compare(selected, "", prompt,
                                                        cfg.num_ctx, cfg.max_tokens)
            def update():
                out = "# Model Comparison\n\n"
                for model, result in sorted(results.items()):
                    out += "## {}\n\n{}\n\n---\n\n".format(model, result.content[:2000])
                for model, err in sorted(errors.items()):
                    out += "## {} (ERROR)\n\n{}\n\n---\n\n".format(model, err)
                self.compare_results.text = out
            SwingUtilities.invokeLater(update)
        threading.Thread(target=run, daemon=True).start()

    # ---- Triage ----
    def _do_triage(self):
        text = self.triage_text.text.strip()
        if not text:
            return
        self.triage_results.text = "Triaging...\n"
        def run():
            try:
                cfg = self._gather_config() or self.config
                result = auto_triage(text, config=cfg)
                out = "## Auto-Triage Results\n\n"
                out += "- **Verdict:** {}\n".format(
                    "REAL vulnerability" if result.is_real else ("False Positive" if result.is_real is False else "Uncertain"))
                out += "- **Confidence:** {}\n".format(result.confidence)
                out += "- **CWE:** {}\n".format(result.cwe_id or "N/A")
                out += "- **Severity:** {}\n".format(result.severity)
                out += "- **Reasoning:** {}\n".format(result.reasoning[:300])
                out += "- **Remediation:** {}\n".format(result.suggested_remediation[:300])
                self.triage_results.text = out
            except Exception as e:
                self.triage_results.text = "Error: {}".format(str(e))
        threading.Thread(target=run, daemon=True).start()

    def _do_cwe(self):
        text = self.triage_text.text.strip()
        if not text:
            return
        self.triage_results.text = "Mapping CWE...\n"
        def run():
            try:
                cfg = self._gather_config() or self.config
                result = map_cwe(text, config=cfg)
                out = "## CWE Mapping\n\n"
                out += "- **Primary:** {} - {}\n".format(result["cwe_id"], result["cwe_name"])
                if result["alternatives"]:
                    out += "- **Alternatives:** {}\n".format(", ".join(result["alternatives"]))
                out += "\n---\n{}".format(result["raw"][:500])
                self.triage_results.text = out
            except Exception as e:
                self.triage_results.text = "Error: {}".format(str(e))
        threading.Thread(target=run, daemon=True).start()

    def _do_exec_summary(self):
        text = self.triage_text.text.strip()
        if not text:
            return
        self.triage_results.text = "Generating executive summary...\n"
        def run():
            try:
                cfg = self._gather_config() or self.config
                result = executive_summary(text, config=cfg)
                self.triage_results.text = "## Executive Summary\n\n{}".format(result)
            except Exception as e:
                self.triage_results.text = "Error: {}".format(str(e))
        threading.Thread(target=run, daemon=True).start()

    # ---- Report ----
    def _do_report(self):
        text = self.report_findings_area.text.strip()
        if not text:
            self._collected_findings.append(self.response_area.text.strip())
            text = "\n\n---\n\n".join(self._collected_findings)
        if not text.strip():
            return

        findings = []
        for section in text.split("\n## "):
            if not section.strip():
                continue
            finding = {"name": "Finding", "severity": "Medium", "url": "N/A",
                       "description": section[:500], "cwe": "N/A"}
            for line in section.split('\n'):
                if line.startswith("## Scanner Finding:"):
                    finding["name"] = line.replace("## Scanner Finding:", "").strip()
                elif "Severity:" in line:
                    finding["severity"] = line.split("Severity:")[-1].strip().replace("**", "")
                elif "URL:" in line:
                    finding["url"] = line.split("URL:")[-1].strip().replace("**", "")
            findings.append(finding)

        self.report_output.text = "Generating report...\n"
        fmt = str(self.report_fmt.getSelectedItem())
        def run():
            try:
                cfg = self._gather_config() or self.config
                report = generate_report(
                    findings if findings else [
                        {"name": "Analysis", "severity": "N/A", "url": "",
                         "description": text[:1000], "cwe": ""}
                    ],
                    config=cfg, report_format=fmt
                )
                self.report_output.text = report
            except Exception as e:
                self.report_output.text = "Error: {}".format(str(e))
        threading.Thread(target=run, daemon=True).start()

    def _clear_findings(self):
        self._collected_findings = []
        self.report_findings_area.text = ""


# ---- Extension ----
class EnhancedAiExtension(ExtensionAdaptor):
    def getName(self):
        return "AskAiEnhanced"

    def getUIName(self):
        return "Ask AI+"

    def getDescription(self):
        return "Enhanced AI-powered security analysis (multi-model, auto-triage, CWE mapping, reports)"

    def init(self):
        ExtensionAdaptor.init(self)
        self.panel = EnhancedAiPanel()

    def getMainPanel(self):
        return self.panel


def install():
    try:
        ext = EnhancedAiExtension()
        Model.getSingleton().getExtensionLoader().addExtension(ext)
        print("[Ask AI+] Enhanced extension loaded with streaming, multi-model, auto-triage, CWE mapping & reports.")
    except Exception as e:
        print("[Ask AI+] Failed to load: {}".format(str(e)))

def uninstall():
    print("[Ask AI+] Unloaded.")
