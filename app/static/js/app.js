const DEFAULT_PATTERN = '';
const DEFAULT_LOGS = '';

const PALETTE = [
  { bg: 'bg-indigo-500/20', text: 'text-indigo-300', border: 'border-indigo-500/30', badge: 'bg-indigo-950/80 text-indigo-300 border-indigo-700/60' },
  { bg: 'bg-emerald-500/20', text: 'text-emerald-300', border: 'border-emerald-500/30', badge: 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60' },
  { bg: 'bg-amber-500/20', text: 'text-amber-300', border: 'border-amber-500/30', badge: 'bg-amber-950/80 text-amber-300 border-amber-700/60' },
  { bg: 'bg-pink-500/20', text: 'text-pink-300', border: 'border-pink-500/30', badge: 'bg-pink-950/80 text-pink-300 border-pink-700/60' },
  { bg: 'bg-purple-500/20', text: 'text-purple-300', border: 'border-purple-500/30', badge: 'bg-purple-950/80 text-purple-300 border-purple-700/60' },
  { bg: 'bg-cyan-500/20', text: 'text-cyan-300', border: 'border-cyan-500/30', badge: 'bg-cyan-950/80 text-cyan-300 border-cyan-700/60' },
  { bg: 'bg-orange-500/20', text: 'text-orange-300', border: 'border-orange-500/30', badge: 'bg-orange-950/80 text-orange-300 border-orange-700/60' },
  { bg: 'bg-teal-500/20', text: 'text-teal-300', border: 'border-teal-500/30', badge: 'bg-teal-950/80 text-teal-300 border-teal-700/60' },
  { bg: 'bg-rose-500/20', text: 'text-rose-300', border: 'border-rose-500/30', badge: 'bg-rose-950/80 text-rose-300 border-rose-700/60' },
  { bg: 'bg-lime-500/20', text: 'text-lime-300', border: 'border-lime-500/30', badge: 'bg-lime-950/80 text-lime-300 border-lime-700/60' },
  { bg: 'bg-fuchsia-500/20', text: 'text-fuchsia-300', border: 'border-fuchsia-500/30', badge: 'bg-fuchsia-950/80 text-fuchsia-300 border-fuchsia-700/60' },
  { bg: 'bg-sky-500/20', text: 'text-sky-300', border: 'border-sky-500/30', badge: 'bg-sky-950/80 text-sky-300 border-sky-700/60' },
  { bg: 'bg-violet-500/20', text: 'text-violet-300', border: 'border-violet-500/30', badge: 'bg-violet-950/80 text-violet-300 border-violet-700/60' },
];

function grokApp() {
  return {
    appConfig: { 
      version: 'Loading...', 
      environment: 'development', 
      features: {
        enable_auto_generate: true
      } 
    },
    pattern: localStorage.getItem('grok_pattern') || DEFAULT_PATTERN,
    customPatterns: localStorage.getItem('grok_custom') || '',
    logText: localStorage.getItem('grok_log_text') || DEFAULT_LOGS,
    namingFormat: localStorage.getItem('grok_naming_format') || 'bracket',
    sortMode: localStorage.getItem('grok_sort_mode') || 'order',
    viewMode: localStorage.getItem('grok_view_mode') || 'cards',
    showUnmatchedOnly: localStorage.getItem('grok_unmatched_only') === 'true',
    searchQuery: '',
    liveMode: true,
    results: [],
    errorMessage: '',
    rawMatchText: '',
    suggestedFix: '',
    rawGroupToReplace: null,
    debounceTimer: null,
    fieldColorMap: {},
    inconsistentFields: [],

    get lineCount() {
      return this.logText ? this.logText.split('\n').length : 1;
    },

    get customLineCount() {
      return this.customPatterns ? this.customPatterns.split('\n').length : 1;
    },

    get matchedCount() {
      return this.results.filter(r => r.matched).length;
    },

    get allLinesMatched() {
      return this.results.length > 0 && this.results.every(r => r.matched);
    },

    get lineNumbers() {
      return Array.from({ length: this.lineCount }, (_, i) => i + 1);
    },

    get logLineClasses() {
      if (!this.results.length) return '';
      return this.results.every(r => r.matched)
        ? 'ring-0'
        : 'bg-[linear-gradient(to_bottom,rgba(127,29,29,0.10),rgba(127,29,29,0.10))]';
    },

    get filteredResults() {
      let list = this.results;

      if (this.showUnmatchedOnly) {
        list = list.filter(r => !r.matched);
      }

      if (this.searchQuery.trim()) {
        const q = this.searchQuery.toLowerCase();
        list = list.filter(r => {
          const lineMatch = r.line_text && r.line_text.toLowerCase().includes(q);
          const fieldMatch = r.matches && Object.entries(r.matches).some(([k, v]) =>
            k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q)
          );
          return lineMatch || fieldMatch;
        });
      }

      return list;
    },

    initApp() {
      this.fetchConfig();
      this.checkSyntaxNotice();
      this.analyzeFormats();
      this.triggerMatch();
    },

    async fetchConfig() {
      try {
        const res = await fetch('/api/config');
        if (res.ok) {
          const data = await res.json();
          this.appConfig = { ...this.appConfig, ...data };
        }
      } catch (e) {
        console.warn('Unable to load server config, using defaults.', e);
      }
    },

    setNamingFormat(format) {
      this.namingFormat = format;
      this.analyzeFormats();
      this.saveState();
      this.onInputChange();
    },

    analyzeFormats() {
      const grokRegex = /%\{[^:]+:([^}:]+)(?::[^}]+)?\}/g;
      const namedGroupRegex = /\(\?(?:<|P<)([^>]+)>/g;
      
      let fields = [];
      let match;
      
      while ((match = grokRegex.exec(this.pattern)) !== null) {
        fields.push(match[1]);
      }
      while ((match = namedGroupRegex.exec(this.pattern)) !== null) {
        fields.push(match[1]);
      }
      
      let detectedInconsistent = [];
      
      fields.forEach(f => {
        const isDot = /^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)+$/.test(f);
        const isBracket = /^(\[[a-zA-Z0-9_\-]+\])+$/.test(f);
        
        if (this.namingFormat === 'dot' && isBracket) {
          detectedInconsistent.push(f);
        }
        if (this.namingFormat === 'bracket' && isDot) {
          detectedInconsistent.push(f);
        }
      });
      
      this.inconsistentFields = [...new Set(detectedInconsistent)];
    },

    normalizePattern() {
      let newPattern = this.pattern;
      
      const convertField = (fieldName) => {
        if (this.namingFormat === 'bracket') {
          if (/^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)+$/.test(fieldName)) {
            return fieldName.split('.').map(p => `[${p}]`).join('');
          }
        } else {
          if (/^(\[[a-zA-Z0-9_\-]+\])+$/.test(fieldName)) {
            return fieldName.replace(/^\[|\]$/g, '').split('][').join('.');
          }
        }
        return fieldName;
      };

      newPattern = newPattern.replace(/(%\{[^:]+:)([^}:]+)((?::[^}]+)?\})/g, (match, prefix, field, suffix) => {
        return prefix + convertField(field) + suffix;
      });
      
      newPattern = newPattern.replace(/(\(\?(?:<|P<))([^>]+)(>)/g, (match, prefix, field, suffix) => {
        return prefix + convertField(field) + suffix;
      });
      
      this.pattern = newPattern;
      this.analyzeFormats();
      this.onInputChange();
    },

    sortObjectKeys(obj) {
      if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return obj;
      }
      return Object.keys(obj)
        .sort((a, b) => a.localeCompare(b))
        .reduce((acc, key) => {
          acc[key] = this.sortObjectKeys(obj[key]);
          return acc;
        }, {});
    },

    formatJson(obj) {
      if (!obj) return '{}';
      const target = this.sortMode === 'alpha' ? this.sortObjectKeys(obj) : obj;
      return JSON.stringify(target, null, 2);
    },

    async copyJson(obj, evt) {
      const text = this.formatJson(obj);
      await navigator.clipboard.writeText(text);
      const btn = evt.currentTarget;
      const orig = btn.innerHTML;
      btn.innerHTML = `<span class="text-emerald-400">Copied!</span>`;
      setTimeout(() => btn.innerHTML = orig, 1500);
    },

    syncResultsHeight() {
      this.$nextTick(() => {
        const customContainer = document.getElementById('customPatternsContainer');
        const resultsContainer = document.getElementById('resultsContainer');
        
        if (customContainer && resultsContainer) {
          const customHeight = customContainer.offsetHeight;
          const resultsHeight = resultsContainer.offsetHeight;
          
          if (customHeight > resultsHeight) {
            const newMaxHeight = Math.max(customHeight - 20, 400);
            resultsContainer.style.maxHeight = newMaxHeight + 'px';
          } else {
            resultsContainer.style.maxHeight = '820px';
          }
        }
      });
    },

    syncScroll() {
      const ta = document.getElementById('area_logs');
      const gutter = document.getElementById('log_gutter');
      if (ta && gutter) gutter.scrollTop = ta.scrollTop;
    },

    syncCustomScroll() {
      const ta = document.getElementById('area_custom');
      const gutter = document.getElementById('custom_gutter');
      if (ta && gutter) gutter.scrollTop = ta.scrollTop;
    },

    resetAll() {
      localStorage.clear();
      this.pattern = DEFAULT_PATTERN;
      this.customPatterns = '';
      this.logText = DEFAULT_LOGS;
      this.namingFormat = 'bracket';
      this.sortMode = 'order';
      this.viewMode = 'cards';
      this.showUnmatchedOnly = false;
      this.searchQuery = '';
      this.results = [];
      this.errorMessage = '';
      this.rawMatchText = '';
      this.suggestedFix = '';
      this.rawGroupToReplace = null;
      this.fieldColorMap = {};
      this.inconsistentFields = [];

      this.saveState();
      this.onInputChange();
    },

    getFieldColor(fieldName) {
      if (!fieldName) return PALETTE[0];
      
      if (this.fieldColorMap[fieldName]) {
        return this.fieldColorMap[fieldName];
      }
      
      const existingFields = Object.keys(this.fieldColorMap);
      const index = existingFields.length % PALETTE.length;
      const color = PALETTE[index];
      
      this.fieldColorMap[fieldName] = color;
      return color;
    },

    getDisplayFields(res) {
      if (!res || !res.matches) return [];
      if (this.sortMode === 'order' && res.ordered_matches && res.ordered_matches.length > 0) {
        return res.ordered_matches;
      }
      return Object.keys(res.matches).sort().map(k => ({ key: k, value: res.matches[k] }));
    },

    resolveRegexToGrok(regex) {
      const normalized = regex.trim();

      const mappings = [
        // Numbers
        { test: /^\\d\+$/, grok: 'INT' },
        { test: /^\[0-9\]\+$/, grok: 'INT' },
        { test: /^\\d\*\$/, grok: 'NUMBER' },
        { test: /^\[0-9\]\*\$/, grok: 'NUMBER' },

        // Words / text
        { test: /^\\w\+$/, grok: 'WORD' },
        { test: /^\\w\*$/, grok: 'WORD' },

        // Non whitespace
        { test: /^\\S\+$/, grok: 'NOTSPACE' },
        { test: /^\\S\*$/, grok: 'NOTSPACE' },

        // Whitespace
        { test: /^\\s\+$/, grok: 'SPACE' },
        { test: /^\\s\*$/, grok: 'SPACE' },

        // Any characters
        { test: /^\.\+$/, grok: 'GREEDYDATA' },
        { test: /^\.\*$/, grok: 'GREEDYDATA' },

        // IPv4 addresses written as a hand-rolled octet regex, e.g. \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
        // NOTE: the previous test here was `/^\(\?P?<[^>]+>.*\)$/`, which tried to match a
        // *named group* against `regex`. But `regex` is already the *inside* of a named
        // group (see checkSyntaxNotice below, which strips `)` from what it captures), so
        // that pattern could never match anything and this branch was dead code - IPv4
        // fields were always falling through to GREEDYDATA. Matching the literal octet
        // pattern instead covers the common hand-written case.
        {
          test: /^(?:\\d\{1,3\}\\\.){3}\\d\{1,3\}$/,
          grok: 'IP'
        },

        // Hex
        { test: /^\\x[0-9a-fA-F]+$/, grok: 'BASE16NUM' },

        // UUID
        { 
          test: /^[0-9a-fA-F-]{36}$/,
          grok: 'UUID'
        },

        // Quoted strings
        {
          test: /^".*"$/,
          grok: 'QUOTEDSTRING'
        }
      ];

      const found = mappings.find(item => item.test.test(normalized));

      return found ? found.grok : 'GREEDYDATA';
    },

    checkSyntaxNotice() {
      const match = this.pattern.match(/\(\?(?:P)?<([^>]+)>([^)]*)\)/);
      if (match) {
        const rawGroup = match[0];
        const fieldName = match[1];
        const innerRegex = match[2];

        this.rawGroupToReplace = rawGroup;
        this.rawMatchText = rawGroup;

        const grokPattern = this.resolveRegexToGrok(innerRegex);

        this.suggestedFix = `%{${grokPattern}:${fieldName}}`;
      } else {
        this.suggestedFix = '';
        this.rawGroupToReplace = null;
        this.rawMatchText = '';
      }
    },

    applyAutoFix() {
      if (this.rawGroupToReplace && this.suggestedFix) {
        this.pattern = this.pattern.replace(this.rawGroupToReplace, this.suggestedFix);
        this.onInputChange();
      }
    },

    strictMode: localStorage.getItem('grok_strict_mode') === 'true',

    saveState() {
      localStorage.setItem('grok_pattern', this.pattern);
      localStorage.setItem('grok_custom', this.customPatterns);
      localStorage.setItem('grok_log_text', this.logText);
      localStorage.setItem('grok_naming_format', this.namingFormat);
      localStorage.setItem('grok_sort_mode', this.sortMode);
      localStorage.setItem('grok_view_mode', this.viewMode);
      localStorage.setItem('grok_unmatched_only', String(this.showUnmatchedOnly));
      localStorage.setItem('grok_strict_mode', String(this.strictMode));
    },

    onLogInput() {
      this.saveState();
      this.onInputChange();
    },

    onInputChange() {
      this.saveState();
      this.checkSyntaxNotice();
      this.analyzeFormats();

      if (!this.liveMode) return;

      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => {
        this.triggerMatch();
      }, 300);
    },

    async triggerMatch() {
      this.errorMessage = '';
      try {
        const res = await fetch('/api/match', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            pattern: this.pattern,
            custom_patterns: this.customPatterns,
            log_text: this.logText,
            naming_format: this.namingFormat,
            strict_mode: this.strictMode
          })
        });
        const data = await res.json();
        if (data.success) {
          this.results = (data.results || []).map(r => ({ ...r, showJson: false }));
          this.fieldColorMap = {};
          this.$nextTick(() => {
            this.syncResultsHeight();
          });
        } else {
          this.errorMessage = data.detail || 'Unknown matching error.';
          this.results = [];
        }
      } catch (err) {
        this.errorMessage = 'Failed to communicate with server backend.';
        this.results = [];
      }
    },

    async autoGenerate() {
      try {
        const res = await fetch('/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            pattern: '',
            custom_patterns: '',
            log_text: this.logText,
            naming_format: this.namingFormat
          })
        });
        const data = await res.json();
        if (data.success) {
          this.pattern = data.generated_pattern || '';
          this.onInputChange();
        }
      } catch (e) {
        console.error(e);
      }
    }
  }
}
