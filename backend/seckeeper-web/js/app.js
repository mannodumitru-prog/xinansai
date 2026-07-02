/// SecKeeper 前端逻辑 - 完美融合版 (OOP架构 + 异步轮询 + 规则更新)

class SecKeeperAPI {
    constructor(baseURL = 'http://localhost:5000') {
        this.baseURL = baseURL;
        this.timeout = 30000;
    }

    async request(endpoint, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const config = {
                headers: { 'Content-Type': 'application/json', ...options.headers },
                signal: controller.signal,
                ...options
            };
            if (options.method === 'POST' && options.body) {
                config.body = JSON.stringify(options.body);
            }

            const response = await fetch(`${this.baseURL}${endpoint}`, config);
            clearTimeout(timeoutId);

            if (!response.ok) {
                let errorMsg = `HTTP ${response.status} 错误`;
                try {
                    const errData = await response.json();
                    if (errData && errData.error) errorMsg = errData.error;
                } catch (e) {}
                throw new Error(errorMsg);
            }

            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/pdf')) {
                return await response.blob();
            }
            return await response.json();
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') throw new Error('请求超时，请检查后端服务是否启动');
            throw error;
        }
    }

    async getRuleStatus() { return await this.request('/api/rules/status'); }
    async checkRuleUpdate() { return await this.request('/api/rules/check'); }
    async executeRuleUpdate() { return await this.request('/api/rules/update', { method: 'POST' }); }
    async importOfflineRules(file) {
        const formData = new FormData();
        formData.append('file', file);
        const response = await fetch(`${this.baseURL}/api/rules/import-offline`, { method: 'POST', body: formData });
        if (!response.ok) {
            let errorMsg = `HTTP ${response.status} 错误`;
            try { const errData = await response.json(); if (errData && errData.error) errorMsg = errData.error; } catch (e) {}
            throw new Error(errorMsg);
        }
        return await response.json();
    }
    async getSystemInfo() { return await this.request('/api/dashboard'); }
    async getAssets() { return await this.request('/api/assets'); }
    async getComplianceResults() { return await this.request('/api/compliance'); }
    async getVulnerabilities() { return await this.request('/api/vulnerabilities'); }
    async startFullScan() { return await this.request('/api/scan', { method: 'POST' }); }
    async getScanStatus(scanId) { return await this.request(`/api/scan/${scanId}/status`); }
    async getSystemStatus() { return await this.request('/api/health'); }
    async generateReport(scanData) { return await this.request('/api/report', { method: 'POST', body: scanData }); }
}

class SecKeeperApp {
    constructor() {
        this.currentTab = 'dashboard';
        this.charts = {};
        this.api = new SecKeeperAPI();
        this.currentData = {
            systemInfo: null,
            software: [],
            services: [],
            compliance: [],
            vulnerabilities: [],
            verificationSummary: {},
            xinchuangSummary: {},
            lastScanResult: null
        };
        this.scanState = {
            isScanning: false,
            lastScanTime: null
        };
        this.scanFlowTimer = null;
        this.scanFlowIndex = 0;

        // 🟢 新增：当前漏洞列表的过滤状态
        this.currentVulnFilter = 'all';
        this.currentComplianceFilter = 'all';
        this.showVerifiedOnly = false;

        this.init();
    }

    async init() {
        console.log('SecKeeper 安全卫士初始化完成！');
        this.setupEventListeners();
        this.initCharts();
        this.showTab('dashboard');

        const historyData = localStorage.getItem('seckeeper_history') || localStorage.getItem('seckeeper_history_compact');

        if (historyData) {
            try {
                const parsed = JSON.parse(historyData);
                this.currentData = this.normalizeHistoryData(parsed);
                const resultsPanel = document.getElementById('results-panel');
                const blankPlaceholder = document.getElementById('blank-placeholder');
                if (resultsPanel) resultsPanel.classList.remove('hidden');
                if (blankPlaceholder) blankPlaceholder.classList.add('hidden');
                this.loadDashboardData();
                this.showHistoricalBanner();
                this.showNotification('<i class="fas fa-history"></i> 已加载上一次的扫描记录', 'info');
            } catch (e) {
                console.warn('历史记录解析失败，已清理本地缓存', e);
                localStorage.removeItem('seckeeper_history');
                localStorage.removeItem('seckeeper_history_compact');
                this.loadSystemInfoOnly();
            }
        } else {
            this.loadSystemInfoOnly();
        }

        this.loadRuleStatus();
    }

    async loadSystemInfo() {
        try {
            const res = await this.api.getAssets();
            if (res && res.data && res.data.system_info) {
                this.currentData.hostInfo = res.data.system_info;
            }
        } catch (error) {
            console.warn('获取系统信息失败:', error);
        }
    }

    async loadSystemInfoOnly() {
        try {
            await this.loadSystemInfo();

            this.currentData.software = [];
            this.currentData.services = [];
            this.currentData.compliance = { summary: { total: 0, passed: 0, compliance_rate: 0 }, checks: [] };
            this.currentData.vulnerabilities = { scan_summary: { total_vulnerabilities: 0 }, details: [], verification_summary: {} };
            this.currentData.verificationSummary = {};
            this.currentData.xinchuangSummary = {};

            const resultsPanel = document.getElementById('results-panel');
            const blankPlaceholder = document.getElementById('blank-placeholder');
            if (resultsPanel) resultsPanel.classList.add('hidden');
            if (blankPlaceholder) blankPlaceholder.classList.remove('hidden');

            this.showNotification('<i class="fas fa-shield-alt"></i> 系统已就绪，请点击一键扫描', 'info');
        } catch (error) {
            console.warn('初始化失败:', error);
        }
    }

    showHistoricalBanner() {
        if (document.getElementById('history-banner')) return;
        const header = document.querySelector('.header');
        if (!header) return;
        const banner = document.createElement('div');
        banner.id = 'history-banner';
        banner.innerHTML = '<i class="fas fa-history"></i> 当前显示的是 <strong>历史扫描记录</strong>。系统状态可能已发生改变，建议点击【一键全面扫描】获取最新安全态势。';
        header.insertAdjacentElement('afterend', banner);
    }

    removeHistoricalBanner() {
        const banner = document.getElementById('history-banner');
        if (banner) banner.remove();
    }

    normalizeHistoryData(data) {
        const normalized = data || {};
        normalized.software = normalized.software || normalized.assets?.software || [];
        normalized.services = normalized.services || normalized.assets?.services || [];
        normalized.hostInfo = normalized.hostInfo || normalized.systemInfo || normalized.assets?.system_info || {};
        normalized.systemInfo = normalized.systemInfo || normalized.hostInfo || {};
        normalized.compliance = normalized.compliance || { summary: { total: 0, passed: 0, compliance_rate: 0 }, checks: [] };
        normalized.vulnerabilities = normalized.vulnerabilities || { scan_summary: { total_vulnerabilities: 0 }, details: [] };
        normalized.verificationSummary = normalized.verificationSummary || normalized.vulnerabilities?.verification_summary || {};
        normalized.xinchuangSummary = normalized.xinchuangSummary || normalized.compliance?.xinchuang_summary || {};
        return normalized;
    }

    saveHistory() {
        const compact = {
            saved_at: new Date().toISOString(),
            hostInfo: this.currentData.hostInfo || this.currentData.systemInfo || {},
            systemInfo: this.currentData.systemInfo || this.currentData.hostInfo || {},
            software: (this.currentData.software || []).slice(0, 300),
            services: (this.currentData.services || []).slice(0, 200),
            compliance: this.currentData.compliance || {},
            vulnerabilities: {
                scan_summary: this.currentData.vulnerabilities?.scan_summary || this.currentData.vulnerabilities?.summary || {},
                verification_summary: this.currentData.vulnerabilities?.verification_summary || this.currentData.verificationSummary || {},
                details: (this.getVulnerabilityList() || []).slice(0, 300)
            },
            verificationSummary: this.currentData.verificationSummary || {},
            xinchuangSummary: this.currentData.xinchuangSummary || {},
            lastScanResult: {
                scan_id: this.currentData.lastScanResult?.scan_id,
                timestamp: this.currentData.lastScanResult?.timestamp
            }
        };
        try {
            localStorage.setItem('seckeeper_history', JSON.stringify(compact));
            localStorage.removeItem('seckeeper_history_compact');
        } catch (err) {
            console.warn('完整历史记录过大，降级保存摘要', err);
            const summaryOnly = { ...compact, software: [], services: [], vulnerabilities: { ...compact.vulnerabilities, details: [] } };
            localStorage.setItem('seckeeper_history_compact', JSON.stringify(summaryOnly));
        }
    }

    setupEventListeners() {
        document.querySelectorAll('.nav-button').forEach(button => {
            button.addEventListener('click', (e) => {
                this.showTab(e.target.closest('.nav-button').getAttribute('data-tab'));
            });
        });

        const updateBtn = document.getElementById('update-rules-btn');
        if (updateBtn) {
            updateBtn.addEventListener('click', () => this.handleRuleUpdate());
        }

        const offlineBtn = document.getElementById('import-offline-rules-btn');
        const offlineInput = document.getElementById('offline-rule-package');
        if (offlineBtn && offlineInput) {
            offlineBtn.addEventListener('click', () => offlineInput.click());
            offlineInput.addEventListener('change', () => {
                const file = offlineInput.files && offlineInput.files[0];
                if (file) this.handleOfflineRuleImport(file);
                offlineInput.value = '';
            });
        }

        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey) {
                switch(e.key) {
                    case '1': this.showTab('dashboard'); break;
                    case '2': this.showTab('assets'); break;
                    case '3': this.showTab('compliance'); break;
                    case '4': this.showTab('vulnerabilities'); break;
                    case 'r': this.refreshCurrentTab(); break;
                    case 'p': this.generatePDFReport(); break;
                }
            }
        });
    }

    showTab(tabName) {
        if(!tabName) return;
        this.currentTab = tabName;
        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active-tab'));
        document.querySelectorAll('.nav-button').forEach(btn => btn.classList.remove('active-nav'));

        const activeTab = document.getElementById(tabName);
        const activeBtn = document.querySelector(`[data-tab="${tabName}"]`);

        if (activeTab) activeTab.classList.add('active-tab');
        if (activeBtn) activeBtn.classList.add('active-nav');

        this.loadTabData(tabName);
    }

    loadTabData(tabName) {
        switch(tabName) {
            case 'dashboard': this.loadDashboardData(); break;
            case 'assets': this.displayAssetData(); break;
            case 'compliance': this.displayComplianceData(); break;
            case 'vulnerabilities': this.displayVulnerabilityData(); break;
        }
    }

    async loadRuleStatus() {
        try {
            const res = await this.api.getRuleStatus();
            if (res.success && res.data) {
                const versionEl = document.getElementById('rule-version');
                if (versionEl) {
                    versionEl.textContent = 'v' + res.data.db_version;
                    const fileCount = res.data.file_count ? ` · ${res.data.file_count} files` : '';
                    const updated = res.data.last_updated ? ` · ${res.data.last_updated}` : '';
                    versionEl.title = `规则库版本 ${res.data.db_version}${fileCount}${updated}`;
                }
            }
        } catch (e) {
            console.error("无法获取规则库状态:", e);
        }
    }

    async handleRuleUpdate() {
        const btn = document.getElementById('update-rules-btn');
        const originalText = btn.innerHTML;
        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 检查中...';
            this.showNotification('正在连接云端检查规则库更新...', 'info');

            const checkRes = await this.api.checkRuleUpdate();

            if (checkRes.data && checkRes.data.update_available) {
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 下载中...';
                this.showNotification(`发现新版本 v${checkRes.data.remote_version}，开始自动下载...`, 'warning');

                const updateRes = await this.api.executeRuleUpdate();
                if (updateRes.success) {
                    this.showNotification(`规则库升级成功！共更新 ${updateRes.data.updated_files.length} 个文件`, 'success');
                    this.loadRuleStatus();
                } else {
                    throw new Error(updateRes.data.message || '下载失败');
                }
            } else {
                this.showNotification('当前规则库已是最新版本，无需更新', 'success');
            }
        } catch (err) {
            this.showNotification('更新失败: ' + err.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    async handleOfflineRuleImport(file) {
        if (!file) return;
        const isZip = file.name.toLowerCase().endsWith('.zip');
        if (!isZip) {
            this.showNotification('离线规则包必须是 .zip 文件', 'warning');
            return;
        }

        const btn = document.getElementById('import-offline-rules-btn');
        const originalText = btn ? btn.innerHTML : '';
        try {
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 导入中...';
            }
            this.showNotification('正在导入离线规则包，请稍候...', 'info');
            const res = await this.api.importOfflineRules(file);
            if (res.success) {
                const updated = res.data?.updated_files || res.data?.imported_files || [];
                this.showNotification(`离线规则包导入成功${updated.length ? `，更新 ${updated.length} 个文件` : ''}`, 'success');
                await this.loadRuleStatus();
            } else {
                throw new Error(res.error || res.data?.message || '离线规则包导入失败');
            }
        } catch (err) {
            this.showNotification('离线规则导入失败: ' + err.message, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        }
    }

    async startFullScan() {
        if (this.scanState.isScanning) {
            this.showNotification('<i class="fas fa-sync-alt"></i> 扫描正在进行中，请稍候...', 'warning');
            return;
        }

        const button = document.querySelector('.scan-button');
        const originalText = button.innerHTML;

        this.scanState.isScanning = true;
        button.innerHTML = '<i class="fas fa-sync-alt loading-spinner"></i> 正在巡检...';
        this.startScanFlowAnimation();
        button.disabled = true;

        const resultsPanel = document.getElementById('results-panel');
        const blankPlaceholder = document.getElementById('blank-placeholder');
        if (resultsPanel) resultsPanel.classList.remove('hidden');
        if (blankPlaceholder) blankPlaceholder.classList.add('hidden');

        this.showNotification('<i class="fas fa-search"></i> 开始启动安全扫描引擎...', 'info');

        try {
            const result = await this.api.startFullScan();

            if (result.success && result.data && result.data.scan_id) {
                const scanId = result.data.scan_id;

                const pollInterval = setInterval(async () => {
                    try {
                        const statusRes = await this.api.getScanStatus(scanId);
                        const statusData = statusRes.data;
                        if (!statusData) return;

                        button.innerHTML = `<i class="fas fa-sync-alt loading-spinner"></i> ${statusData.current_step} (${statusData.progress || 0}%)`;
                        if (!this.scanFlowTimer) this.updateScanFlow(statusData.current_step || '扫描中');

                        if (statusData.status === 'completed' || statusData.status === 'failed') {
                            clearInterval(pollInterval);

                            if (statusData.status === 'completed') {
                                button.innerHTML = '<i class="fas fa-check-circle"></i> 数据聚合中...';
                                this.stopScanFlowAnimation(true);
                                this.showNotification('<i class="fas fa-check-circle"></i> 扫描完成，正在渲染结果', 'success');
                                this.showScanCompleteBanner();

                                const finalResult = statusData.result || {};
                                this.currentData.lastScanResult = finalResult;

                                if(finalResult.assets) {
                                    this.currentData.software = finalResult.assets.software || [];
                                    this.currentData.services = finalResult.assets.services || [];
                                    if (finalResult.assets.system_info) {
                                        this.currentData.hostInfo = finalResult.assets.system_info;
                                        this.currentData.systemInfo = finalResult.assets.system_info;
                                    }
                                }
                                if(finalResult.compliance) {
                                    this.currentData.compliance = finalResult.compliance;
                                    this.currentData.xinchuangSummary = finalResult.compliance.xinchuang_summary || {};
                                }
                                if(finalResult.vulnerabilities) {
                                    this.currentData.vulnerabilities = finalResult.vulnerabilities;
                                    this.currentData.verificationSummary = finalResult.vulnerabilities.verification_summary || {};
                                }

                                this.saveHistory();

                                this.removeHistoricalBanner();
                                await this.loadDashboardData();
                                this.refreshCurrentTab();
                                setTimeout(() => this.refreshCharts(), 500);
                            } else {
                                this.stopScanFlowAnimation(false);
                                this.showNotification('<i class="fas fa-times-circle"></i> 后台扫描异常终止', 'error');
                            }

                            setTimeout(() => {
                                button.innerHTML = originalText;
                                button.disabled = false;
                                this.scanState.isScanning = false;
                            }, 2000);
                        }
                    } catch (pollErr) {
                        clearInterval(pollInterval);
                        console.error("轮询出现异常:", pollErr);
                        this.stopScanFlowAnimation(false);
                        button.innerHTML = originalText;
                        button.disabled = false;
                        this.scanState.isScanning = false;
                    }
                }, 2000);

            } else {
                throw new Error(result.error || '无法获取扫描任务ID');
            }
        } catch (error) {
            this.scanState.isScanning = false;
            this.stopScanFlowAnimation(false);
            button.innerHTML = '<i class="fas fa-times-circle"></i> 扫描失败';
            this.showNotification('<i class="fas fa-times-circle"></i> 启动失败: ' + error.message, 'error');
            setTimeout(() => { button.innerHTML = originalText; button.disabled = false; }, 3000);
        }
    }

    startScanFlowAnimation() {
        this.stopScanFlowAnimation(false);
        this.scanFlowIndex = 0;
        const nodes = Array.from(document.querySelectorAll('.flow-node'));
        if (!nodes.length) return;
        const apply = () => {
            nodes.forEach((node, idx) => {
                node.classList.remove('active', 'done', 'scanning');
                if (idx < this.scanFlowIndex) node.classList.add('done');
                if (idx === this.scanFlowIndex) node.classList.add('scanning', 'active');
            });
            this.scanFlowIndex = (this.scanFlowIndex + 1) % nodes.length;
        };
        apply();
        this.scanFlowTimer = setInterval(apply, 950);
    }

    stopScanFlowAnimation(markDone = false) {
        if (this.scanFlowTimer) {
            clearInterval(this.scanFlowTimer);
            this.scanFlowTimer = null;
        }
        const nodes = Array.from(document.querySelectorAll('.flow-node'));
        nodes.forEach((node, idx) => {
            node.classList.remove('active', 'done', 'scanning');
            if (markDone) node.classList.add('done');
            else if (idx === 0) node.classList.add('active');
        });
    }

    updateScanFlow(step) {
        if (this.scanFlowTimer) return;
        const stepText = String(step || '').toLowerCase();
        const flowSteps = [
            { key: 'asset', match: ['资产', 'asset'], label: '资产清点' },
            { key: 'compliance', match: ['合规', '基线', 'compliance'], label: '合规检查' },
            { key: 'vuln', match: ['漏洞', 'cve', 'vulnerability'], label: '漏洞扫描' },
            { key: 'verify', match: ['验证', '本地', '网络', 'poc', 'nuclei'], label: '双核验证' },
            { key: 'report', match: ['报告', '完成', 'report'], label: '报告输出' }
        ];
        let activeIndex = 0;
        flowSteps.forEach((item, idx) => {
            if (item.match.some(m => stepText.includes(String(m).toLowerCase()))) activeIndex = idx;
        });
        if (stepText.includes('扫描完成') || stepText.includes('completed')) activeIndex = flowSteps.length - 1;
        document.querySelectorAll('.flow-node').forEach((node, idx) => {
            node.classList.remove('active', 'done', 'scanning');
            if (idx < activeIndex) node.classList.add('done');
            if (idx === activeIndex) node.classList.add('active');
        });
    }

    showScanCompleteBanner() {
        const old = document.querySelector('.scan-complete-banner');
        if (old) old.remove();
        const banner = document.createElement('div');
        banner.className = 'scan-complete-banner';
        banner.innerHTML = '<i class="fas fa-check-circle"></i> 巡检完成 · 资产、合规与风险检测已完成';
        document.body.appendChild(banner);
        setTimeout(() => {
            banner.style.opacity = '0';
            banner.style.transition = '.28s ease';
            setTimeout(() => banner.remove(), 300);
        }, 2400);
    }

    async loadDashboardData() {
        this.updateDashboardStats();
        this.displayRealTimeStatus();
        setTimeout(() => this.refreshCharts(), 500);
    }

    updateDashboardStats() {
        const softwareCount = this.currentData.software?.length || 0;
        const serviceCount = this.currentData.services?.length || 0;
        const complianceRate = this.currentData.compliance?.summary?.compliance_rate || 0;
        const vulnSummary = this.currentData.vulnerabilities?.scan_summary || this.currentData.vulnerabilities?.summary || {};
        const verificationSummary = this.getVerificationSummary();

        let highRiskCount = 0;
        const vulnsForRisk = this.getVulnerabilityList();
        if (vulnsForRisk.length > 0) {
            vulnsForRisk.forEach(v => {
                const sev = (v.severity || v.level || '').toLowerCase();
                const status = this.normalizeVulnStatus(v);
                if (status !== 'needs_manual_check' && (sev === 'high' || sev === 'critical')) highRiskCount++;
            });
        } else {
            highRiskCount = (vulnSummary.critical || 0) + (vulnSummary.high || 0);
        }

        document.getElementById('total-assets').textContent = softwareCount + serviceCount;
        document.getElementById('compliance-rate').textContent = complianceRate + '%';
        document.getElementById('high-risk-count').textContent = highRiskCount;
        this.currentData.verificationSummary = verificationSummary;
    }

    displayRealTimeStatus() {
        const isHealthy = document.getElementById('high-risk-count').textContent === "0";
        const verificationSummary = this.getVerificationSummary();
        const complianceData = this.currentData.compliance || {};
        const checks = complianceData.checks || complianceData.results || complianceData.details || [];

        const isXinchuangItem = (item) =>
            item.xinchuang === true ||
            item.is_xinchuang === true ||
            /麒麟|kylin|统信|uos|达梦|dameng|金仓|kingbase|tongweb|东方通/i.test(
                `${item.name || item.check || item.check_name || ''} ${item.category || ''} ${item.description || ''}`
            );

        const isPassedItem = (item) =>
            item.passed === true || item.status === 'passed';

        const xinchuangTotal = checks
            .filter(item => isXinchuangItem(item) && !isPassedItem(item))
            .length;
        const statusData = [
            { icon: 'microchip', label: '主机安全状态', value: isHealthy ? '健康' : '异常', status: isHealthy ? 'normal' : 'warning' },
            { icon: 'box', label: '软件资产数量', value: this.currentData.software.length || 0, status: 'normal' },
            { icon: 'cogs', label: '运行服务数量', value: this.currentData.services.length || 0, status: 'normal' },
            { icon: 'shield-alt', label: '基线合规率', value: document.getElementById('compliance-rate').textContent, status: 'normal' },
            { icon: 'check-double', label: '已确认风险', value: verificationSummary.verified || 0, status: (verificationSummary.verified || 0) > 0 ? 'warning' : 'normal' },
            { icon: 'server', label: 'Nuclei 网络验证', value: verificationSummary.network || 0, status: 'normal' },
            { icon: 'terminal', label: '本地 PoC 验证', value: verificationSummary.local || 0, status: 'normal' },
            { icon: 'landmark', label: '信创专项异常', value: xinchuangTotal || 0, status: xinchuangTotal > 0 ? 'warning' : 'normal' }
        ];

        const statusGrid = document.getElementById('real-time-status');
        if (!statusGrid) return;
        statusGrid.classList.add('status-dashboard');
        statusGrid.innerHTML = statusData.map(item => `
            <div class="status-item ${item.status}">
                <div class="status-icon"><i class="fas fa-${item.icon}"></i></div>
                <div class="status-info">
                    <div class="status-label">${item.label}</div>
                    <div class="status-value">${item.value}</div>
                </div>
            </div>
        `).join('');
    }

    displayAssetData() {
        const assetsTab = document.getElementById('assets');
        const info = this.currentData.hostInfo || this.currentData.systemInfo || {};

        const systemInfoHTML = `
            <div class="card">
                <h3><i class="fas fa-info-circle"></i> 系统信息</h3>
                <div class="system-info-grid">
                    <div class="system-info-item"><i class="fas fa-laptop"></i> <strong>操作系统:</strong> ${info.os_name || info.os || '未知操作系统'}</div>
                    <div class="system-info-item"><i class="fas fa-code"></i> <strong>内核版本:</strong> ${info.platform || info.os_version || '未知内核'}</div>
                    <div class="system-info-item"><i class="fas fa-microchip"></i> <strong>系统架构:</strong> ${info.architecture || info.arch || '未知架构'}</div>
                    <div class="system-info-item"><i class="fas fa-desktop"></i> <strong>主机名:</strong> ${info.hostname || '未知主机'}</div>
                </div>
            </div>`;


        const mappedPackages = (this.currentData.software || []).filter(pkg => pkg.xinchuang_package_mapped || (pkg.security_name && pkg.security_name !== pkg.name) || (pkg.normalized_name && pkg.normalized_name !== pkg.name));
        const adapterHTML = `
            <div class="xinchuang-adapter-card">
                <div class="adapter-title"><i class="fas fa-code-branch"></i> 信创包名解析适配</div>
                <div class="adapter-desc">
                    平台会对银河麒麟、统信 UOS 等国产发行版中的包名差异进行规范化处理，将系统包名映射到安全知识库中的通用组件名，提升 CVE 初筛准确性。
                    ${mappedPackages.length ? `<br><span class="adapter-highlight">已规范化：${mappedPackages.length} 个软件包</span>` : '<br><span class="adapter-highlight">当前环境暂未发现规范化映射包</span>'}
                </div>
            </div>`;

        let softwareHTML = `
            <div style="margin-bottom: 25px;">
                <h4 class="section-title">
                    <i class="fas fa-box"></i> 已安装软件 (${this.currentData.software.length}个)
                </h4>
                <table class="data-table">
                    <thead><tr><th><i class="fas fa-cube"></i> 名称</th><th><i class="fas fa-code-branch"></i> 版本</th><th><i class="fas fa-info-circle"></i> 状态</th></tr></thead>
                    <tbody>
                        ${this.currentData.software.slice(0, 100).map(pkg => `
                            <tr>
                                <td><i class="fas fa-cube" style="color: var(--accent); margin-right: 8px;"></i>${pkg.name || pkg.package_name || '未知软件'}</td>
                                <td>${pkg.version || pkg.package_version || '未知'}</td>
                                <td><span class="status-indicator status-installed"><i class="fas fa-circle-check"></i> 已安装</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>`;

        assetsTab.innerHTML = systemInfoHTML + adapterHTML + `<div class="card"><h3><i class="fas fa-desktop"></i> 资产总览</h3>${softwareHTML}</div>`;
    }

    displayComplianceData() {
        const complianceTab = document.getElementById('compliance');
        const data = this.currentData.compliance || {};
        const summary = data.summary || {};
        const checks = data.checks || data.results || data.details || [];
        const xinchuangSummary = this.getXinchuangSummary();
        const categories = data.categories || summary.categories || {};

        if (checks.length === 0) {
            complianceTab.innerHTML = '<div class="card"><div class="empty-state"><i class="fas fa-shield-alt"></i><h3>暂无合规检查数据</h3><p>请点击一键扫描获取最新状态</p></div></div>';
            return;
        }

        const isXinchuangItem = (item) => item.xinchuang === true || item.is_xinchuang === true || /麒麟|kylin|统信|uos|达梦|dameng|金仓|kingbase|tongweb|东方通/i.test(`${item.name || item.check || item.check_name || ''} ${item.category || ''} ${item.description || ''}`);
        const isPassedItem = (item) => item.passed === true || item.status === 'passed';
        const passedCount = Number(summary.passed || checks.filter(isPassedItem).length || 0);
        const totalCount = Number(summary.total || checks.length || 0);
        const failed = Math.max(0, totalCount - passedCount);
        const xinchuangItems = checks.filter(isXinchuangItem);
        const xinchuangFailed = xinchuangItems.filter(item => !isPassedItem(item)).length;
        const xinchuangLabels = { kylin: '银河麒麟', uos: '统信 UOS', dameng: '达梦数据库', kingbase: '人大金仓', tongweb: '东方通 TongWeb' };

        let filteredChecks = checks.filter(item => {
            const passed = isPassedItem(item);
            const xin = isXinchuangItem(item);
            if (this.currentComplianceFilter === 'passed') return passed;
            if (this.currentComplianceFilter === 'failed') return !passed;
            if (this.currentComplianceFilter === 'xinchuang') return xin;
            return true;
        });

        let html = `
            <div class="card compliance-hero" style="margin-bottom: 20px;">
                <h3><i class="fas fa-shield-alt"></i> 安全合规检查</h3>
                <div class="status-grid status-grid-balanced metric-card-grid">
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-list-check"></i></div><div class="status-info"><div class="status-label">检查总数</div><div class="status-value">${totalCount}</div></div></div>
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-check-circle"></i></div><div class="status-info"><div class="status-label">通过项</div><div class="status-value">${passedCount}</div></div></div>
                    <div class="status-item ${failed > 0 ? 'warning' : 'normal'}"><div class="status-icon"><i class="fas fa-triangle-exclamation"></i></div><div class="status-info"><div class="status-label">未通过项</div><div class="status-value">${failed}</div></div></div>
                    <div class="status-item ${xinchuangFailed > 0 ? 'warning' : 'normal'}"><div class="status-icon"><i class="fas fa-landmark"></i></div><div class="status-info"><div class="status-label">信创基线异常</div><div class="status-value">${xinchuangFailed}</div></div></div>
                </div>
            </div>`;

        const getXinchuangObject = (item) => {
            const text = `${item.name || item.check || item.check_name || ''} ${item.category || ''} ${item.description || ''}`;
            if (/达梦|dameng|dm8/i.test(text)) return { name: '达梦数据库', icon: 'database' };
            if (/金仓|kingbase/i.test(text)) return { name: '人大金仓', icon: 'database' };
            if (/东方通|tongweb/i.test(text)) return { name: '东方通 TongWeb', icon: 'layer-group' };
            if (/麒麟|kylin/i.test(text)) return { name: '银河麒麟', icon: 'server' };
            if (/统信|uos/i.test(text)) return { name: '统信 UOS', icon: 'server' };
            return { name: '信创组件', icon: 'landmark' };
        };
        const getXinchuangDirection = (item) => {
            const text = `${item.name || item.check || item.check_name || ''} ${item.category || ''} ${item.description || ''} ${item.remediation || ''}`;
            if (/默认.*端口|端口|port/i.test(text)) return '默认端口';
            if (/权限|permission|配置文件|文件权限/i.test(text)) return '权限配置';
            if (/后台|管理入口|路径|console|admin/i.test(text)) return '管理入口';
            if (/口令|密码|password/i.test(text)) return '口令策略';
            if (/审计|audit/i.test(text)) return '审计配置';
            if (/防火墙|firewall/i.test(text)) return '防火墙配置';
            if (/ssh/i.test(text)) return '远程访问';
            return '专项基线';
        };
        const xinchuangPairs = {};
        xinchuangItems.forEach(item => {
            const obj = getXinchuangObject(item);
            const direction = getXinchuangDirection(item);
            const key = `${obj.name}__${direction}`;
            if (!xinchuangPairs[key]) {
                xinchuangPairs[key] = { object: obj.name, icon: obj.icon, direction, total: 0, failed: 0 };
            }
            xinchuangPairs[key].total += 1;
            if (!isPassedItem(item)) xinchuangPairs[key].failed += 1;
        });
        const pairList = Object.values(xinchuangPairs);

        html += `
            <div class="card" style="margin-bottom: 20px;">
                <h3><i class="fas fa-flag"></i> 信创专项基线</h3>
                <p class="module-desc">针对国产操作系统、数据库和中间件的专项安全基线，重点识别默认端口、敏感配置、管理入口暴露等风险。</p>
                ${pairList.length ? `<div class="xinchuang-pair-grid">
                    ${pairList.map(pair => `<div class="xinchuang-pair-card ${pair.failed > 0 ? 'warning' : 'normal'}">
                        <div class="xinchuang-pair-icon"><i class="fas fa-${pair.icon}"></i></div>
                        <div class="xinchuang-pair-main">
                            <div class="xinchuang-object">${pair.object}</div>
                            <div class="xinchuang-direction">检查方向：${pair.direction}</div>
                            <div class="xinchuang-result ${pair.failed > 0 ? 'warn' : 'safe'}">${pair.failed > 0 ? `${pair.failed} 项异常` : '检查通过'}</div>
                        </div>
                    </div>`).join('')}
                </div>` : `<div class="empty-state xinchuang-empty"><i class="fas fa-landmark"></i><h3>暂无信创专项结果</h3><p>当前扫描结果中未返回国产系统、数据库或中间件专项检查项。</p></div>`}
            </div>`;

        if (Object.keys(categories).length > 0) {
            const categoryNames = {
                xinchuang_baseline: '信创专项基线',
                security_baseline: '通用安全基线',
                file_integrity: '文件完整性',
                account_security: '账号安全',
                password_policy: '密码策略',
                password: '密码策略',
                weak_password: '弱口令检查',
                ssh: 'SSH 安全',
                mysql: 'MySQL 安全',
                nginx: 'Nginx 安全',
                network_security: '网络安全',
                firewall: '防火墙',
                system_security: '系统安全'
            };
            const mergedCategories = {};
            Object.entries(categories).forEach(([name, value]) => {
                const label = categoryNames[name] || this.getCategoryLabel(name) || name;
                const count = typeof value === 'object' ? (value.total || value.failed || value.count || 0) : value;
                mergedCategories[label] = (mergedCategories[label] || 0) + (Number(count) || 0);
            });
            html += `<div class="card" style="margin-bottom: 20px;"><h3><i class="fas fa-layer-group"></i> 分类统计</h3><div class="status-grid status-grid-balanced category-grid">`;
            Object.entries(mergedCategories).forEach(([label, count]) => {
                html += `<div class="status-item normal"><div class="status-icon"><i class="fas fa-tag"></i></div><div class="status-info"><div class="status-label">${label}</div><div class="status-value">${count}</div></div></div>`;
            });
            html += `</div></div>`;
        }

        html += `<div class="card"><div class="tech-panel-header"><h3 style="margin:0;"><i class="fas fa-clipboard-check"></i> 合规检查明细</h3>
            <div class="vuln-filters compact-filters">
                <button class="filter-btn ${this.currentComplianceFilter === 'all' ? 'active' : ''}" onclick="window.secKeeperApp.setComplianceFilter('all')">全部 (${checks.length})</button>
                <button class="filter-btn ${this.currentComplianceFilter === 'failed' ? 'active' : ''}" onclick="window.secKeeperApp.setComplianceFilter('failed')">未通过 (${failed})</button>
                <button class="filter-btn ${this.currentComplianceFilter === 'passed' ? 'active' : ''}" onclick="window.secKeeperApp.setComplianceFilter('passed')">已通过 (${passedCount})</button>
                <button class="filter-btn ${this.currentComplianceFilter === 'xinchuang' ? 'active' : ''}" onclick="window.secKeeperApp.setComplianceFilter('xinchuang')">信创专项 (${xinchuangItems.length})</button>
            </div></div>`;

        if (filteredChecks.length === 0) {
            html += '<div class="empty-state"><i class="fas fa-filter"></i><h3>没有匹配的检查项</h3></div>';
        } else {
            filteredChecks.forEach(item => {
                const isPassed = isPassedItem(item);
                const isXinchuang = isXinchuangItem(item);
                html += `
                    <div class="tech-panel ${isPassed ? 'status-pass' : 'status-fail'}">
                        <div class="tech-panel-header">
                            <div class="compliance-title-line">
                                <strong class="tech-panel-title">${item.name || item.check || item.check_name || '未命名检查项'}</strong>
                                <span class="compliance-title-badges">
                                    ${item.category ? `<span class="tech-chip"><i class="fas fa-tag"></i> ${this.getCategoryLabel(item.category)}</span>` : ''}
                                    ${isXinchuang ? '<span class="tech-chip"><i class="fas fa-landmark"></i> 信创专项</span>' : ''}
                                </span>
                            </div>
                            <div style="display:flex; gap:7px; align-items:center; flex-wrap:wrap;">
                                <span class="tech-chip ${isPassed ? 'safe' : 'danger'}"><i class="fas ${isPassed ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${isPassed ? '通过' : '未通过'}</span>
                            </div>
                        </div>
                        <div class="tech-panel-desc">${item.description || '无详细描述'}</div>
                        ${!isPassed && item.remediation ? `<div class="tech-remediation"><strong><i class="fas fa-wrench"></i> 修复建议:</strong> ${item.remediation}</div>` : ''}
                    </div>`;
            });
        }
        complianceTab.innerHTML = html + '</div>';
    }

    setComplianceFilter(filterType) {
        this.currentComplianceFilter = filterType;
        this.displayComplianceData();
    }

    displayVulnerabilityData() {
        const vulnTab = document.getElementById('vulnerabilities');
        const vulns = this.getVulnerabilityList();

        if (vulns.length === 0) {
            vulnTab.innerHTML = '<div class="card"><div class="empty-state"><i class="fas fa-shield-check"></i><h3>系统处于安全状态</h3><p>本次扫描未发现风险漏洞</p></div></div>';
            return;
        }

        const counts = this.getVulnFilterCounts(vulns);
        let html = `
        ${this.renderVerificationSummaryCards()}
        <div class="card vuln-filter-card">
            <div class="tech-panel-header">
                <div>
                    <h3 style="margin:0 0 6px 0;"><i class="fas fa-bug"></i> 漏洞扫描结果</h3>
                    <p class="module-desc" style="margin:0;">按验证结论、验证方式和风险类型筛选扫描结果。</p>
                </div>
                <div class="vuln-filters compact-filters">
                    <button class="filter-btn ${this.currentVulnFilter === 'all' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('all')">全部风险 (${vulns.length})</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'verified' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('verified')">已验证风险 (${counts.verified})</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'suspected' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('suspected')">疑似风险 (${counts.suspected})</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'manual' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('manual')">待核验项 (${counts.manual})</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'local' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('local')">本地 PoC 验证 (${counts.local})</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'network' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('network')">Nuclei 网络验证 (${counts.network})</button>
                </div>
            </div>
        </div>
        <div id="vuln-list-container"></div>`;

        vulnTab.innerHTML = html;
        this.renderFilteredVulnList(vulns);
    }

    getVulnFilterCounts(vulns) {
        return vulns.reduce((acc, v) => {
            const status = this.normalizeVulnStatus(v);
            const method = (v.verification_method || '').toLowerCase();
            if (status === 'verified') acc.verified++;
            else if (status === 'needs_manual_check') acc.manual++;
            else acc.suspected++;
            if (method === 'local') acc.local++;
            if (method === 'network') acc.network++;
            return acc;
        }, { verified: 0, suspected: 0, manual: 0, local: 0, network: 0 });
    }

    normalizeVulnStatus(v) {
        const title = String(v.title || '');
        const raw = (v.verification_status || '').toLowerCase();
        if (raw === 'verified' || title.includes('实锤')) return 'verified';
        if (raw === 'needs_manual_check' || raw === 'manual' || (v.tags && v.tags.includes('kernel'))) return 'needs_manual_check';
        return 'unverified';
    }

    setVulnFilter(filterType) {
        this.currentVulnFilter = filterType;
        this.displayVulnerabilityData();
    }

    // 暴露给 HTML 的开关事件
    toggleVerifiedOnly(isChecked) {
        this.showVerifiedOnly = isChecked;
        this.displayVulnerabilityData();
    }

    renderFilteredVulnList(vulns) {
        const container = document.getElementById('vuln-list-container');
        if (!container) return;

        let filteredVulns = vulns.filter(v => {
            const status = this.normalizeVulnStatus(v);
            const method = (v.verification_method || '').toLowerCase();
            if (this.currentVulnFilter === 'verified') return status === 'verified';
            if (this.currentVulnFilter === 'suspected') return status === 'unverified';
            if (this.currentVulnFilter === 'manual') return status === 'needs_manual_check';
            if (this.currentVulnFilter === 'local') return method === 'local';
            if (this.currentVulnFilter === 'network') return method === 'network';
            return true;
        });

        if (filteredVulns.length === 0) {
            container.innerHTML = '<div class="card"><div class="empty-state"><i class="fas fa-clipboard-check"></i><h3>无匹配的风险条目</h3><p>可以切换筛选条件查看其他类型风险。</p></div></div>';
            return;
        }

        const originalCount = filteredVulns.length;
        const manualCount = filteredVulns.filter(v => this.normalizeVulnStatus(v) === 'needs_manual_check').length;
        filteredVulns.sort((a, b) => {
            const orderStatus = { verified: 0, unverified: 1, needs_manual_check: 2 };
            const orderSeverity = { critical: 0, high: 1, medium: 2, low: 3 };
            const sa = orderStatus[this.normalizeVulnStatus(a)] ?? 9;
            const sb = orderStatus[this.normalizeVulnStatus(b)] ?? 9;
            if (sa !== sb) return sa - sb;
            return (orderSeverity[(a.severity || 'low').toLowerCase()] ?? 9) - (orderSeverity[(b.severity || 'low').toLowerCase()] ?? 9);
        });

        const renderLimit = this.currentVulnFilter === 'manual' ? 160 : 120;
        const displayList = filteredVulns.slice(0, renderLimit);
        let html = '';
        if (originalCount > renderLimit) {
            html += `<div class="kernel-notice list-limit-notice"><i class="fas fa-circle-info"></i> 当前筛选共 ${originalCount} 条风险，页面先展示前 ${renderLimit} 条。内核版本类风险数量较多，建议结合发行版补丁公告批量确认。</div>`;
        }
        if (manualCount > 50 && this.currentVulnFilter === 'all') {
            html += `<div class="kernel-notice list-limit-notice"><i class="fas fa-shield-halved"></i> 发现 ${manualCount} 条待核验项，主要为内核版本命中。此类结果不等同于实锤漏洞，建议切换“已验证风险”查看确认风险。</div>`;
        }

        displayList.forEach(vuln => {
            const sev = (vuln.severity || 'low').toLowerCase();
            const status = this.normalizeVulnStatus(vuln);
            const isManual = status === 'needs_manual_check';
            const severityClass = isManual ? 'manual' : (sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low');
            const severityLabel = isManual ? '待确认' : ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[sev] || sev.toUpperCase());
            const targets = vuln.affected_targets ? vuln.affected_targets.join(', ') : (vuln.affected_target || '系统组件');
            const kernelNotice = isManual ? `
                <div class="kernel-notice">
                    <i class="fas fa-info-circle"></i>
                    <strong>说明：</strong>Linux 发行版常通过补丁回移修复内核漏洞，版本命中不代表一定存在可利用漏洞，需结合发行版安全公告或补丁记录确认。
                </div>` : '';
            const panelStatus = status === 'verified' ? 'status-fail' : (isManual ? 'status-info' : 'status-warn');
            html += `
                <div class="tech-panel ${panelStatus} ${isManual ? 'kernel-muted' : ''}">
                    <div class="tech-panel-header">
                        <div class="vuln-title-line">
                            <strong class="tech-panel-title">${this.cleanVulnTitle(vuln.title || vuln.vuln_id || '未知风险')}</strong>
                            <span class="vuln-title-badges">${this.renderVulnVerificationBadges(vuln, true)}</span>
                        </div>
                        <span class="risk-severity ${severityClass}">${severityLabel}</span>
                    </div>
                    ${kernelNotice}
                    <div class="tech-panel-desc"><strong><i class="fas fa-align-left"></i> 描述:</strong> ${vuln.description || '暂无描述'}</div>
                    <div class="tech-meta"><i class="fas fa-crosshairs"></i><strong>影响组件:</strong> ${targets}</div>
                    ${vuln.remediation ? `<div class="tech-remediation"><strong><i class="fas fa-wrench"></i> 修复建议:</strong> ${vuln.remediation}</div>` : ''}
                </div>`;
        });
        container.innerHTML = html;
    }


    cleanVulnTitle(title) {
        return String(title || '')
            .replace(/^[🔴🟡⚪⚫🔵🟢\s]+/g, '')
            .replace(/\[(实锤漏洞|疑似漏洞|待确认|已验证风险|疑似风险|待核验项)\]/g, '')
            .trim();
    }

    getCategoryLabel(value) {
        const map = {
            xinchuang_baseline: '信创专项基线',
            security_baseline: '通用安全基线',
            file_integrity: '文件权限基线',
            account_security: '账号安全基线',
            password_policy: '密码策略',
            network_security: '网络安全基线',
            config: '配置基线',
            cve: 'CVE 漏洞',
            service: '网络服务漏洞',
            privilege_escalation: '提权风险',
            threat: '后门与威胁',
        };
        return map[value] || value || '未分类';
    }

    getVulnerabilityList() {
        return this.currentData.vulnerabilities?.details || this.currentData.vulnerabilities?.vulnerabilities || [];
    }

    getVerificationSummary() {
        const serverSummary = this.currentData.vulnerabilities?.verification_summary || this.currentData.verificationSummary || {};
        const vulns = this.getVulnerabilityList();
        const summary = {
            verified: Number(serverSummary.verified || 0),
            unverified: Number(serverSummary.unverified || 0),
            needs_manual_check: Number(serverSummary.needs_manual_check || serverSummary.manual || 0),
            local: Number(serverSummary.local || 0),
            network: Number(serverSummary.network || 0),
            version: Number(serverSummary.version || 0)
        };
        if (Object.values(summary).some(v => v > 0) || vulns.length === 0) return summary;

        vulns.forEach(v => {
            const status = v.verification_status || (String(v.title || '').includes('实锤') ? 'verified' : 'unverified');
            if (status === 'verified') summary.verified += 1;
            else if (status === 'needs_manual_check') summary.needs_manual_check += 1;
            else summary.unverified += 1;

            const method = (v.verification_method || '').toLowerCase();
            if (method === 'local') summary.local += 1;
            else if (method === 'network') summary.network += 1;
            else if (method === 'version') summary.version += 1;
        });
        return summary;
    }

    getXinchuangSummary() {
        return this.currentData.compliance?.xinchuang_summary || this.currentData.xinchuangSummary || {};
    }

    getSafetyLabel(value) {
        const map = {
            safe_probe: '无害化探测',
            version_probe: '版本探针',
            environment_probe: '环境探针',
            active_probe: '深度验证',
            auth_probe: '授权/口令探测',
            sensitive_read: '敏感信息读取验证',
            oob: 'OOB 探测',
            version_match:'版本匹配'
        };
        return map[value] || value || '未标注';
    }

    getMethodLabel(value) {
        const map = { local: '本地 PoC 验证', network: 'Nuclei 网络验证', version: '版本匹配' };
        return map[value] || value || '未标注';
    }

    renderVerificationSummaryCards() {
        const summary = this.getVerificationSummary();
        return `
            <div class="card" style="margin-bottom: 20px;">
                <h3><i class="fas fa-diagram-project"></i> 双核验证统计</h3>
                <p class="module-desc">本地 PoC 安全探针与 Nuclei 网络模板协同验证：先由规则库初筛候选风险，再通过无害化验证提升结果可信度。</p>
                <div class="status-grid status-grid-balanced metric-card-grid">
                    <div class="status-item ${(summary.verified || 0) > 0 ? 'warning' : 'normal'}"><div class="status-icon"><i class="fas fa-circle-check"></i></div><div class="status-info"><div class="status-label">已验证风险</div><div class="status-value">${summary.verified || 0}</div></div></div>
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-terminal"></i></div><div class="status-info"><div class="status-label">本地 PoC 验证</div><div class="status-value">${summary.local || 0}</div></div></div>
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-server"></i></div><div class="status-info"><div class="status-label">Nuclei 网络验证</div><div class="status-value">${summary.network || 0}</div></div></div>
                    <div class="status-item warning"><div class="status-icon"><i class="fas fa-circle-question"></i></div><div class="status-info"><div class="status-label">待核验项</div><div class="status-value">${summary.needs_manual_check || 0}</div></div></div>
                </div>
            </div>`;
    }

    renderVulnVerificationBadges(vuln, inline = false) {
        const method = vuln.verification_method;
        const safety = vuln.verification_safety;
        const status = vuln.verification_status || 'unverified';
        const statusMap = {
            verified: ['已验证风险', '#27ae60'],
            unverified: ['疑似风险', '#f39c12'],
            needs_manual_check: ['待核验项', '#7f8c8d']
        };
        const [statusLabel, statusColor] = statusMap[status] || [status, '#7f8c8d'];
        const statusClass = status === 'verified' ? 'verified-blue' : (status === 'needs_manual_check' ? 'muted' : 'warn');
        const methodClass = method === 'network' ? 'nuclei-chip' : '';
        const chips = `
                <span class="tech-chip ${statusClass}"><i class="fas fa-check-double"></i> ${statusLabel}</span>
                ${method ? `<span class="tech-chip ${methodClass}"><i class="fas fa-microchip"></i> ${this.getMethodLabel(method)}</span>` : ''}
                ${safety ? `<span class="tech-chip muted"><i class="fas fa-shield-halved"></i> ${this.getSafetyLabel(safety)}</span>` : ''}`;
        return inline ? chips : `<div style="display:flex; gap:6px; flex-wrap:wrap; margin:8px 0;">${chips}</div>`;
    }

    initCharts() {
        setTimeout(() => {
            this.initVulnerabilityChart();
            this.initComplianceChart();
        }, 100);
    }

    initVulnerabilityChart() {
        const el = document.getElementById('vulnPieChart');
        if (!el || typeof echarts === 'undefined') return;

        const vulns = this.getVulnerabilityList();
        const confirmedOrSuspected = vulns.filter(v => this.normalizeVulnStatus(v) !== 'needs_manual_check');
        const manualOnlyCount = vulns.length - confirmedOrSuspected.length;
        let counts = { critical: 0, high: 0, medium: 0, low: 0 };
        confirmedOrSuspected.forEach(v => { const s = (v.severity || 'low').toLowerCase(); if(counts[s] !== undefined) counts[s]++; });
        const total = Object.values(counts).reduce((a, b) => a + b, 0);

        if (this.charts.vuln) { this.charts.vuln.dispose(); }
        this.charts.vuln = echarts.init(el);
        if (total === 0) {
            this.charts.vuln.setOption({
                title: { text: manualOnlyCount > 0 ? '仅发现待核验项' : '未发现风险漏洞', subtext: manualOnlyCount > 0 ? `${manualOnlyCount} 条内核版本命中需人工确认` : '当前扫描结果为空', left: 'center', top: '38%', textStyle: { color: '#e0eeff', fontSize: 22 }, subtextStyle: { color: '#a8c8ee', fontSize: 15 } },
                graphic: [{ type: 'circle', left: 'center', top: 'middle', shape: { r: 96 }, style: { fill: 'rgba(0,200,255,0.035)', stroke: 'rgba(0,200,255,0.18)', lineWidth: 2 } }]
            });
            this.charts.vuln.resize();
            return;
        }

        this.charts.vuln.setOption({
            tooltip: { trigger: 'item', backgroundColor: 'rgba(5,13,26,0.92)', borderColor: 'rgba(0,200,255,0.25)', textStyle: { color: '#fff' } },
            legend: { bottom: 2, itemGap: 18, textStyle: { color: '#eaf6ff', fontSize: 15, fontWeight: 600 } },
            series: [{
                type: 'pie', radius: ['42%', '68%'], center: ['50%', '45%'],
                label: { color: '#ffffff', fontWeight: 700, fontSize: 15, formatter: '{b}\n{d}%' },
                labelLine: { lineStyle: { color: 'rgba(255,255,255,0.65)' } },
                data: [
                    { value: counts.critical, name: '严重', itemStyle: { color: '#ff3b6b', shadowBlur: 12, shadowColor: 'rgba(255,59,107,0.45)' } },
                    { value: counts.high, name: '高危', itemStyle: { color: '#ff6b3d', shadowBlur: 12, shadowColor: 'rgba(255,107,61,0.35)' } },
                    { value: counts.medium, name: '中危', itemStyle: { color: '#ffd166', shadowBlur: 10, shadowColor: 'rgba(255,209,102,0.32)' } },
                    { value: counts.low, name: '低危', itemStyle: { color: '#00c8ff', shadowBlur: 10, shadowColor: 'rgba(0,200,255,0.35)' } }
                ].filter(d => d.value > 0)
            }]
        });
        this.charts.vuln.resize();
    }

    initComplianceChart() {
        const el = document.getElementById('complianceChart');
        if (!el || typeof echarts === 'undefined') return;

        const summary = this.currentData.compliance?.summary || { passed: 0, total: 0 };
        const total = Number(summary.total || 0);
        const passed = Number(summary.passed || 0);
        const failed = Math.max(0, total - passed);

        if (this.charts.comp) { this.charts.comp.dispose(); }
        this.charts.comp = echarts.init(el);
        if (total === 0) {
            this.charts.comp.setOption({
                title: { text: '暂无合规数据', subtext: '完成扫描后显示检查结果', left: 'center', top: '38%', textStyle: { color: '#e0eeff', fontSize: 22 }, subtextStyle: { color: '#a8c8ee', fontSize: 15 } },
                graphic: [{ type: 'circle', left: 'center', top: 'middle', shape: { r: 96 }, style: { fill: 'rgba(0,200,255,0.035)', stroke: 'rgba(0,200,255,0.18)', lineWidth: 2 } }]
            });
            this.charts.comp.resize();
            return;
        }

        this.charts.comp.setOption({
            tooltip: { trigger: 'item', backgroundColor: 'rgba(5,13,26,0.92)', borderColor: 'rgba(0,200,255,0.25)', textStyle: { color: '#fff' } },
            legend: { bottom: 2, itemGap: 18, textStyle: { color: '#eaf6ff', fontSize: 15, fontWeight: 600 } },
            series: [{
                type: 'pie', radius: ['42%', '68%'], center: ['50%', '45%'],
                label: { color: '#ffffff', fontWeight: 700, fontSize: 15, formatter: '{b}\n{d}%' },
                labelLine: { lineStyle: { color: 'rgba(255,255,255,0.65)' } },
                data: [
                    { value: passed, name: '通过', itemStyle: { color: '#1de9b6', shadowBlur: 12, shadowColor: 'rgba(29,233,182,0.35)' } },
                    { value: failed, name: '未通过', itemStyle: { color: '#ff4d6a', shadowBlur: 12, shadowColor: 'rgba(255,77,106,0.35)' } }
                ].filter(d => d.value > 0)
            }]
        });
        this.charts.comp.resize();
    }

    refreshCharts() {
        if(this.charts.vuln) this.charts.vuln.dispose();
        if(this.charts.comp) this.charts.comp.dispose();
        this.initCharts();
    }

    async generatePDFReport() {
        try {
            this.showNotification('<i class="fas fa-file-pdf"></i> 正在生成PDF报告...', 'info');
            const pdfBlob = await this.api.generateReport({
                scan_id: this.currentData.lastScanResult?.scan_id || `report_${Date.now()}`,
                timestamp: this.currentData.lastScanResult?.timestamp || new Date().toISOString(),
                assets: { software: this.currentData.software, services: this.currentData.services, system_info: this.currentData.hostInfo || this.currentData.systemInfo || {} },
                compliance: this.currentData.compliance,
                vulnerabilities: this.currentData.vulnerabilities
            });
            const url = window.URL.createObjectURL(pdfBlob);
            const a = document.createElement('a');
            a.href = url; a.download = `seckeeper_report_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a); a.click(); window.URL.revokeObjectURL(url); a.remove();
            this.showNotification('PDF报告已生成', 'success');
        } catch (error) {
            this.showNotification('生成失败: ' + error.message, 'error');
        }
    }

    showNotification(message, type = 'info') {
        const notif = document.createElement('div');
        notif.className = `sk-toast ${type}`;
        notif.innerHTML = message;
        document.body.appendChild(notif);
        setTimeout(() => {
            notif.classList.add('fade-out');
            setTimeout(() => notif.remove(), 320);
        }, 3200);
    }

    startAutoRefresh() { setInterval(() => { if(this.currentTab === 'dashboard') this.loadDashboardData(); }, 60000); }
    refreshCurrentTab() { this.loadTabData(this.currentTab); }
}

function startFullScan() { window.secKeeperApp.startFullScan(); }
function generatePDFReport() { window.secKeeperApp.generatePDFReport(); }
document.addEventListener('DOMContentLoaded', () => { window.secKeeperApp = new SecKeeperApp(); });