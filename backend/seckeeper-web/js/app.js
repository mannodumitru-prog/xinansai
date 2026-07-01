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

        // 🟢 新增：当前漏洞列表的过滤状态
        this.currentVulnFilter = 'all';
        this.showVerifiedOnly = false;

        this.init();
    }

    async init() {
        console.log('SecKeeper 安全卫士初始化完成！');
        this.setupEventListeners();
        this.initCharts();
        this.showTab('dashboard');

        const historyData = localStorage.getItem('seckeeper_history');

        if (historyData) {
            this.currentData = JSON.parse(historyData);
            this.loadDashboardData();
            this.showHistoricalBanner();
            this.showNotification('<i class="fas fa-history"></i> 已加载上一次的扫描记录', 'info');
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
        const header = document.querySelector('.header');
        const banner = document.createElement('div');
        banner.id = 'history-banner';
        banner.innerHTML = '<i class="fas fa-exclamation-triangle"></i> 当前显示的是 <strong>历史扫描记录</strong>。系统状态可能已发生改变，建议立即点击【一键全面扫描】获取最新安全态势。';
        header.insertAdjacentElement('afterend', banner);
    }

    removeHistoricalBanner() {
        const banner = document.getElementById('history-banner');
        if (banner) banner.remove();
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
        button.innerHTML = '<i class="fas fa-sync-alt loading-spinner"></i> 引擎初始化中...';
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

                        if (statusData.status === 'completed' || statusData.status === 'failed') {
                            clearInterval(pollInterval);

                            if (statusData.status === 'completed') {
                                button.innerHTML = '<i class="fas fa-check-circle"></i> 数据聚合中...';
                                this.showNotification('<i class="fas fa-check-circle"></i> 扫描完成，正在渲染结果', 'success');

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

                                try {
                                    localStorage.setItem('seckeeper_history', JSON.stringify(this.currentData));
                                } catch (storageErr) {
                                    console.warn('⚠️ 资产数据量过大，已跳过本地历史记录存储', storageErr);
                                }

                                this.removeHistoricalBanner();
                                await this.loadDashboardData();
                                this.refreshCurrentTab();
                                setTimeout(() => this.refreshCharts(), 500);
                            } else {
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
            button.innerHTML = '<i class="fas fa-times-circle"></i> 扫描失败';
            this.showNotification('<i class="fas fa-times-circle"></i> 启动失败: ' + error.message, 'error');
            setTimeout(() => { button.innerHTML = originalText; button.disabled = false; }, 3000);
        }
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

        let highRiskCount = (vulnSummary.critical || 0) + (vulnSummary.high || 0);
        if (!highRiskCount) {
            const vulns = this.getVulnerabilityList();
            vulns.forEach(v => {
                const sev = (v.severity || v.level || '').toLowerCase();
                if (sev === 'high' || sev === 'critical') highRiskCount++;
            });
        }

        document.getElementById('total-assets').textContent = softwareCount + serviceCount;
        document.getElementById('compliance-rate').textContent = complianceRate + '%';
        document.getElementById('high-risk-count').textContent = highRiskCount;
        this.currentData.verificationSummary = verificationSummary;
    }

    displayRealTimeStatus() {
        const isHealthy = document.getElementById('high-risk-count').textContent === "0";
        const verificationSummary = this.getVerificationSummary();
        const xinchuangSummary = this.getXinchuangSummary();
        const xinchuangTotal = Object.values(xinchuangSummary).reduce((sum, value) => sum + (Number(value) || 0), 0);
        const statusData = [
            { icon: 'microchip', label: '系统状态', value: isHealthy ? '健康' : '异常', status: isHealthy ? 'normal' : 'warning' },
            { icon: 'box', label: '软件数量', value: this.currentData.software.length || 0, status: 'normal' },
            { icon: 'cogs', label: '服务数量', value: this.currentData.services.length || 0, status: 'normal' },
            { icon: 'shield-alt', label: '合规率', value: document.getElementById('compliance-rate').textContent, status: 'normal' },
            { icon: 'check-double', label: '已验证漏洞', value: verificationSummary.verified || 0, status: (verificationSummary.verified || 0) > 0 ? 'warning' : 'normal' },
            { icon: 'server', label: 'Network Verify', value: verificationSummary.network || 0, status: 'normal' },
            { icon: 'terminal', label: 'Local Verify', value: verificationSummary.local || 0, status: 'normal' },
            { icon: 'landmark', label: '信创专项命中', value: xinchuangTotal || 0, status: xinchuangTotal > 0 ? 'warning' : 'normal' }
        ];

        const statusGrid = document.getElementById('real-time-status');
        if (!statusGrid) return;
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
                                <td><span class="status-indicator status-safe"><i class="fas fa-check"></i> 已安装</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>`;

        assetsTab.innerHTML = systemInfoHTML + `<div class="card"><h3><i class="fas fa-desktop"></i> 资产总览</h3>${softwareHTML}</div>`;
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

        const failed = Math.max(0, (summary.total || checks.length || 0) - (summary.passed || 0));
        const xinchuangTotal = Object.values(xinchuangSummary).reduce((sum, value) => sum + (Number(value) || 0), 0);
        const xinchuangLabels = {
            kylin: '银河麒麟', uos: '统信 UOS', dameng: '达梦', kingbase: '人大金仓', tongweb: '东方通 TongWeb'
        };

        let html = `
            <div class="card" style="margin-bottom: 20px;">
                <h3><i class="fas fa-shield-alt"></i> 安全合规检查</h3>
                <div class="status-grid">
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-list-check"></i></div><div class="status-info"><div class="status-label">检查总数</div><div class="status-value">${summary.total || checks.length || 0}</div></div></div>
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-check-circle"></i></div><div class="status-info"><div class="status-label">通过项</div><div class="status-value">${summary.passed || 0}</div></div></div>
                    <div class="status-item ${failed > 0 ? 'warning' : 'normal'}"><div class="status-icon"><i class="fas fa-triangle-exclamation"></i></div><div class="status-info"><div class="status-label">未通过项</div><div class="status-value">${failed}</div></div></div>
                    <div class="status-item ${xinchuangTotal > 0 ? 'warning' : 'normal'}"><div class="status-icon"><i class="fas fa-landmark"></i></div><div class="status-info"><div class="status-label">信创专项命中</div><div class="status-value">${xinchuangTotal}</div></div></div>
                </div>
            </div>`;

        html += `
            <div class="card" style="margin-bottom: 20px;">
                <h3><i class="fas fa-flag"></i> 信创专项基线</h3>
                <p style="margin-bottom: 14px; color: var(--text-sec);">该区域来自合规检查中的 config_rules 规则，不是独立第四模块。</p>
                <div class="status-grid">
                    ${Object.entries(xinchuangLabels).map(([key, label]) => `
                        <div class="status-item ${(xinchuangSummary[key] || 0) > 0 ? 'warning' : 'normal'}">
                            <div class="status-icon"><i class="fas fa-${key === 'dameng' || key === 'kingbase' ? 'database' : 'server'}"></i></div>
                            <div class="status-info"><div class="status-label">${label}</div><div class="status-value">${xinchuangSummary[key] || 0}</div></div>
                        </div>`).join('')}
                </div>
            </div>`;

        if (Object.keys(categories).length > 0) {
            html += `<div class="card" style="margin-bottom: 20px;"><h3><i class="fas fa-layer-group"></i> 分类统计</h3><div class="status-grid">`;
            Object.entries(categories).forEach(([name, value]) => {
                const count = typeof value === 'object' ? (value.total || value.failed || 0) : value;
                html += `<div class="status-item normal"><div class="status-icon"><i class="fas fa-tag"></i></div><div class="status-info"><div class="status-label">${name}</div><div class="status-value">${count}</div></div></div>`;
            });
            html += `</div></div>`;
        }

        html += `<div class="card"><h3><i class="fas fa-clipboard-check"></i> 合规检查明细</h3>`;
        checks.forEach(item => {
            const isPassed = item.passed === true || item.status === 'passed';
            const statusColor = isPassed ? '#27ae60' : '#e74c3c';
            const isXinchuang = item.xinchuang === true || item.is_xinchuang === true || /麒麟|kylin|统信|uos|达梦|dameng|金仓|kingbase|tongweb|东方通/i.test(`${item.name || item.check || item.check_name || ''} ${item.category || ''} ${item.description || ''}`);
            html += `
                <div class="tech-panel ${isPassed ? 'status-pass' : 'status-fail'}">
                    <div class="tech-panel-header">
                        <strong class="tech-panel-title">${item.name || item.check || item.check_name || '未命名检查项'}</strong>
                        <div style="display:flex; gap:6px; align-items:center; flex-wrap:wrap;">
                            ${isXinchuang ? '<span class="tech-chip"><i class="fas fa-landmark"></i> 信创专项</span>' : ''}
                            <span class="tech-chip ${isPassed ? 'safe' : 'danger'}"><i class="fas ${isPassed ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${isPassed ? '通过' : '失败'}</span>
                        </div>
                    </div>
                    <div class="tech-panel-desc">${item.description || '无详细描述'}</div>
                    ${item.category ? `<div class="tech-meta"><i class="fas fa-tag"></i>分类: ${item.category}</div>` : ''}
                    ${!isPassed && item.remediation ? `<div class="tech-remediation"><strong><i class="fas fa-wrench"></i> 修复建议:</strong> ${item.remediation}</div>` : ''}
                </div>`;
        });
        complianceTab.innerHTML = html + '</div>';
    }

    // 🟢 重点：重构漏洞渲染逻辑，加入分类和 PoC 过滤功能
    displayVulnerabilityData() {
        const vulnTab = document.getElementById('vulnerabilities');
        const vulns = this.getVulnerabilityList();

        if (vulns.length === 0) {
            vulnTab.innerHTML = '<div class="card"><div class="empty-state"><i class="fas fa-shield-check"></i><h3>系统处于安全状态</h3><p>本次扫描未发现风险漏洞</p></div></div>';
            return;
        }

        let html = `
        <div class="card" style="margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                <div class="vuln-filters">
                    <button class="filter-btn ${this.currentVulnFilter === 'all' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('all')">全部漏洞 (${vulns.length})</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'cve' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('cve')">CVE 漏洞</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'config' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('config')">配置与越权</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'privilege' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('privilege')">提权与后门</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'kernel' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('kernel')" title="内核CVE因发行版向后移植补丁机制，版本号与上游不一致，需人工确认">⚪ 内核CVE (待确认)</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'network' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('network')">Network Verify</button>
                    <button class="filter-btn ${this.currentVulnFilter === 'local' ? 'active' : ''}" onclick="window.secKeeperApp.setVulnFilter('local')">Local Verify</button>
                </div>
                <label class="verified-toggle">
                    <input type="checkbox" id="verified-checkbox" ${this.showVerifiedOnly ? 'checked' : ''} onchange="window.secKeeperApp.toggleVerifiedOnly(this.checked)">
                    🎯 仅看 🔴[实锤] 漏洞
                </label>
            </div>
        </div>
        ${this.renderVerificationSummaryCards()}
        <div id="vuln-list-container"></div>`;

        vulnTab.innerHTML = html;
        this.renderFilteredVulnList(vulns);
    }

    // 暴露给 HTML 的点击事件
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

        // 执行双重过滤
        let filteredVulns = vulns.filter(v => {
            // 1. 根据分类标签过滤
            let matchCategory = false;
            const cat = (v.category || '').toLowerCase();
            const id = (v.vuln_id || '').toLowerCase();

            if (this.currentVulnFilter === 'all') matchCategory = true;
            else if (this.currentVulnFilter === 'cve' && (cat === 'cve' || id.includes('cve'))) {
                // CVE分类下排除内核CVE（内核CVE单独一个Tab）
                const isKernel = (v.verification_status === 'needs_manual_check') ||
                                 (v.tags && v.tags.includes('kernel'));
                matchCategory = !isKernel;
            }
            else if (this.currentVulnFilter === 'config' && (cat === 'config' || cat === 'file_integrity')) matchCategory = true;
            else if (this.currentVulnFilter === 'privilege' && (cat === 'privilege_escalation' || cat === 'threat')) matchCategory = true;
            else if (this.currentVulnFilter === 'kernel') {
                matchCategory = (v.verification_status === 'needs_manual_check') ||
                                (v.tags && v.tags.includes('kernel'));
            }
            else if (this.currentVulnFilter === 'network') matchCategory = (v.verification_method === 'network');
            else if (this.currentVulnFilter === 'local') matchCategory = (v.verification_method === 'local');

            // 2. 根据实锤开关过滤
            let matchVerified = true;
            if (this.showVerifiedOnly) {
                const title = (v.title || '');
                matchVerified = (v.verification_status === 'verified' || title.includes('🔴') || title.includes('实锤'));
            }

            return matchCategory && matchVerified;
        });

        if (filteredVulns.length === 0) {
            container.innerHTML = '<div class="card"><div class="empty-state"><i class="fas fa-clipboard-check"></i><h3>无匹配的风险条目</h3></div></div>';
            return;
        }

        let html = '';
        filteredVulns.forEach(vuln => {
            const sev = (vuln.severity || 'low').toLowerCase();
            const isKernel = (vuln.verification_status === 'needs_manual_check') ||
                             (vuln.tags && vuln.tags.includes('kernel'));

            // 内核CVE用灰色样式；普通CVE按危险等级着色
            const color = isKernel ? '#95a5a6'
                        : sev==='critical' ? '#8b0000'
                        : sev==='high'     ? '#e74c3c'
                        : sev==='medium'   ? '#f39c12'
                        :                    '#f1c40f';

            const sevLabel = isKernel ? '待确认' : sev.toUpperCase();
            const targets = vuln.affected_targets ? vuln.affected_targets.join(', ') : (vuln.affected_target || '系统组件');

            // 内核CVE额外显示一个说明提示条
            const kernelNotice = isKernel ? `
                <div class="kernel-notice">
                    <i class="fas fa-info-circle"></i>
                    <strong>注：</strong>发行版内核会向后移植安全补丁，实际修复状态需通过
                    <code>apt-cache changelog linux-image-$(uname -r)</code>
                    或查阅发行版安全公告确认，此条目仅供参考。
                </div>` : '';

            const severityClass = isKernel ? 'manual' : (sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low');
            html += `
                <div class="tech-panel status-${isKernel ? 'info' : (sev === 'critical' || sev === 'high' ? 'fail' : 'warn')} ${isKernel ? 'kernel-muted' : ''}">
                    <div class="tech-panel-header">
                        <strong class="tech-panel-title">${vuln.title || vuln.vuln_id || '未知风险'}</strong>
                        <span class="risk-severity ${severityClass}">${sevLabel}</span>
                    </div>
                    ${kernelNotice}
                    <div class="tech-panel-desc"><strong><i class="fas fa-align-left"></i> 描述:</strong> ${vuln.description || ''}</div>
                    <div class="tech-meta"><i class="fas fa-crosshairs"></i><strong>影响组件:</strong> ${targets}</div>
                    ${this.renderVulnVerificationBadges(vuln)}
                    ${vuln.remediation ? `<div class="tech-remediation"><strong><i class="fas fa-wrench"></i> 修复建议:</strong> ${vuln.remediation}</div>` : ''}
                </div>`;
        });
        container.innerHTML = html;
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
            oob: 'OOB 探测'
        };
        return map[value] || value || '未标注';
    }

    getMethodLabel(value) {
        const map = { local: 'Local Verify', network: 'Network Verify', version: 'Version Match' };
        return map[value] || value || '未标注';
    }

    renderVerificationSummaryCards() {
        const summary = this.getVerificationSummary();
        return `
            <div class="card" style="margin-bottom: 20px;">
                <h3><i class="fas fa-diagram-project"></i> 双核验证统计</h3>
                <div class="status-grid">
                    <div class="status-item warning"><div class="status-icon"><i class="fas fa-circle-check"></i></div><div class="status-info"><div class="status-label">已验证漏洞</div><div class="status-value">${summary.verified || 0}</div></div></div>
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-server"></i></div><div class="status-info"><div class="status-label">Network Verify</div><div class="status-value">${summary.network || 0}</div></div></div>
                    <div class="status-item normal"><div class="status-icon"><i class="fas fa-terminal"></i></div><div class="status-info"><div class="status-label">Local Verify</div><div class="status-value">${summary.local || 0}</div></div></div>
                    <div class="status-item warning"><div class="status-icon"><i class="fas fa-circle-question"></i></div><div class="status-info"><div class="status-label">待确认</div><div class="status-value">${summary.needs_manual_check || 0}</div></div></div>
                </div>
            </div>`;
    }

    renderVulnVerificationBadges(vuln) {
        const method = vuln.verification_method;
        const safety = vuln.verification_safety;
        const status = vuln.verification_status || 'unverified';
        const statusMap = {
            verified: ['已验证', '#27ae60'],
            unverified: ['疑似', '#f39c12'],
            needs_manual_check: ['待确认', '#7f8c8d']
        };
        const [statusLabel, statusColor] = statusMap[status] || [status, '#7f8c8d'];
        const statusClass = status === 'verified' ? 'safe' : (status === 'needs_manual_check' ? 'muted' : 'warn');
        return `
            <div style="display:flex; gap:6px; flex-wrap:wrap; margin:8px 0;">
                <span class="tech-chip ${statusClass}"><i class="fas fa-check-double"></i> ${statusLabel}</span>
                ${method ? `<span class="tech-chip"><i class="fas fa-microchip"></i> ${this.getMethodLabel(method)}</span>` : ''}
                ${safety ? `<span class="tech-chip muted"><i class="fas fa-shield-halved"></i> ${this.getSafetyLabel(safety)}</span>` : ''}
            </div>`;
    }

    initCharts() {
        setTimeout(() => {
            this.initVulnerabilityChart();
            this.initComplianceChart();
        }, 100);
    }

    initVulnerabilityChart() {
        const el = document.getElementById('vulnPieChart');
        if (!el) return;

        const vulns = this.getVulnerabilityList();
        let counts = { critical: 0, high: 0, medium: 0, low: 0 };
        vulns.forEach(v => { const s = (v.severity || 'low').toLowerCase(); if(counts[s] !== undefined) counts[s]++; });

        this.charts.vuln = echarts.init(el);
        this.charts.vuln.setOption({
            tooltip: { trigger: 'item' },
            series: [{
                type: 'pie', radius: ['40%', '70%'],
                data: [
                    { value: counts.critical, name: '严重', itemStyle: { color: '#8b0000' } },
                    { value: counts.high, name: '高危', itemStyle: { color: '#e74c3c' } },
                    { value: counts.medium, name: '中危', itemStyle: { color: '#f39c12' } },
                    { value: counts.low, name: '低危', itemStyle: { color: '#f1c40f' } }
                ]
            }]
        });
    }

    initComplianceChart() {
        const el = document.getElementById('complianceChart');
        if (!el) return;

        const summary = this.currentData.compliance?.summary || { passed: 0, total: 0 };
        const failed = Math.max(0, (summary.total || 0) - (summary.passed || 0));

        this.charts.comp = echarts.init(el);
        this.charts.comp.setOption({
            tooltip: { trigger: 'item' },
            series: [{
                type: 'pie', radius: ['40%', '70%'],
                data: [
                    { value: summary.passed || 0, name: '通过', itemStyle: { color: '#27ae60' } },
                    { value: failed, name: '未通过', itemStyle: { color: '#e74c3c' } }
                ]
            }]
        });
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
        const colors = { info: '#3498db', success: '#27ae60', warning: '#f39c12', error: '#e74c3c' };
        const notif = document.createElement('div');
        notif.style.cssText = `position: fixed; top: 20px; right: 20px; background: ${colors[type]}; color: white; padding: 15px 20px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 9999; animation: slideIn 0.3s;`;
        notif.innerHTML = message;
        document.body.appendChild(notif);
        setTimeout(() => { notif.style.opacity = '0'; notif.style.transition = '0.3s'; setTimeout(() => notif.remove(), 300); }, 3000);
    }

    startAutoRefresh() { setInterval(() => { if(this.currentTab === 'dashboard') this.loadDashboardData(); }, 60000); }
    refreshCurrentTab() { this.loadTabData(this.currentTab); }
}

function startFullScan() { window.secKeeperApp.startFullScan(); }
function generatePDFReport() { window.secKeeperApp.generatePDFReport(); }
document.addEventListener('DOMContentLoaded', () => { window.secKeeperApp = new SecKeeperApp(); });