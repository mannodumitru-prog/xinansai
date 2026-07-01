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
            vulnerabilities: []
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
            this.currentData.vulnerabilities = { scan_summary: { total_vulnerabilities: 0 }, details: [] };

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
        banner.style.cssText = 'background: linear-gradient(90deg, rgba(0,65,120,0.82), rgba(0,95,165,0.75), rgba(0,65,120,0.82)); color: #e0eeff; padding: 12px; text-align: center; font-size: 15px; font-weight: 500; animation: slideIn 0.5s; border-bottom: 1px solid rgba(0,200,255,0.2);';
        banner.innerHTML = '<i class="fas fa-exclamation-triangle"></i> 当前显示的是历史扫描记录。系统状态可能已发生改变，建议立即点击【一键全面扫描】获取最新安全态势。';
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
                if (versionEl) versionEl.textContent = 'v' + res.data.db_version;
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

                                if(finalResult.assets) {
                                    this.currentData.software = finalResult.assets.software || [];
                                    this.currentData.services = finalResult.assets.services || [];
                                    if (finalResult.assets.system_info) {
                                        this.currentData.hostInfo = finalResult.assets.system_info;
                                        this.currentData.systemInfo = finalResult.assets.system_info;
                                    }
                                }
                                if(finalResult.compliance) this.currentData.compliance = finalResult.compliance;
                                if(finalResult.vulnerabilities) this.currentData.vulnerabilities = finalResult.vulnerabilities;

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

        let highRiskCount = 0;
        const vulns = this.currentData.vulnerabilities?.details || this.currentData.vulnerabilities?.vulnerabilities || [];
        vulns.forEach(v => {
            if ((v.severity || v.level) === 'high' || (v.severity || v.level) === 'critical') highRiskCount++;
        });

        document.getElementById('total-assets').textContent = softwareCount + serviceCount;
        document.getElementById('compliance-rate').textContent = complianceRate + '%';
        document.getElementById('high-risk-count').textContent = highRiskCount;
    }

    displayRealTimeStatus() {
        const isHealthy = document.getElementById('high-risk-count').textContent === "0";
        const statusData = [
            { icon: 'microchip', label: '系统状态', value: isHealthy ? '健康' : '异常', status: isHealthy ? 'normal' : 'warning' },
            { icon: 'box', label: '软件数量', value: this.currentData.software.length || 0, status: 'normal' },
            { icon: 'cogs', label: '服务数量', value: this.currentData.services.length || 0, status: 'normal' },
            { icon: 'shield-alt', label: '合规率', value: document.getElementById('compliance-rate').textContent, status: 'normal' }
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
                <h4 style="color: #2c3e50; margin-bottom: 15px; display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-box"></i> 已安装软件 (${this.currentData.software.length}个)
                </h4>
                <table class="data-table">
                    <thead><tr><th><i class="fas fa-cube"></i> 名称</th><th><i class="fas fa-code-branch"></i> 版本</th><th><i class="fas fa-info-circle"></i> 状态</th></tr></thead>
                    <tbody>
                        ${this.currentData.software.slice(0, 100).map(pkg => `
                            <tr>
                                <td><i class="fas fa-cube" style="color: #3498db; margin-right: 8px;"></i>${pkg.name || pkg.package_name || '未知软件'}</td>
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
        const checks = data.checks || data.details || [];

        if (checks.length === 0) {
            complianceTab.innerHTML = '<div class="card"><div style="text-align:center; padding:40px; color:#7f8c8d;"><i class="fas fa-shield-alt" style="font-size:48px; margin-bottom:20px;"></i><h3>暂无合规检查数据</h3><p>请点击一键扫描获取最新状态</p></div></div>';
            return;
        }

        let html = `<div class="card"><h3><i class="fas fa-shield-alt"></i> 安全合规检查</h3><p style="margin-bottom: 20px;">共检查 <strong>${summary.total || 0}</strong> 项，通过率: <strong>${summary.compliance_rate || 0}%</strong></p>`;

        checks.forEach(item => {
            const isPassed = item.passed;
            const statusColor = isPassed ? '#27ae60' : '#e74c3c';
            html += `
                <div style="padding: 16px; margin: 12px 0; border-radius: 8px; border-left: 4px solid ${statusColor}; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong>${item.name || item.check}</strong>
                        <span style="color: ${statusColor}; font-weight: bold;"><i class="fas ${isPassed ? 'fa-check-circle' : 'fa-times-circle'}"></i> ${isPassed ? '通过' : '失败'}</span>
                    </div>
                    <div style="color: #666; margin-top: 8px; font-size: 13px;">${item.description || '无详细描述'}</div>
                    ${!isPassed && item.remediation ? `<div style="color: #e67e22; margin-top: 6px; font-size: 12px;"><i class="fas fa-wrench"></i> 修复建议: ${item.remediation}</div>` : ''}
                </div>`;
        });
        complianceTab.innerHTML = html + '</div>';
    }

    // 🟢 重点：重构漏洞渲染逻辑，加入分类和 PoC 过滤功能
    displayVulnerabilityData() {
        const vulnTab = document.getElementById('vulnerabilities');
        const vulns = this.currentData.vulnerabilities?.details || this.currentData.vulnerabilities?.vulnerabilities || [];

        if (vulns.length === 0) {
            vulnTab.innerHTML = '<div class="card"><div style="text-align:center; padding:40px; color:#27ae60;"><i class="fas fa-shield-check" style="font-size:48px; margin-bottom:20px;"></i><h3>系统处于安全状态</h3><p>本次扫描未发现风险漏洞</p></div></div>';
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
                </div>
                <label class="verified-toggle">
                    <input type="checkbox" id="verified-checkbox" ${this.showVerifiedOnly ? 'checked' : ''} onchange="window.secKeeperApp.toggleVerifiedOnly(this.checked)">
                    🎯 仅看 🔴[实锤] 漏洞
                </label>
            </div>
        </div>
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

            // 2. 根据实锤开关过滤
            let matchVerified = true;
            if (this.showVerifiedOnly) {
                const title = (v.title || '');
                matchVerified = (v.verification_status === 'verified' || title.includes('🔴') || title.includes('实锤'));
            }

            return matchCategory && matchVerified;
        });

        if (filteredVulns.length === 0) {
            container.innerHTML = '<div class="card" style="text-align:center; padding:40px; color:#7f8c8d;"><i class="fas fa-clipboard-check" style="font-size: 48px; color: #bdc3c7; margin-bottom: 15px;"></i><h3>无匹配的风险条目</h3></div>';
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
                <div style="margin: 8px 0; padding: 8px 12px; background: #f0f0f0; border-radius: 4px; font-size: 12px; color: #666;">
                    <i class="fas fa-info-circle"></i>
                    <strong>注：</strong>发行版内核会向后移植安全补丁，实际修复状态需通过
                    <code>apt-cache changelog linux-image-$(uname -r)</code>
                    或查阅发行版安全公告确认，此条目仅供参考。
                </div>` : '';

            html += `
                <div style="padding: 18px; margin-bottom: 15px; border-radius: 8px; border-left: 4px solid ${color}; background: ${isKernel ? '#fafafa' : '#fff'}; box-shadow: 0 2px 4px rgba(0,0,0,0.1); ${isKernel ? 'opacity: 0.85;' : ''}">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <strong style="color: ${color}; font-size: 1.1em;">${vuln.title || vuln.vuln_id || '未知风险'}</strong>
                        <span style="padding: 2px 8px; background: ${color}; color: white; border-radius: 3px; font-size: 12px;">${sevLabel}</span>
                    </div>
                    ${kernelNotice}
                    <div style="font-size: 13px; margin-bottom: 5px;"><strong><i class="fas fa-align-left" style="color: #7f8c8d;"></i> 描述:</strong> ${vuln.description || ''}</div>
                    <div style="font-size: 13px; margin-bottom: 5px;"><strong><i class="fas fa-crosshairs" style="color: #7f8c8d;"></i> 影响组件:</strong> ${targets}</div>
                    ${vuln.remediation ? `<div style="font-size: 13px; color: #27ae60; margin-top: 8px; padding-top: 8px; border-top: 1px dashed #eee;"><strong><i class="fas fa-wrench"></i> 修复建议:</strong> ${vuln.remediation}</div>` : ''}
                </div>`;
        });
        container.innerHTML = html;
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

        const vulns = this.currentData.vulnerabilities?.details || this.currentData.vulnerabilities?.vulnerabilities || [];
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
                scan_id: `report_${Date.now()}`,
                assets: { software: this.currentData.software, services: this.currentData.services },
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