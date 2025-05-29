// 描述: Electron 渲染进程的 JavaScript 文件。

document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const deviceIdDisplay = document.getElementById('deviceIdDisplay');

    const regUsernameInput = document.getElementById('regUsername');
    const regEmailInput = document.getElementById('regEmail');
    const regPasswordInput = document.getElementById('regPassword');
    const btnRegister = document.getElementById('btnRegister');

    const loginUsernameInput = document.getElementById('loginUsername');
    const loginPasswordInput = document.getElementById('loginPassword');
    const loginRememberDeviceCheckbox = document.getElementById('loginRememberDevice');
    const btnLogin = document.getElementById('btnLogin');

    const totpLoginSection = document.getElementById('totpLoginSection');
    const totpLoginUserIdSpan = document.getElementById('totpLoginUserId');
    const totpLoginDeviceIdSpan = document.getElementById('totpLoginDeviceId');
    const loginTotpCodeInput = document.getElementById('loginTotpCode');
    const totpRememberDeviceCheckbox = document.getElementById('totpRememberDevice');
    const btnLoginVerifyTotp = document.getElementById('btnLoginVerifyTotp');

    const btnGetMe = document.getElementById('btnGetMe');
    const btnRefreshToken = document.getElementById('btnRefreshToken');
    const btnLogout = document.getElementById('btnLogout');

    const totpSetupSection = document.getElementById('totpSetupSection');
    const btnSetupTotp = document.getElementById('btnSetupTotp');
    const qrCodeContainer = document.getElementById('qrCodeContainer');
    const qrCodeImage = document.getElementById('qrCodeImage');
    const manualSecretSpan = document.getElementById('manualSecret');
    const setupTotpCodeInput = document.getElementById('setupTotpCode');
    const btnVerifySetupTotp = document.getElementById('btnVerifySetupTotp');
    const btnDisableTotp = document.getElementById('btnDisableTotp');

    const trustedDevicesSection = document.getElementById('trustedDevicesSection');
    const btnListTrustedDevices = document.getElementById('btnListTrustedDevices');
    const trustedDeviceListUl = document.getElementById('trustedDeviceList');

    const accessTokenDisplay = document.getElementById('accessTokenDisplay');
    const refreshTokenDisplay = document.getElementById('refreshTokenDisplay');
    const statusLog = document.getElementById('statusLog');

    // --- State ---
    let accessToken = window.electronAPI.getValue('accessToken') || null;
    let refreshToken = window.electronAPI.getValue('refreshToken') || null;
    let currentUserIDForTOTPLogin = null; 
    let currentDeviceIDForTOTPLogin = null; // Store device ID passed from login to TOTP step
    const deviceID = window.electronAPI.getDeviceId(); // Get or generate device ID
    deviceIdDisplay.textContent = deviceID;


    updateTokenDisplays();
    updateButtonStates();
    if(accessToken) fetchInitialUserData(); // Fetch user data if already logged in

    // --- Helper Functions ---
    function logStatus(message, data) {
        const timestamp = new Date().toLocaleTimeString();
        let logEntry = `[${timestamp}] ${message}`;
        if (data !== undefined) { // Check for undefined to allow logging null/false
            try {
                logEntry += `\n${JSON.stringify(data, null, 2)}`;
            } catch (e) {
                logEntry += `\n<Unserializable data: ${e.message}>`;
            }
        }
        statusLog.textContent = logEntry + '\n\n' + statusLog.textContent.substring(0, 5000); // Keep log short
        console.log(message, data !== undefined ? data : '');
    }

    async function apiRequest(method, endpoint, body, requireAuth = false) {
        const headers = {};
        if (requireAuth && accessToken) {
            headers['Authorization'] = `Bearer ${accessToken}`;
        }

        logStatus(`请求: ${method} ${endpoint}`, body);

        try {
            const result = await window.electronAPI.sendApiRequest({ method, endpoint, body, headers });
            
            // Handle non-JSON or error responses from main process
            if (result && result.error) {
                 logStatus(`错误: ${method} ${endpoint} (状态: ${result.status || 'N/A'})`, { error: result.error, responseBody: result.body });
                if (result.status === 401 && endpoint !== '/token/refresh' && endpoint !== '/logout') { 
                    logStatus("访问令牌可能已过期或无效。");
                    // Optionally, try to refresh or prompt for re-login
                }
                return { success: false, status: result.status, data: result.body, error: result.error };
            }
            
            logStatus(`响应: ${method} ${endpoint} (状态: ${result.status})`, result.body);
            return { success: true, status: result.status, data: result.body };
        } catch (error) { // Should be caught by main process, but as a fallback
            logStatus(`严重网络或IPC错误: ${method} ${endpoint}`, { message: error.message, stack: error.stack });
            return { success: false, error: error.message };
        }
    }


    function updateTokenDisplays() {
        accessTokenDisplay.textContent = accessToken ? accessToken.substring(0, 30) + '...' : '-';
        refreshTokenDisplay.textContent = refreshToken ? refreshToken.substring(0, 30) + '...' : '-';
    }

    function updateButtonStates() {
        const loggedIn = !!accessToken;
        btnGetMe.disabled = !loggedIn;
        btnRefreshToken.disabled = !refreshToken; 
        btnLogout.disabled = !loggedIn && !refreshToken; 
        totpSetupSection.style.display = loggedIn ? 'block' : 'none';
        trustedDevicesSection.style.display = loggedIn ? 'block' : 'none';
    }
    
    async function fetchInitialUserData() {
        if (!accessToken) return;
        const result = await apiRequest('GET', '/me', null, true);
        if (result.success && result.data) {
            btnDisableTotp.style.display = result.data.is_totp_enabled ? 'inline-block' : 'none';
            btnSetupTotp.style.display = result.data.is_totp_enabled ? 'none' : 'inline-block';
            if (result.data.is_totp_enabled) {
                 qrCodeContainer.style.display = 'none'; 
            }
            await listTrustedDevices(); // Also list devices on login
        }
    }


    function storeTokens(newAccessToken, newRefreshToken) {
        accessToken = newAccessToken;
        refreshToken = newRefreshToken;
        if (newAccessToken) window.electronAPI.storeValue('accessToken', newAccessToken);
        else window.electronAPI.removeValue('accessToken');
        if (newRefreshToken) window.electronAPI.storeValue('refreshToken', newRefreshToken);
        else window.electronAPI.removeValue('refreshToken');
        updateTokenDisplays();
        updateButtonStates();
        if (newAccessToken) {
            fetchInitialUserData(); // Fetch user data after successful login/token update
        }
    }

    // --- Event Listeners ---
    btnRegister.addEventListener('click', async () => {
        console.log("注册按钮被点击");
        const username = regUsernameInput.value;
        const email = regEmailInput.value;
        const password = regPasswordInput.value;
        if (!username || !email || !password) {
            logStatus("注册错误: 所有字段均为必填项。");
            return;
        }
        const result = await apiRequest('POST', '/register', { username, email, password });
        if (result.success && result.status === 201) {
            logStatus("注册成功!", result.data);
            regUsernameInput.value = '';
            regEmailInput.value = '';
            regPasswordInput.value = '';
        }
    });

    btnLogin.addEventListener('click', async () => {
        const username = loginUsernameInput.value;
        const password = loginPasswordInput.value;
        const rememberDevice = loginRememberDeviceCheckbox.checked;

        if (!username || !password) {
            logStatus("登录错误: 用户名和密码均为必填项。");
            return;
        }
        const payload = { username, password, device_id: deviceID, remember_device: rememberDevice };
        const result = await apiRequest('POST', '/login', payload);

        if (result.success && result.data) {
            if (result.data.trusted_device) {
                logStatus("从受信任的设备登录成功!", { access_token: "...", refresh_token: "..."});
                storeTokens(result.data.access_token, result.data.refresh_token);
                totpLoginSection.style.display = 'none';
            } else if (result.data.totp_required) {
                logStatus("登录需要 TOTP 验证。", result.data);
                currentUserIDForTOTPLogin = result.data.user_id;
                currentDeviceIDForTOTPLogin = result.data.device_id || deviceID; // Use deviceID from response or current
                totpLoginUserIdSpan.textContent = currentUserIDForTOTPLogin;
                totpLoginDeviceIdSpan.textContent = currentDeviceIDForTOTPLogin;
                totpLoginSection.style.display = 'block';
                storeTokens(null, null); 
            } else if (result.data.access_token && result.data.refresh_token) {
                logStatus("登录成功 (未启用TOTP 或 设备已在登录时记住)!", { access_token: "...", refresh_token: "..."});
                storeTokens(result.data.access_token, result.data.refresh_token);
                totpLoginSection.style.display = 'none';
            }
        } else {
             logStatus("登录失败。", result.data || result.error);
        }
    });

    btnLoginVerifyTotp.addEventListener('click', async () => {
        const code = loginTotpCodeInput.value;
        const rememberDevice = totpRememberDeviceCheckbox.checked;

        if (!currentUserIDForTOTPLogin || !code) {
            logStatus("TOTP 登录错误: 用户 ID 或 TOTP 码缺失。");
            return;
        }
        const payload = { 
            user_id: currentUserIDForTOTPLogin, 
            code, 
            device_id: currentDeviceIDForTOTPLogin, 
            remember_device: rememberDevice 
        };
        const result = await apiRequest('POST', '/login/verify-totp', payload);

        if (result.success && result.data && result.data.access_token && result.data.refresh_token) {
            logStatus("TOTP 登录成功!", { access_token: "...", refresh_token: "..."});
            storeTokens(result.data.access_token, result.data.refresh_token);
            totpLoginSection.style.display = 'none';
            loginTotpCodeInput.value = '';
            currentUserIDForTOTPLogin = null;
            currentDeviceIDForTOTPLogin = null;
        } else {
            logStatus("TOTP 登录失败。", result.data || result.error);
        }
    });

    btnGetMe.addEventListener('click', fetchInitialUserData); // Re-use the function

    btnRefreshToken.addEventListener('click', async () => {
        if (!refreshToken) {
            logStatus("刷新令牌错误: 没有可用的刷新令牌。");
            return;
        }
        const result = await apiRequest('POST', '/token/refresh', { refresh_token: refreshToken });
        if (result.success && result.data && result.data.access_token) {
            logStatus("令牌刷新成功!", { access_token: "..." });
            storeTokens(result.data.access_token, refreshToken); 
        } else {
            logStatus("令牌刷新失败。可能需要重新登录。", result.data || result.error);
            storeTokens(null, null); 
        }
    });

    btnLogout.addEventListener('click', async () => {
        if (!refreshToken && !accessToken) {
            logStatus("登出: 本地没有令牌。");
            storeTokens(null, null); 
            return;
        }
        let payload = {};
        if (refreshToken) {
            payload.refresh_token = refreshToken;
        } else {
            logStatus("登出: 没有刷新令牌可发送给后端。仅清除本地令牌。");
            storeTokens(null, null);
            trustedDeviceListUl.innerHTML = ''; // Clear trusted devices list on logout
            return;
        }

        // Logout requires auth (access token) to identify the session to invalidate potentially,
        // and refresh token in payload to invalidate that specific refresh token.
        const result = await apiRequest('POST', '/logout', payload, true); 
        if (result.success && (result.status === 200 || result.status === 204)) {
            logStatus("登出成功 (后端已处理)。", result.data);
        } else {
            logStatus("后端登出可能失败或刷新令牌已失效。", result.data || result.error);
        }
        storeTokens(null, null); 
        trustedDeviceListUl.innerHTML = ''; // Clear trusted devices list on logout
    });

    btnSetupTotp.addEventListener('click', async () => {
        const result = await apiRequest('POST', '/2fa/setup', null, true);
        if (result.success && result.data && result.data.qr_code_url) {
            try {
                const qrDataURL = await window.electronAPI.generateQRCodeDataURL(result.data.qr_code_url);
                qrCodeImage.src = qrDataURL;
                manualSecretSpan.textContent = result.data.secret; 
                qrCodeContainer.style.display = 'block';
                btnDisableTotp.style.display = 'none'; 
            } catch (qrError) {
                logStatus("生成二维码失败", qrError);
                qrCodeContainer.style.display = 'none';
            }
        } else {
            qrCodeContainer.style.display = 'none';
        }
    });

    btnVerifySetupTotp.addEventListener('click', async () => {
        const code = setupTotpCodeInput.value;
        if (!code) {
            logStatus("TOTP 设置验证错误: 需要 TOTP 码。");
            return;
        }
        const result = await apiRequest('POST', '/2fa/verify', { code }, true);
        if (result.success && result.status === 200) {
            logStatus("TOTP 启用成功!", result.data);
            qrCodeContainer.style.display = 'none';
            setupTotpCodeInput.value = '';
            btnDisableTotp.style.display = 'inline-block'; 
            btnSetupTotp.style.display = 'none'; 
        } else {
            logStatus("TOTP 启用失败。", result.data || result.error);
        }
    });

    btnDisableTotp.addEventListener('click', async () => {
        const result = await apiRequest('POST', '/2fa/disable', {}, true);
        if (result.success && result.status === 200) {
            logStatus("TOTP 禁用成功!", result.data);
            btnDisableTotp.style.display = 'none';
            btnSetupTotp.style.display = 'inline-block'; 
        } else {
            logStatus("TOTP 禁用失败。", result.data || result.error);
        }
    });

    // Trusted Devices Management
    async function listTrustedDevices() {
        if (!accessToken) return;
        const result = await apiRequest('GET', '/me/devices', null, true);
        trustedDeviceListUl.innerHTML = ''; // Clear previous list
        if (result.success && Array.isArray(result.data)) {
            if (result.data.length === 0) {
                const li = document.createElement('li');
                li.textContent = '没有受信任的设备。';
                trustedDeviceListUl.appendChild(li);
            } else {
                result.data.forEach(device => {
                    const li = document.createElement('li');
                    const isCurrentDevice = device.device_id === deviceID;
                    li.innerHTML = `
                        ID: ${device.device_id} ${isCurrentDevice ? '<strong>(此设备)</strong>' : ''}<br>
                        描述: ${device.description || 'N/A'}<br>
                        上次使用: ${new Date(device.last_used_at).toLocaleString()}<br>
                        创建时间: ${new Date(device.created_at).toLocaleString()}
                        ${!isCurrentDevice ? `<button class="btn-remove-device" data-deviceid="${device.device_id}">移除</button>` : ''}
                    `;
                    trustedDeviceListUl.appendChild(li);
                });
            }
        } else {
            const li = document.createElement('li');
            li.textContent = '无法加载受信任的设备列表。';
            trustedDeviceListUl.appendChild(li);
        }
    }

    btnListTrustedDevices.addEventListener('click', listTrustedDevices);

    trustedDeviceListUl.addEventListener('click', async (event) => {
        if (event.target.classList.contains('btn-remove-device')) {
            const deviceIdToRemove = event.target.dataset.deviceid;
            if (confirm(`您确定要移除设备 ${deviceIdToRemove} 吗？您将需要在此设备上重新进行2FA验证（如果已启用）。`)) {
                const result = await apiRequest('DELETE', `/me/devices/${deviceIdToRemove}`, null, true);
                if (result.success && (result.status === 200 || result.status === 204)) {
                    logStatus(`设备 ${deviceIdToRemove} 已成功移除。`, result.data);
                    listTrustedDevices(); // Refresh the list
                } else {
                    logStatus(`移除设备 ${deviceIdToRemove} 失败。`, result.data || result.error);
                }
            }
        }
    });
});