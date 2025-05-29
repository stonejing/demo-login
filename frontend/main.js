// 描述: Electron 的主进程文件。
// 负责创建浏览器窗口和处理系统事件。
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

// 后端 API 的基础 URL
const API_BASE_URL = 'http://localhost:8080'; // 确保这与您的 Go 服务运行的地址和端口一致

function createWindow () {
  const mainWindow = new BrowserWindow({
    width: 1000,
    height: 850, // 稍微增加高度以容纳新元素
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: true
    }
  });

  mainWindow.loadFile('index.html');
  mainWindow.webContents.openDevTools();
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('api-request', async (event, { method, endpoint, body, headers }) => {
  const url = `${API_BASE_URL}${endpoint}`;
  console.log(`[Main Process] API Request: ${method} ${url}`, body, headers);
  try {
    const fetch = (await import('node-fetch')).default; 
    const response = await fetch(url, {
      method: method,
      body: body ? JSON.stringify(body) : null,
      headers: {
        'Content-Type': 'application/json',
        ...headers, 
      },
    });

    // 尝试解析 JSON，但如果响应为空或不是 JSON，则优雅处理
    let responseBody;
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
        responseBody = await response.json();
    } else if (response.status === 204 || response.headers.get("content-length") === "0" ) { // No Content
        responseBody = null; // 或者 {} 或 { message: "Success, no content"}
    }
     else {
        responseBody = await response.text(); // 获取文本以进行调试
        console.warn(`[Main Process] API Response for ${method} ${url} was not JSON:`, responseBody);
    }

    console.log(`[Main Process] API Response: ${response.status}`, responseBody);
    return { status: response.status, body: responseBody };
  } catch (error) {
    console.error('[Main Process] API Request Error:', error);
    // 尝试解析错误体（如果 fetch 失败但仍有 response 对象）
    let errorBody = null;
    if (error.response && typeof error.response.json === 'function') {
        try {
            errorBody = await error.response.json();
        } catch (e) { /* ignore parsing error */ }
    } else if (error.response && typeof error.response.text === 'function') {
         try {
            errorBody = await error.response.text();
        } catch (e) { /* ignore parsing error */ }
    }
    return { error: error.message, status: error.response?.status, body: errorBody };
  }
});