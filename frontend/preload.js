// 预加载脚本

const { contextBridge, ipcRenderer } = require('electron');
const qrcode = require('qrcode'); 
const { v4: uuidv4 } = require('uuid'); // 引入 uuid

contextBridge.exposeInMainWorld('electronAPI', {
    sendApiRequest: (args) => ipcRenderer.invoke('api-request', args),
    generateQRCodeDataURL: (text) => {
        return new Promise((resolve, reject) => {
            qrcode.toDataURL(text, (err, url) => {
                if (err) {
                console.error('QR Code generation error:', err);
                reject(err);
                } else {
                resolve(url);
                }
            });
        });
    },
    getDeviceId: () => { // 用于获取或生成设备 ID
        let deviceId = localStorage.getItem('deviceId');
        if (!deviceId) {
            deviceId = uuidv4();
            localStorage.setItem('deviceId', deviceId);
        }
        return deviceId;
    },
    storeValue: (key, value) => {
        localStorage.setItem(key, value);
    },
    getValue: (key) => {
        return localStorage.getItem(key);
    },
    removeValue: (key) => {
        localStorage.removeItem(key);
    }
});