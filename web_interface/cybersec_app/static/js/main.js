/**
 * Main JavaScript for Cybersecurity Platform
 */

// Notification system
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease-out reverse';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// CSRF Token handling for Django
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const csrftoken = getCookie('csrftoken');

// Set CSRF token for all AJAX requests
if (csrftoken) {
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        if (options.method && options.method.toUpperCase() !== 'GET') {
            options.headers = options.headers || {};
            options.headers['X-CSRFToken'] = csrftoken;
        }
        return originalFetch(url, options);
    };
}

// Utility functions
function formatTimestamp(date) {
    return new Date(date).toLocaleString();
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function validateIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part);
        return num >= 0 && num <= 255;
    });
}

// Network utilities
async function testConnection(ip) {
    try {
        const response = await fetch(`/api/network/ping/${ip}/`);
        const data = await response.json();
        return data.reachable;
    } catch (error) {
        console.error('Connection test failed:', error);
        return false;
    }
}

// Auto-refresh handler
class AutoRefresh {
    constructor(callback, interval = 3000) {
        this.callback = callback;
        this.interval = interval;
        this.timerId = null;
    }
    
    start() {
        if (!this.timerId) {
            this.callback();
            this.timerId = setInterval(this.callback, this.interval);
        }
    }
    
    stop() {
        if (this.timerId) {
            clearInterval(this.timerId);
            this.timerId = null;
        }
    }
    
    setInterval(newInterval) {
        this.interval = newInterval;
        if (this.timerId) {
            this.stop();
            this.start();
        }
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Cybersecurity Platform initialized');
    
    // Highlight active nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.style.color = 'var(--secondary-color)';
        }
    });
});

// Export utilities for use in other scripts
window.CyberSecUtils = {
    showNotification,
    validateIP,
    formatTimestamp,
    formatBytes,
    testConnection,
    AutoRefresh
};
