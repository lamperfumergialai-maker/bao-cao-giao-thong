document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('adminPass').addEventListener('keypress', e => {
    if (e.key === 'Enter') login();
});
document.getElementById('refreshBtn').addEventListener('click', () => loadReports(false));
document.getElementById('logoutBtn').addEventListener('click', logout);

loadReports(true);

async function login() {
    const password = document.getElementById('adminPass').value;
    if (!password) return alert('Vui lòng nhập mật khẩu!');
    try {
        const res = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
            alert(data.message || 'Sai mật khẩu quản trị!');
            return;
        }
        loadReports(false);
    } catch (err) {
        alert('Lỗi kết nối máy chủ.');
    }
}

async function logout() {
    await fetch('/api/admin/logout', { method: 'POST' }).catch(() => {});
    location.reload();
}

function formatLocation(item) {
    const locText = String(item.location || '').replace(/</g, "&lt;").replace(/>/g, "&gt;");
    let lat = item.latitude;
    let lng = item.longitude;

    if (lat == null || lng == null) {
        const numbers = locText.match(/-?\d+\.\d+/g);
        if (numbers && numbers.length >= 2) {
            lat = numbers.shift();
            lng = numbers.shift();
        }
    }

    if (lat != null && lng != null) {
        const mapUrl = 'https://google.com' + lat + ',' + lng;
        return locText + '<br><a href="' + mapUrl + '" target="_blank" rel="noopener noreferrer" class="btn-map">📍 Mở trên Google Maps</a>';
    }
    return locText;
}


function formatMedia(item) {
    const fileUrl = item.filePath || (item.fileName ? `/api/admin/uploads/${item.fileName}` : null);
    if (!fileUrl) return 'Không có';
    const isVideo = (item.mimeType && item.mimeType.startsWith('video/')) || fileUrl.match(/\.(mp4|mov|avi|webm)$/i);
    if (isVideo) {
        return `<video src="${fileUrl}" controls class="media-preview"></video>
                <a href="${fileUrl}" target="_blank" style="font-size:12px;">Mở video</a>`;
    }
    return `<a href="${fileUrl}" target="_blank"><img src="${fileUrl}" class="media-preview" alt="Ảnh minh chứng"></a>`;
}

async function loadReports(isInitialCheck = false) {
    try {
        let response = await fetch('/api/admin/reports');
        if (response.status === 404) {
            response = await fetch('/api/reports');
        }

        if (response.status === 401) {
            if (!isInitialCheck) alert('Phiên đăng nhập hết hạn, vui lòng đăng nhập lại.');
            return;
        }

        const result = await response.json();
        const reports = Array.isArray(result) ? result : (result.reports || []);

        document.getElementById('loginBox').style.display = 'none';
        document.getElementById('adminPanel').style.display = 'block';
        document.getElementById('totalCount').innerText = reports.length;

        const tbody = document.getElementById('reportTableBody');
        tbody.innerHTML = reports.map(item => `
            <tr>
                <td>${new Date(item.createdAt).toLocaleString('vi-VN')}</td>
                <td><strong>${item.fullName}</strong><br>SĐT: ${item.phone}</td>
                <td>${formatLocation(item)}</td>
                <td>${item.description}</td>
                <td>${formatMedia(item)}</td>
            </tr>
        `).join('');
    } catch (error) {
        if (!isInitialCheck) alert('Không thể tải dữ liệu từ máy chủ.');
    }
}
