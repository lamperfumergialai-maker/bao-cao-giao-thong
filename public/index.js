document.getElementById('gpsBtn').addEventListener('click', getLocation);
document.getElementById('reportForm').addEventListener('submit', submitReport);

let currentLat = '';
let currentLng = '';

function getLocation() {
    const gpsBtn = document.getElementById('gpsBtn');
    if (!navigator.geolocation) {
        alert("Trình duyệt của bạn không hỗ trợ định vị GPS.");
        return;
    }

    gpsBtn.innerText = "⏳ Đang dò vị trí...";
    gpsBtn.disabled = true;

    navigator.geolocation.getCurrentPosition(position => {
        currentLat = position.coords.latitude.toFixed(6);
        currentLng = position.coords.longitude.toFixed(6);
        document.getElementById('location').value = `Tọa độ: ${currentLat}, ${currentLng}`;
        gpsBtn.innerText = "✅ Đã lấy tọa độ thành công";
        gpsBtn.disabled = false;
    }, () => {
        alert("Không thể tự động lấy vị trí. Vui lòng bật GPS trên điện thoại hoặc nhập địa chỉ bằng tay.");
        gpsBtn.innerText = "📍 Lấy tọa độ GPS hiện tại";
        gpsBtn.disabled = false;
    }, { enableHighAccuracy: true, timeout: 10000 });
}

async function submitReport(e) {
    e.preventDefault();
    const submitBtn = document.getElementById('submitBtn');
    const form = document.getElementById('reportForm');
    const formData = new FormData(form);

    // Gửi kèm tọa độ tách rời để khớp với server.js
    formData.append('latitude', currentLat);
    formData.append('longitude', currentLng);

    submitBtn.innerText = "⏳ Đang tải dữ liệu lên...";
    submitBtn.disabled = true;

    try {
        const response = await fetch('/api/report', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(result.message || "Tệp tin quá lớn (vượt quá 20MB) hoặc lỗi máy chủ.");
        }

        alert(`${result.message}\nMã phản ánh của bạn: ${result.reportId || ''}`);
        form.reset();
        currentLat = '';
        currentLng = '';
        document.getElementById('gpsBtn').innerText = "📍 Lấy tọa độ GPS hiện tại";
    } catch (error) {
        alert("Gửi thất bại: " + error.message);
    } finally {
        submitBtn.innerText = "Gửi phản ánh";
        submitBtn.disabled = false;
    }
}
