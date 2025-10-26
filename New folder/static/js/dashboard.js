// Dashboard JavaScript - dashboard.js
function detectPhishing() {
    const urlInput = document.getElementById('urlInput');
    const resultDiv = document.getElementById('result');
    const resultContent = document.getElementById('resultContent');

    const url = urlInput.value.trim();

    if (!url) {
        alert('Please enter a URL to check');
        return;
    }

    // Show loading state
    resultDiv.style.display = 'block';
    resultContent.innerHTML = '<div style="text-align: center; padding: 20px;"><strong>🔄 Analyzing URL...</strong></div>';

    fetch('/detect_phishing', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            resultContent.innerHTML = `
                <div style="color: #721c24; text-align: center;">
                    <strong>❌ Error:</strong> ${data.error}
                </div>
            `;
            resultDiv.className = 'result-box result-danger';
            return;
        }

        const isPhishing = data.is_phishing;
        const confidence = data.confidence.toFixed(2);

        if (isPhishing) {
            resultDiv.className = 'result-box result-danger';
            resultContent.innerHTML = `
                <div style="text-align: center; margin-bottom: 20px;">
                    <h3 style="color: #721c24; margin-bottom: 10px;">🚨 WARNING: Potential Phishing Website!</h3>
                    <p style="font-size: 16px;"><strong>Confidence Level:</strong> ${confidence}%</p>
                </div>
                <div style="background: rgba(114, 28, 36, 0.1); padding: 15px; border-radius: 8px;">
                    <p><strong>⚠️ Security Alert:</strong> This URL shows characteristics commonly found in phishing websites.</p>
                    <p style="margin-top: 10px;"><strong>Recommendation:</strong> Do not enter personal information or credentials on this website.</p>
                </div>
                ${generateFeatureAnalysis(data.features, true)}
            `;
        } else {
            resultDiv.className = 'result-box result-safe';
            resultContent.innerHTML = `
                <div style="text-align: center; margin-bottom: 20px;">
                    <h3 style="color: #155724; margin-bottom: 10px;">✅ Website appears to be safe</h3>
                    <p style="font-size: 16px;"><strong>Confidence Level:</strong> ${confidence}%</p>
                </div>
                <div style="background: rgba(21, 87, 36, 0.1); padding: 15px; border-radius: 8px;">
                    <p><strong>🛡️ Security Status:</strong> This URL does not show obvious phishing characteristics.</p>
                    <p style="margin-top: 10px;"><strong>Note:</strong> While this analysis suggests the URL is safe, always exercise caution when entering sensitive information online.</p>
                </div>
                ${generateFeatureAnalysis(data.features, false)}
            `;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        resultDiv.style.display = 'block';
        resultDiv.className = 'result-box result-danger';
        resultContent.innerHTML = `
            <div style="color: #721c24; text-align: center;">
                <strong>❌ Error:</strong> Failed to analyze URL. Please try again.
            </div>
        `;
    });
}

function generateFeatureAnalysis(features, isPhishing) {
    const suspiciousFeatures = [];
    const normalFeatures = [];

    // Analyze features
    if (features.url_length > 100) suspiciousFeatures.push(`Long URL (${features.url_length} characters)`);
    if (features.dots_count > 3) suspiciousFeatures.push(`Many dots (${features.dots_count})`);
    if (features.hyphens_count > 2) suspiciousFeatures.push(`Multiple hyphens (${features.hyphens_count})`);
    if (features.has_ip === 1) suspiciousFeatures.push('Contains IP address');
    if (features.has_https === 0) suspiciousFeatures.push('No HTTPS encryption');
    if (features.suspicious_keywords > 0) suspiciousFeatures.push(`Suspicious keywords found (${features.suspicious_keywords})`);

    // Normal features
    if (features.url_length <= 100) normalFeatures.push(`Normal URL length (${features.url_length} characters)`);
    if (features.has_https === 1) normalFeatures.push('Uses HTTPS encryption');
    if (features.has_ip === 0) normalFeatures.push('Uses domain name (no IP)');
    if (features.suspicious_keywords === 0) normalFeatures.push('No suspicious keywords detected');

    let analysisHtml = `
        <div style="margin-top: 20px; padding: 15px; background: rgba(255, 255, 255, 0.5); border-radius: 8px;">
            <h4 style="margin-bottom: 15px; color: #333;">🔍 Detailed Analysis:</h4>
    `;

    if (suspiciousFeatures.length > 0) {
        analysisHtml += `
            <div style="margin-bottom: 15px;">
                <strong style="color: #721c24;">⚠️ Warning Signs:</strong>
                <ul style="margin: 5px 0 0 20px; color: #721c24;">
                    ${suspiciousFeatures.map(feature => `<li>${feature}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (normalFeatures.length > 0) {
        analysisHtml += `
            <div>
                <strong style="color: #155724;">✅ Positive Signs:</strong>
                <ul style="margin: 5px 0 0 20px; color: #155724;">
                    ${normalFeatures.map(feature => `<li>${feature}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    analysisHtml += '</div>';

    return analysisHtml;
}

// Handle Enter key press
document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                detectPhishing();
            }
        });
    }
});
