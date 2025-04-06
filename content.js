// content.js
async function checkWebsite() {
  const url = window.location.href;
  const html = document.documentElement.outerHTML;

  try {
    const response = await fetch("http://localhost:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        html: html,
      }),
    });

    const result = await response.json();

    if (result.is_phishing && result.confidence > 0.7) {
      // Create warning overlay
      const warning = document.createElement("div");
      warning.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                background: rgba(255, 0, 0, 0.9);
                color: white;
                text-align: center;
                padding: 20px;
                z-index: 9999;
            `;
      warning.innerHTML = `
                <h2>WARNING: Potential Phishing Site Detected!</h2>
                <p>Confidence: ${(result.confidence * 100).toFixed(2)}%</p>
                <button class="close-btn">Close</button>
            `;
      document.body.appendChild(warning);

      document.addEventListener("click", function (event) {
        if (event.target.matches(".close-btn")) {
          event.target.parentElement.remove();
        }
      });
    }
  } catch (error) {
    console.error("Error checking website:", error);
  }
}

// Run check when page loads
window.addEventListener("load", checkWebsite);
