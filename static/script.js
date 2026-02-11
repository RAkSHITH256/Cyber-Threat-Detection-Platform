document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form");
  const resultContainer = document.querySelector(".container"); // We'll append result here or replace an existing one.
  // Actually, based on index.html, the result is outside the form but inside .container.
  // Let's create a dedicated container for results in index.html later.
  // For now, let's find where to put it. The current template puts it after the form.

  // Handle Dynamic Backgrounds
  const inputTypeSelect = document.querySelector('select[name="input_type"]');
  
  function updateBackground() {
      const type = inputTypeSelect.value;
      document.body.className = `bg-${type}`;
  }

  if (inputTypeSelect) {
      inputTypeSelect.addEventListener("change", updateBackground);
      updateBackground(); // Set initial background
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    // user input
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    // Select or create result display area
    const results = document.querySelectorAll('.result');
    results.forEach(el => el.remove());

    // Show loading state
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loading';
    loadingDiv.className = 'result fade-in';
    loadingDiv.innerHTML = `
            <h3>🔍 Scanning...</h3>
            <div class="loader"></div>
            <p>Analyzing threat vectors...</p>
        `;
    form.after(loadingDiv); // Insert after form

    try {
      const response = await fetch("/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest",
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) throw new Error("Network response was not ok");

      const result = await response.json();

      // Remove loader
      loadingDiv.remove();

      // Render Result
      if (result) {
        renderResult(result, form);
      } else {
        loadingDiv.innerHTML = `<h3 style="color: #f59e0b;">No Result</h3><p>The server returned no data.</p>`;
        form.after(loadingDiv); // Re-add loadingDiv as error message container since we removed it
      }
    } catch (error) {
      console.error("Error:", error);
      loadingDiv.innerHTML = `<h3 style="color: #ef4444;">Error</h3><p>Something went wrong. Please try again.</p>`;
    }
  });
});

function renderResult(result, form) {
  const riskScore = result.risk_score;
  const riskClass = riskScore < 25 ? "low" : riskScore < 50 ? "medium" : "high";

  const resultHtml = `
    <div class="result fade-in">
        <h3>Threat Analysis Result</h3>

        <p><strong>Input Type:</strong> ${result.input_type}</p>
        <p><strong>Input:</strong> ${result.input}</p>

        <p><strong>Risk Score:</strong> ${riskScore}%</p>
        <p><strong>Verdict:</strong> ${result.verdict}</p>

        <div class="meter-container">
            <div class="meter-label">Threat Level</div>
            <div class="meter">
                <div class="meter-fill ${riskClass}" style="width: ${riskScore}%;"></div>
            </div>
        </div>

        <details>
            <summary>Why was this flagged?</summary>
            <ul>
                ${Object.entries(result.features)
                  .map(
                    ([key, value]) =>
                      `<li><strong>${key}:</strong> ${value}</li>`
                  )
                  .join("")}
            </ul>
        </details>

        ${
          riskScore >= 25
            ? `
        <div style="margin-top: 20px; border-top: 1px solid rgba(148, 163, 184, 0.1); padding-top: 15px;">
            <h3>🚨 What should you do?</h3>
            <ul>
                <li>❌ Do NOT click links or share OTPs</li>
                <li>📞 Do NOT return suspicious calls</li>
                <li>📸 Take screenshots as evidence</li>
            </ul>

            <h4>📢 Report Cyber Crime (India)</h4>
            <ul>
                <li><strong>Cyber Crime Helpline:</strong> 1930</li>
                <li><strong>Cyber Crime Portal:</strong> <a href="https://cybercrime.gov.in" target="_blank" style="color: #38bdf8;">cybercrime.gov.in</a></li>
                <li><strong>Local Police:</strong> Nearest Police Station</li>
            </ul>
        </div>
        `
            : ""
        }
    </div>
    `;

  form.insertAdjacentHTML("afterend", resultHtml);
}
