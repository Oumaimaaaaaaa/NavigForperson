const form = document.getElementById('risk-form');
const resultCard = document.getElementById('result-card');
const scoreValue = document.getElementById('score-value');
const riskLevel = document.getElementById('risk-level');
const summaryText = document.getElementById('summary-text');
const exposureList = document.getElementById('exposure-list');
const toolsList = document.getElementById('tools-list');
const tipsList = document.getElementById('tips-list');
const identityScore = document.getElementById('identity-score');
const infraScore = document.getElementById('infra-score');
const socialScore = document.getElementById('social-score');
const postureScore = document.getElementById('posture-score');
const residualRisk = document.getElementById('residual-risk');
const confidenceLevel = document.getElementById('confidence-level');
const controlsList = document.getElementById('controls-list');

form.addEventListener('submit', (event) => {
  event.preventDefault();

  const target = document.getElementById('target').value.trim();
  const assetType = document.getElementById('asset-type').value;
  const posture = document.getElementById('posture').value;
  const context = document.getElementById('context').value;
  const indicators = {
    publicSocial: document.getElementById('public-social').checked,
    publicRepo: document.getElementById('public-repo').checked,
    openPorts: document.getElementById('open-ports').checked,
    breachData: document.getElementById('breach-data').checked,
    misconfig: document.getElementById('misconfig').checked,
  };

  const analysis = analyzeExposure(target, assetType, posture, context, indicators);

  scoreValue.textContent = `${analysis.score}/100`;
  riskLevel.textContent = analysis.riskLabel;
  riskLevel.style.background = analysis.riskStyle;
  summaryText.textContent = analysis.summary;
  identityScore.textContent = `${analysis.identityScore}/10`;
  infraScore.textContent = `${analysis.infraScore}/10`;
  socialScore.textContent = `${analysis.socialScore}/10`;
  postureScore.textContent = `${analysis.postureScore}/10`;
  residualRisk.textContent = `${analysis.residualRisk}`;
  confidenceLevel.textContent = analysis.confidence;
  exposureList.innerHTML = analysis.exposures.map((item) => `<li>${item}</li>`).join('');
  controlsList.innerHTML = analysis.controls.map((item) => `<li>${item}</li>`).join('');
  toolsList.innerHTML = analysis.tools.map((item) => `<li>${item}</li>`).join('');
  tipsList.innerHTML = analysis.tips.map((item) => `<li>${item}</li>`).join('');

  resultCard.classList.remove('hidden');
});

function analyzeExposure(target, assetType, posture, context, indicators) {
  let identityScore = 4;
  let infraScore = 4;
  let socialScore = 4;
  let postureScore = 4;
  const exposures = [];
  const tools = [];
  const tips = [];
  const controls = [];

  if (!target) {
    exposures.push('No target value was provided, so the scan used a baseline profile.');
  } else {
    exposures.push(`The target "${target}" appears to be a ${assetType} asset that may be visible in online recon workflows.`);
  }

  if (assetType === 'email' || assetType === 'phone' || assetType === 'username') {
    identityScore += 2;
    exposures.push('Identity-based signals are strong; email, phone, and username data can be abused in phishing or impersonation attacks.');
  }

  if (assetType === 'domain' || assetType === 'company' || assetType === 'ip') {
    infraScore += 2;
    exposures.push('Infrastructure-facing assets can reveal exposed services, weak DNS posture, or misused cloud exposure.');
  }

  if (context === 'credential') {
    identityScore += 2;
    exposures.push('Credential-focused review increases the likelihood of account takeover or password reuse exposure.');
  } else if (context === 'cloud') {
    infraScore += 2;
    exposures.push('Cloud-focused assessment highlights misconfigured storage, public interfaces, and weak identity controls.');
  } else if (context === 'supply') {
    socialScore += 1;
    postureScore += 1;
    exposures.push('Third-party and supply-chain exposure can propagate risk through vendors, dependencies, and shared services.');
  }

  if (indicators.publicSocial) {
    socialScore += 2;
    exposures.push('Public social presence increases the chance of OSINT enrichment and targeted attacks.');
  }

  if (indicators.publicRepo) {
    socialScore += 1;
    exposures.push('A public repository can expose source code, secrets, commit history, and developer patterns.');
  }

  if (indicators.openPorts) {
    infraScore += 2;
    exposures.push('Visible services or open ports suggest service enumeration is possible and may indicate attack surface exposure.');
  }

  if (indicators.breachData) {
    identityScore += 2;
    infraScore += 1;
    exposures.push('Breach or leaked data exposure is a serious signal of credential or identity compromise risk.');
  }

  if (indicators.misconfig) {
    infraScore += 2;
    exposures.push('Misconfiguration can expose DNS records, security headers, or admin endpoints to discovery.');
  }

  if (posture === 'basic') {
    postureScore += 1;
  } else if (posture === 'moderate') {
    postureScore += 2;
  } else {
    postureScore += 3;
  }

  identityScore = Math.min(10, identityScore);
  infraScore = Math.min(10, infraScore);
  socialScore = Math.min(10, socialScore);
  postureScore = Math.min(10, postureScore);

  const signalCount = [target, indicators.publicSocial, indicators.publicRepo, indicators.openPorts, indicators.breachData, indicators.misconfig].filter(Boolean).length;
  const confidence = signalCount >= 5 ? 'High' : signalCount >= 3 ? 'Medium' : 'Low';
  const riskScore = Math.min(100, Math.round((identityScore * 2.5) + (infraScore * 2.2) + (socialScore * 1.8) + (postureScore * 1.5)));
  const score = Math.max(0, 100 - riskScore);

  let riskLabel = 'Low';
  let riskStyle = 'rgba(74, 222, 128, 0.18)';
  let summary = 'The target appears relatively hardened and not obviously overexposed.';

  if (score < 50) {
    riskLabel = 'High';
    riskStyle = 'rgba(255, 107, 107, 0.2)';
    summary = 'This target shows multiple high-signal exposure indicators and should be reviewed immediately.';
  } else if (score < 75) {
    riskLabel = 'Medium';
    riskStyle = 'rgba(255, 205, 75, 0.2)';
    summary = 'The target has mixed signals and would benefit from stronger defensive controls.';
  }

  controls.push('Enforce MFA and password rotation for privileged and exposed identities.');
  controls.push('Review DNS, TLS, email security, and cloud IAM posture for misconfiguration drift.');
  controls.push('Reduce public exposure of repositories, documentation, and developer metadata.');
  controls.push('Create continuous monitoring and alerting for new services, exposed ports, and leaked credentials.');

  tools.push('Shodan or Censys for infrastructure discovery');
  tools.push('VirusTotal for file and domain reputation analysis');
  tools.push('HaveIBeenPwned or breach intel for credential exposure checks');
  tools.push('Amass or theHarvester for open-source reconnaissance');
  tools.push('MISP or threat intel feeds for enrichment and context');

  tips.push('Rotate credentials and review exposed secrets in public repositories.');
  tips.push('Lock down DNS records, SPF, DKIM, DMARC, and security headers.');
  tips.push('Reduce public exposure of social and developer activity where possible.');
  tips.push('Use monitoring tools and alerts for new exposed services or suspicious changes.');

  return {
    score,
    riskLabel,
    riskStyle,
    summary,
    identityScore,
    infraScore,
    socialScore,
    postureScore,
    residualRisk: riskScore,
    confidence,
    exposures,
    controls,
    tools,
    tips,
  };
}
