const form = document.getElementById('risk-form');
const resultCard = document.getElementById('result-card');
const scoreValue = document.getElementById('score-value');
const riskLevel = document.getElementById('risk-level');
const exposureList = document.getElementById('exposure-list');
const tipsList = document.getElementById('tips-list');

form.addEventListener('submit', (event) => {
  event.preventDefault();

  const name = document.getElementById('name').value.trim();
  const email = document.getElementById('email').value.trim();
  const phone = document.getElementById('phone').value.trim();

  const analysis = analyzeExposure(name, email, phone);

  scoreValue.textContent = `${analysis.score}/100`;
  riskLevel.textContent = analysis.riskLabel;
  riskLevel.style.background = analysis.riskStyle;
  exposureList.innerHTML = analysis.exposures
    .map((item) => `<li>${item}</li>`)
    .join('');
  tipsList.innerHTML = analysis.tips
    .map((item) => `<li>${item}</li>`)
    .join('');

  resultCard.classList.remove('hidden');
});

function analyzeExposure(name, email, phone) {
  let score = 100;
  const exposures = [];
  const tips = [];

  if (name) {
    score -= 12;
    exposures.push('Providing your full name can make it easier for others to connect your identity to online records.');
  } else {
    exposures.push('No name was provided, so the analysis is based only on the information available.');
  }

  if (email) {
    score -= 18;
    exposures.push('Email addresses are often targeted in data breaches and phishing attempts.');
  }

  if (phone) {
    score -= 15;
    exposures.push('Phone numbers can appear in contact lists, leaked databases, or scam campaigns.');
  }

  if (email.includes('@')) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (domain && ['gmail.com', 'yahoo.com', 'outlook.com'].includes(domain)) {
      score -= 7;
      exposures.push('Widely used public services increase the chance that your information appears in public records or search results.');
    }
  }

  if (name && email && phone) {
    score -= 10;
    exposures.push('Combining all of these details increases the chance of linking your identity to your digital footprint.');
  }

  score = Math.max(0, Math.min(100, score));

  let riskLabel = 'Low';
  let riskStyle = 'rgba(74, 222, 128, 0.18)';
  if (score < 50) {
    riskLabel = 'High';
    riskStyle = 'rgba(255, 107, 107, 0.2)';
  } else if (score < 75) {
    riskLabel = 'Medium';
    riskStyle = 'rgba(255, 205, 75, 0.2)';
  }

  tips.push('Use a strong password manager and a unique password for each service.');
  tips.push('Enable two-factor authentication on your email and important accounts.');
  tips.push('Review your privacy settings on social media and check what information is visible.');

  if (score < 70) {
    tips.push('Use a separate email address for less important sign-ups.');
  }

  if (exposures.length === 0) {
    exposures.push('Not enough information was provided for further analysis in this demo version.');
  }

  return { score, riskLabel, riskStyle, exposures, tips };
}
