const depoimentos = document.querySelectorAll('.depoimento');
let depoimentoIndex = 0;

function rotateDepoimentos() {
  if (!depoimentos.length) return;
  depoimentos.forEach((item, index) => item.classList.toggle('ativo', index === depoimentoIndex));
  depoimentoIndex = (depoimentoIndex + 1) % depoimentos.length;
}

setInterval(rotateDepoimentos, 5000);

const steps = document.querySelectorAll('.how-steps .step');
const previews = document.querySelectorAll('.preview-slide');
let activeStep = 0;
let stepInterval;

function setActiveStep(index) {
  steps.forEach((step, stepIndex) => step.classList.toggle('active', stepIndex === index));
  previews.forEach((preview, previewIndex) => preview.classList.toggle('active', previewIndex === index));
  activeStep = index;
}

function startStepRotation() {
  stepInterval = setInterval(() => {
    const next = (activeStep + 1) % steps.length;
    setActiveStep(next);
  }, 4500);
}

function stopStepRotation() {
  clearInterval(stepInterval);
}

steps.forEach((step, index) => {
  step.addEventListener('click', () => {
    setActiveStep(index);
    stopStepRotation();
    startStepRotation();
  });
});

if (steps.length) {
  setActiveStep(0);
  startStepRotation();
}

const hamb = document.querySelector('.hamb');
const navLinks = document.querySelector('.nav-links');

if (hamb && navLinks) {
  hamb.addEventListener('click', () => {
    navLinks.classList.toggle('active');
  });
}

